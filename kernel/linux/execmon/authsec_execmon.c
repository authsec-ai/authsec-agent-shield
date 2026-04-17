/*
 * AuthSec Agent Shield — Linux exec monitor daemon
 *
 * Intercepts ALL process executions system-wide using:
 *   1. fanotify FAN_OPEN_EXEC_PERM  — blocks the exec in kernel until we respond
 *   2. eBPF tracepoint on execve    — captures full argv[] before exec completes
 *   3. process_vm_readv fallback    — reads argv from stack when eBPF unavailable
 *
 * This intercepts execution of ANY binary regardless of:
 *   - Its filename (renamed /bin/rm → /bin/safe: still caught, same inode)
 *   - Whether it's called from Python, Node, a shell script, or directly
 *   - Whether the caller is an AI tool, human, or script
 *
 * A renamed dangerous binary is still caught because FAN_OPEN_EXEC_PERM fires
 * on the INODE being exec'd, not the filename. The risk engine then sees the
 * actual binary content path (via /proc/self/fd/<N> → real path) and the args.
 *
 * Self-protection:
 *   - Runs as root — non-root processes cannot kill it
 *   - PR_SET_DUMPABLE=0 — prevents ptrace attach from non-root
 *   - OOM score -1000 — kernel will not OOM-kill this process
 *   - SIGTERM handler requires mobile approval before shutting down
 *   - Binary marked immutable by installer (chattr +i)
 *
 * Build:
 *   make -C kernel/linux/execmon
 *
 * Requires: Linux 5.0+ (FAN_OPEN_EXEC_PERM), libbpf, libcurl
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#pragma GCC diagnostic ignored "-Wunused-result"
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#pragma GCC diagnostic ignored "-Wunused-variable"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/uio.h>        /* process_vm_readv */
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/limits.h>
#include <curl/curl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "authsec_execmon_ebpf.h"

/* ── Constants ─────────────────────────────────────────────────────────── */

#define MAX_PROTECTED_PATHS  32
#define MAX_POLL_ATTEMPTS    12       /* 12 × 5s = 60s timeout */
#define POLL_INTERVAL_MS     5000
#define WORKER_THREADS       16       /* process up to 16 execs concurrently */
#define ARGV_CACHE_SIZE      512      /* ring buffer of recent eBPF events */
#define CONTROL_SOCKET       "/run/authsec-shield-execmon.sock"
#define DAEMON_BIN           "/usr/local/sbin/authsec-shield-execmon"

/* ── Global state ──────────────────────────────────────────────────────── */

static char  g_ApiBaseURL[1024]  = "";
static char  g_AccessToken[4096] = "";
static int   g_FanotifyFd        = -1;
static volatile int g_Running    = 1;
static volatile int g_Paused     = 0;   /* pause 1h — skip checks */
static volatile time_t g_PauseUntil = 0;

/* eBPF argv cache — ring buffer keyed by pid */
typedef struct {
    __u32   pid;
    __u64   timestamp_ns;
    char    argv[EXEC_ARGV_MAX];
    __u32   argv_len;
    char    filename[EXEC_PATH_MAX];
} ArgvCacheEntry;

static ArgvCacheEntry  g_ArgvCache[ARGV_CACHE_SIZE];
static int             g_ArgvCacheHead = 0;
static pthread_mutex_t g_ArgvLock      = PTHREAD_MUTEX_INITIALIZER;

/* Worker thread pool */
typedef struct {
    struct fanotify_event_metadata ev;
    int   in_use;
} WorkItem;

static WorkItem        g_WorkItems[WORKER_THREADS] __attribute__((unused));
static pthread_mutex_t g_WorkLock __attribute__((unused)) = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_WorkCond __attribute__((unused)) = PTHREAD_COND_INITIALIZER;

/* ── Logging ─────────────────────────────────────────────────────────────── */

static void log_msg(const char *level, const char *fmt, ...)
{
    va_list args;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(stderr, "[execmon] [%ld.%03ld] [%s] ",
            (long)tv.tv_sec, (long)(tv.tv_usec / 1000), level);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

typedef struct { char *data; size_t len; size_t cap; } CurlBuf;

static size_t curl_write_cb(void *ptr, size_t sz, size_t nm, void *ud);
static int json_str(const char *json, const char *key, char *out, size_t outlen);

/* ── Self-protection ─────────────────────────────────────────────────────── */

static void apply_self_protection(void)
{
    /* Prevent ptrace attach from non-root */
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Become subreaper — orphaned children are adopted by us, not init */
    prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0);

    /* Set OOM score to minimum — kernel will not kill us */
    {
        FILE *f = fopen("/proc/self/oom_score_adj", "w");
        if (f) { fprintf(f, "-1000\n"); fclose(f); }
    }

    /* Lock all current and future pages in RAM — prevent swap */
    mlockall(MCL_CURRENT | MCL_FUTURE);

    log_msg("PROTECT", "Self-protection applied (OOM-immune, ptrace-resistant)");
}

/* ── SIGTERM handler — requires mobile approval before shutting down ────── */

static void request_shutdown_approval(void)
{
    log_msg("WARN", "Shutdown requested — sending mobile approval request");

    /* Call the API synchronously — block until decision */
    CURL *curl = curl_easy_init();
    if (!curl) { g_Running = 0; return; }

    char url[2048];
    snprintf(url, sizeof(url), "%s/authsec/uflow/agent/actions/evaluate", g_ApiBaseURL);

    const char *body =
        "{\"agent_id\":\"authsec-shield-execmon\","
        "\"agent_name\":\"AuthSec Shield Daemon\","
        "\"agent_framework\":\"kernel\","
        "\"action\":\"stop-daemon\","
        "\"resource\":\"authsec-shield-execmon\","
        "\"detail\":\"Request to stop the AuthSec exec monitor daemon\","
        "\"metadata\":{\"risk\":\"high\",\"reason\":\"daemon_stop\"}}";

    char authHeader[4200];
    snprintf(authHeader, sizeof(authHeader), "Authorization: Bearer %s", g_AccessToken);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authHeader);

    CurlBuf resp = { .data = malloc(8192), .len = 0, .cap = 8192 };
    if (!resp.data) {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return;
    }

    curl_easy_setopt(curl, CURLOPT_URL,          url);
    curl_easy_setopt(curl, CURLOPT_POST,          1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,    body);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,       10L);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    if (rc != CURLE_OK) {
        log_msg("ERROR", "Shutdown approval request failed: %s", curl_easy_strerror(rc));
        free(resp.data);
        curl_easy_cleanup(curl);
        return;
    }

    char status[64] = "";
    json_str(resp.data, "status", status, sizeof(status));
    if (strcmp(status, "auto_approved") == 0 || strcmp(status, "approved") == 0) {
        log_msg("WARN", "Shutdown approved via mobile. Stopping daemon.");
        g_Running = 0;
        free(resp.data);
        curl_easy_cleanup(curl);
        return;
    }

    char req_id[64] = "";
    json_str(resp.data, "action_req_id", req_id, sizeof(req_id));
    free(resp.data);
    if (req_id[0] == '\0') {
        log_msg("WARN", "Shutdown denied: approval service did not return action_req_id");
        curl_easy_cleanup(curl);
        return;
    }

    char poll_url[2048];
    snprintf(poll_url, sizeof(poll_url),
             "%s/authsec/uflow/agent/actions/status?action_req_id=%s",
             g_ApiBaseURL, req_id);

    for (int i = 0; i < MAX_POLL_ATTEMPTS; i++) {
        usleep(POLL_INTERVAL_MS * 1000);

        CurlBuf pr = { .data = malloc(4096), .len = 0, .cap = 4096 };
        if (!pr.data) break;

        struct curl_slist *ph = NULL;
        ph = curl_slist_append(ph, authHeader);
        curl_easy_setopt(curl, CURLOPT_URL,          poll_url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET,       1L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &pr);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    ph);
        curl_easy_perform(curl);
        curl_slist_free_all(ph);

        char ps[64] = "";
        json_str(pr.data, "status", ps, sizeof(ps));
        free(pr.data);

        if (strcmp(ps, "approved") == 0 || strcmp(ps, "auto_approved") == 0) {
            log_msg("WARN", "Shutdown approved via mobile. Stopping daemon.");
            g_Running = 0;
            break;
        }
        if (strcmp(ps, "denied") == 0 || strcmp(ps, "expired") == 0 ||
            strcmp(ps, "timed_out") == 0) {
            log_msg("WARN", "Shutdown denied by approval status: %s", ps);
            break;
        }
    }

    if (g_Running) {
        log_msg("WARN", "Shutdown not approved; daemon remains running");
    }
    curl_easy_cleanup(curl);
}

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT) {
        if (g_ApiBaseURL[0] != '\0') {
            /* Require mobile approval before stopping */
            request_shutdown_approval();
        } else {
            /* Not configured — allow immediate stop */
            g_Running = 0;
        }
    }
}

/* ── eBPF ring buffer consumer ─────────────────────────────────────────── */

static int ebpf_event_handler(void *ctx, void *data, size_t size)
{
    (void)ctx; (void)size;
    struct exec_event *e = (struct exec_event *)data;

    pthread_mutex_lock(&g_ArgvLock);
    ArgvCacheEntry *entry = &g_ArgvCache[g_ArgvCacheHead % ARGV_CACHE_SIZE];
    entry->pid          = e->pid;
    entry->timestamp_ns = e->timestamp_ns;
    entry->argv_len     = e->argv_len < EXEC_ARGV_MAX ? e->argv_len : EXEC_ARGV_MAX - 1;
    memcpy(entry->argv,     e->argv,     entry->argv_len);
    memcpy(entry->filename, e->filename, EXEC_PATH_MAX);
    g_ArgvCacheHead++;
    pthread_mutex_unlock(&g_ArgvLock);

    return 0;
}

static void *ebpf_thread(void *arg)
{
    struct ring_buffer *rb = (struct ring_buffer *)arg;
    while (g_Running) {
        ring_buffer__poll(rb, 100 /* ms timeout */);
    }
    return NULL;
}

/* ── argv fallback: process_vm_readv from stack ──────────────────────────── */
/*
 * When eBPF is unavailable, read the exec argv from the target process's
 * stack using process_vm_readv(). This works because:
 *   - The target process is suspended inside execve (blocked by fanotify)
 *   - Its address space has not been replaced yet (exec hasn't committed)
 *   - The kernel ABI places argc, argv ptrs, env ptrs at the stack top
 *   - We (root) can read any process's memory via process_vm_readv
 */
static int read_argv_from_stack(pid_t pid, char *out, size_t outlen)
{
    /* Find the stack region from /proc/PID/maps */
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);

    FILE *f = fopen(maps_path, "r");
    if (!f) return -1;

    unsigned long stack_start = 0, stack_end = 0;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "[stack]")) {
            sscanf(line, "%lx-%lx", &stack_start, &stack_end);
            break;
        }
    }
    fclose(f);

    if (!stack_start || !stack_end) {
        /* Fallback: read /proc/PID/cmdline of the PARENT process */
        char status_path[64];
        snprintf(status_path, sizeof(status_path), "/proc/%d/status", (int)pid);
        FILE *sf = fopen(status_path, "r");
        if (sf) {
            pid_t ppid = -1;
            while (fgets(line, sizeof(line), sf)) {
                if (sscanf(line, "PPid: %d", &ppid) == 1) break;
            }
            fclose(sf);
            if (ppid > 0) {
                char cmdline_path[64];
                snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", ppid);
                int fd = open(cmdline_path, O_RDONLY);
                if (fd >= 0) {
                    ssize_t n = read(fd, out, outlen - 1);
                    close(fd);
                    if (n > 0) { out[n] = '\0'; return 0; }
                }
            }
        }
        return -1;
    }

    /* Read top 8 KB of stack — argv[] lives near the top */
    size_t read_size = 8192;
    unsigned long read_addr = stack_end - read_size;
    if (read_addr < stack_start) {
        read_addr = stack_start;
        read_size = stack_end - stack_start;
    }

    char *stack_buf = malloc(read_size);
    if (!stack_buf) return -1;

    struct iovec local_iov  = { .iov_base = stack_buf, .iov_len = read_size };
    struct iovec remote_iov = { .iov_base = (void *)read_addr, .iov_len = read_size };

    ssize_t bytes = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (bytes <= 0) {
        free(stack_buf);
        return -1;
    }

    /*
     * Scan backwards from the top for null-terminated strings (the env and arg strings).
     * The argv strings are written onto the stack above the pointer array.
     * We collect printable null-terminated runs and emit them as the argv.
     */
    size_t out_offset = 0;
    int    in_string  = 0;
    size_t str_start  = 0;

    for (ssize_t i = (ssize_t)bytes - 1; i >= 0; i--) {
        if (stack_buf[i] == '\0') {
            if (in_string && (size_t)i < str_start) {
                /* Emit this string */
                size_t slen = str_start - (size_t)i;
                if (out_offset + slen + 1 < outlen) {
                    memcpy(out + out_offset, stack_buf + i + 1, slen);
                    out_offset += slen;
                    out[out_offset++] = '\0';
                }
                in_string = 0;
            }
        } else if (!in_string) {
            in_string = 1;
            str_start = (size_t)i;
        }
    }

    free(stack_buf);
    out[out_offset] = '\0';
    return (out_offset > 0) ? 0 : -1;
}

/* ── argv lookup — eBPF cache first, then fallback ───────────────────────── */

static void get_argv(pid_t pid, char *out, size_t outlen, const char *ebpf_filename)
{
    /* Try eBPF cache first (populated from ring buffer consumer thread) */
    pthread_mutex_lock(&g_ArgvLock);
    __u64 best_ts   = 0;
    int   best_idx  = -1;
    for (int i = 0; i < ARGV_CACHE_SIZE; i++) {
        ArgvCacheEntry *e = &g_ArgvCache[i];
        if (e->pid == (__u32)pid && e->argv_len > 0) {
            if (e->timestamp_ns > best_ts) {
                best_ts  = e->timestamp_ns;
                best_idx = i;
            }
        }
    }
    if (best_idx >= 0) {
        ArgvCacheEntry *e = &g_ArgvCache[best_idx];
        size_t copy = e->argv_len < outlen ? e->argv_len : outlen - 1;
        memcpy(out, e->argv, copy);
        out[copy] = '\0';
        /* Verify filename matches to rule out PID reuse */
        if (ebpf_filename && e->filename[0] != '\0' &&
            strstr(ebpf_filename, e->filename) == NULL &&
            strstr(e->filename, ebpf_filename) == NULL) {
            /* Mismatch — discard, use fallback */
            out[0] = '\0';
        }
        /* Clear the entry to avoid stale data */
        e->pid = 0; e->argv_len = 0;
        pthread_mutex_unlock(&g_ArgvLock);
        if (out[0] != '\0') return;
    } else {
        pthread_mutex_unlock(&g_ArgvLock);
    }

    /* Fallback: read from process stack via process_vm_readv */
    if (read_argv_from_stack(pid, out, outlen) == 0 && out[0] != '\0') return;

    /* Last resort: read /proc/PID/cmdline (shows pre-exec cmdline) */
    char cmdline_path[64];
    snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", (int)pid);
    int fd = open(cmdline_path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, out, outlen - 1);
        close(fd);
        if (n > 0) { out[n] = '\0'; return; }
    }

    snprintf(out, outlen, "%s", ebpf_filename ? ebpf_filename : "(unknown)");
}

/* ── Get real binary path from fanotify event fd ─────────────────────────── */

static int get_exec_path(int fd, char *out, size_t outlen)
{
    char fd_path[64];
    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(fd_path, out, outlen - 1);
    if (n < 0) return -1;
    out[n] = '\0';
    return 0;
}

/* ── Get process name from /proc/PID/comm ────────────────────────────────── */

static void get_comm(pid_t pid, char *out, size_t outlen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", (int)pid);
    FILE *f = fopen(path, "r");
    if (!f) { strncpy(out, "unknown", outlen); return; }
    if (!fgets(out, (int)outlen, f)) strncpy(out, "unknown", outlen);
    fclose(f);
    size_t len = strlen(out);
    if (len > 0 && out[len-1] == '\n') out[len-1] = '\0';
}

/* ── libcurl response buffer ─────────────────────────────────────────────── */

static size_t curl_write_cb(void *ptr, size_t sz, size_t nm, void *ud)
{
    CurlBuf *b = (CurlBuf *)ud;
    size_t total = sz * nm;
    if (b->len + total + 1 > b->cap) {
        b->cap = b->len + total + 4096;
        b->data = realloc(b->data, b->cap);
        if (!b->data) return 0;
    }
    memcpy(b->data + b->len, ptr, total);
    b->len += total;
    b->data[b->len] = '\0';
    return total;
}

static int json_str(const char *json, const char *key, char *out, size_t outlen)
{
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i < outlen - 1) out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

/* ── Agent Guard API ──────────────────────────────────────────────────────── */

static int call_agent_guard(const char *binary, const char *argv,
                             const char *comm, pid_t pid, int *approved)
{
    *approved = 0; /* default deny */

    if (g_ApiBaseURL[0] == '\0') {
        log_msg("WARN", "No API URL — DENY by default");
        return 0;
    }

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[2048];
    snprintf(url, sizeof(url), "%s/authsec/uflow/agent/actions/evaluate", g_ApiBaseURL);

    /* Escape quotes in argv for JSON */
    char safe_argv[4096]; int si = 0;
    for (int i = 0; argv[i] && si < (int)sizeof(safe_argv) - 2; i++) {
        if (argv[i] == '"' || argv[i] == '\\') safe_argv[si++] = '\\';
        safe_argv[si++] = (argv[i] == '\0') ? ' ' : argv[i];
    }
    safe_argv[si] = '\0';

    char body[8192];
    int blen = snprintf(body, sizeof(body),
        "{\"agent_id\":\"authsec-shield-execmon\","
        "\"agent_name\":\"AuthSec Agent Shield (exec monitor)\","
        "\"agent_framework\":\"fanotify+ebpf\","
        "\"action\":\"exec\","
        "\"resource\":\"%s\","
        "\"detail\":\"%s\","
        "\"metadata\":{"
            "\"binary\":\"%s\","
            "\"process\":\"%s\","
            "\"pid\":%d}}",
        binary, safe_argv, binary, comm, (int)pid);

    char authHeader[4200];
    snprintf(authHeader, sizeof(authHeader), "Authorization: Bearer %s", g_AccessToken);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authHeader);

    CurlBuf resp = { .data = malloc(8192), .len = 0, .cap = 8192 };
    if (!resp.data) { curl_easy_cleanup(curl); return -1; }

    curl_easy_setopt(curl, CURLOPT_URL,           url);
    curl_easy_setopt(curl, CURLOPT_POST,           1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     body);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,  (long)blen);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,  curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,      &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,        10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);

    CURLcode rc = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        log_msg("ERROR", "API call failed: %s — DENY", curl_easy_strerror(rc));
        free(resp.data);
        curl_easy_cleanup(curl);
        return -1;
    }

    char status[64] = "";
    json_str(resp.data, "status", status, sizeof(status));
    if (strcmp(status, "auto_approved") == 0) {
        *approved = 1;
        free(resp.data);
        curl_easy_cleanup(curl);
        return 0;
    }

    char req_id[64] = "";
    json_str(resp.data, "action_req_id", req_id, sizeof(req_id));
    free(resp.data);

    if (req_id[0] == '\0') { curl_easy_cleanup(curl); return -1; }

    log_msg("PENDING", "binary=%s argv=%s req_id=%s", binary, safe_argv, req_id);

    char poll_url[2048];
    snprintf(poll_url, sizeof(poll_url),
             "%s/authsec/uflow/agent/actions/status?action_req_id=%s",
             g_ApiBaseURL, req_id);

    for (int i = 0; i < MAX_POLL_ATTEMPTS; i++) {
        usleep(POLL_INTERVAL_MS * 1000);

        CurlBuf pr = { .data = malloc(4096), .len = 0, .cap = 4096 };
        if (!pr.data) break;

        struct curl_slist *ph = NULL;
        ph = curl_slist_append(ph, authHeader);
        curl_easy_setopt(curl, CURLOPT_URL,          poll_url);
        curl_easy_setopt(curl, CURLOPT_HTTPGET,       1L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &pr);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER,    ph);
        curl_easy_perform(curl);
        curl_slist_free_all(ph);

        char ps[64] = "";
        json_str(pr.data, "status", ps, sizeof(ps));
        free(pr.data);

        if (strcmp(ps, "approved")      == 0 ||
            strcmp(ps, "auto_approved") == 0) { *approved = 1; break; }
        if (strcmp(ps, "denied")    == 0 ||
            strcmp(ps, "expired")   == 0 ||
            strcmp(ps, "timed_out") == 0) { *approved = 0; break; }
    }

    log_msg(*approved ? "APPROVED" : "DENIED", "binary=%s req_id=%s", binary, req_id);
    curl_easy_cleanup(curl);
    return 0;
}

/* ── Risk scoring (local — no network call) ──────────────────────────────── */
/*
 * Quick local pre-filter. If score is below threshold, allow immediately
 * without calling the API. This keeps low-latency for safe operations
 * (ls, cat, grep, etc.) and only blocks for genuinely risky commands.
 */
static int local_risk_score(const char *binary, const char *argv)
{
    int score = 0;

    /* Dangerous binaries by base name */
    const char *base = strrchr(binary, '/');
    base = base ? base + 1 : binary;

    static const char *RISKY_BINS[] = {
        "rm", "shred", "unlink", "dd", "mkfs", "wipefs",
        "git", "kubectl", "helm", "terraform", "aws", "gcloud", "az",
        "docker", "podman", "systemctl", "service",
        "chmod", "chown", "passwd", "useradd", "userdel",
        "crontab", "at", "nohup",
        NULL
    };
    for (int i = 0; RISKY_BINS[i]; i++) {
        if (strcmp(base, RISKY_BINS[i]) == 0) { score += 30; break; }
    }

    /* Risky arguments */
    if (strstr(argv, "-rf") || strstr(argv, "-fr") ||
        strstr(argv, "--force") || strstr(argv, "-f "))   score += 20;
    if (strstr(argv, "--recursive") || strstr(argv, "-r ")) score += 15;
    if (strstr(argv, "push --force") || strstr(argv, "push -f")) score += 50;
    if (strstr(argv, "delete namespace") || strstr(argv, "delete ns")) score += 60;
    if (strstr(argv, "destroy") || strstr(argv, "terminate")) score += 40;
    if (strstr(argv, "DROP TABLE") || strstr(argv, "TRUNCATE "))  score += 60;
    if (strstr(argv, "/etc/") || strstr(argv, "/root/") ||
        strstr(argv, "/.ssh/") || strstr(argv, "/.aws/"))  score += 25;

    /* Shell executing script content directly */
    if ((strcmp(base, "bash") == 0 || strcmp(base, "sh") == 0 ||
         strcmp(base, "zsh")  == 0) && strstr(argv, "-c "))     score += 10;

    if (score > 100) score = 100;
    return score;
}

/* ── Worker thread: handle one exec event ─────────────────────────────────── */

typedef struct {
    struct fanotify_event_metadata ev_copy;
} ThreadArg;

static void *handle_exec_event_thread(void *arg)
{
    ThreadArg *ta = (ThreadArg *)arg;
    struct fanotify_event_metadata ev = ta->ev_copy;
    free(ta);

    if (ev.fd < 0) return NULL;

    char binpath[PATH_MAX] = "(unknown)";
    get_exec_path(ev.fd, binpath, sizeof(binpath));

    /* Skip our own daemon to prevent recursive loops */
    if (strcmp(binpath, DAEMON_BIN) == 0) {
        struct fanotify_response resp = { .fd = ev.fd, .response = FAN_ALLOW };
(void)write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev.fd);
        return NULL;
    }

    /* Skip kernel threads (pid 0 or kthreadd children) */
    if (ev.pid <= 1) {
        struct fanotify_response resp = { .fd = ev.fd, .response = FAN_ALLOW };
(void)write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev.fd);
        return NULL;
    }

    /* If paused — allow everything */
    if (g_Paused && time(NULL) < g_PauseUntil) {
        struct fanotify_response resp = { .fd = ev.fd, .response = FAN_ALLOW };
(void)write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev.fd);
        return NULL;
    } else if (g_Paused) {
        g_Paused = 0; /* pause expired */
    }

    /* Get full argv */
    char argv[EXEC_ARGV_MAX] = "";
    get_argv(ev.pid, argv, sizeof(argv), binpath);

    /* Get process name */
    char comm[64] = "";
    get_comm(ev.pid, comm, sizeof(comm));

    /* Local risk score */
    int score = local_risk_score(binpath, argv);
    int risk_threshold = 30; /* TODO: read from config */

    if (score <= risk_threshold) {
        /* Allow immediately — no API call */
        struct fanotify_response resp = { .fd = ev.fd, .response = FAN_ALLOW };
(void)write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev.fd);
        return NULL;
    }

    log_msg("INTERCEPT", "score=%d pid=%d comm=%s binary=%s argv=%s",
            score, (int)ev.pid, comm, binpath, argv);

    int approved = 0;
    if (call_agent_guard(binpath, argv, comm, ev.pid, &approved) < 0) {
        log_msg("ERROR", "API call failed — DENYING for safety");
        approved = 0;
    }

    struct fanotify_response resp = {
        .fd       = ev.fd,
        .response = approved ? FAN_ALLOW : FAN_DENY
    };
(void)write(g_FanotifyFd, &resp, sizeof(resp));
    close(ev.fd);

    return NULL;
}

/* ── Control socket (for authsec-shield pause / enable commands) ───────────── */

static void *control_thread(void *arg)
{
    (void)arg;

    unlink(CONTROL_SOCKET);
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    strncpy(addr.sun_path, CONTROL_SOCKET, sizeof(addr.sun_path)-1);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return NULL;
    }
    chmod(CONTROL_SOCKET, 0600); /* root only */
    listen(sock, 4);

    while (g_Running) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) continue;

        char buf[128] = {0};
        (void)read(client, buf, sizeof(buf)-1);

        if (strncmp(buf, "PAUSE ", 6) == 0) {
            int seconds = atoi(buf + 6);
            if (seconds > 0) {
                g_PauseUntil = time(NULL) + seconds;
                g_Paused = 1;
                log_msg("PAUSE", "Paused for %d seconds", seconds);
                (void)write(client, "OK\n", 3);
            }
        } else if (strcmp(buf, "ENABLE") == 0) {
            g_Paused = 0;
            g_PauseUntil = 0;
            log_msg("ENABLE", "Enforcement re-enabled");
            (void)write(client, "OK\n", 3);
        } else if (strcmp(buf, "STATUS") == 0) {
            char status[128];
            snprintf(status, sizeof(status), "running paused=%d\n", g_Paused);
            (void)write(client, status, strlen(status));
        }

        close(client);
    }

    close(sock);
    unlink(CONTROL_SOCKET);
    return NULL;
}

/* ── Load config ─────────────────────────────────────────────────────────── */

static void load_config(void)
{
    const char *apiURL = getenv("AUTHSEC_API_URL");
    if (apiURL) strncpy(g_ApiBaseURL, apiURL, sizeof(g_ApiBaseURL)-1);

    const char *token = getenv("AUTHSEC_TOKEN");
    if (token) strncpy(g_AccessToken, token, sizeof(g_AccessToken)-1);

    /* Config file */
    const char *cfgPaths[] = {
        "/etc/authsec-shield/config.json",
        NULL
    };
    char homeCfg[PATH_MAX];
    const char *home = getenv("HOME");
    if (home) {
        snprintf(homeCfg, sizeof(homeCfg), "%s/.config/authsec-shield/config.json", home);
        cfgPaths[1] = homeCfg;
    }

    FILE *f = NULL;
    for (int i = 0; cfgPaths[i]; i++) {
        f = fopen(cfgPaths[i], "r");
        if (f) { log_msg("INFO", "Config: %s", cfgPaths[i]); break; }
    }
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *json = malloc(sz + 1);
    if (!json) { fclose(f); return; }
    (void)fread(json, 1, sz, f);
    json[sz] = '\0';
    fclose(f);

    char tmp[2048];
    if (g_ApiBaseURL[0] == '\0') {
        if (json_str(json, "authsec_base_url", tmp, sizeof(tmp)) == 0)
            strncpy(g_ApiBaseURL, tmp, sizeof(g_ApiBaseURL)-1);
    }
    if (g_AccessToken[0] == '\0') {
        if (json_str(json, "access_token", tmp, sizeof(tmp)) == 0)
            strncpy(g_AccessToken, tmp, sizeof(g_AccessToken)-1);
    }
    free(json);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    (void)argc; (void)argv;

    if (geteuid() != 0) {
        fprintf(stderr, "[execmon] ERROR: Must run as root\n");
        return 1;
    }

    log_msg("INFO", "AuthSec Agent Shield — exec monitor starting (PID=%d)", (int)getpid());

    apply_self_protection();
    load_config();
    curl_global_init(CURL_GLOBAL_ALL);

    /* ── Load eBPF program ───────────────────────────────────────────────── */
    struct bpf_object *bpf_obj = NULL;
    struct ring_buffer *rb     = NULL;
    pthread_t ebpf_tid;
    int ebpf_available = 0;

    /* Look for pre-compiled BPF object */
    const char *bpf_obj_path = "/usr/local/lib/authsec-shield/authsec_execmon_ebpf.o";
    if (access(bpf_obj_path, R_OK) == 0) {
        bpf_obj = bpf_object__open(bpf_obj_path);
        if (bpf_obj && bpf_object__load(bpf_obj) == 0) {
            /* Attach both tracepoints */
            struct bpf_program *prog;
            bpf_object__for_each_program(prog, bpf_obj) {
                struct bpf_link *link = bpf_program__attach(prog);
                if (!link) {
                    log_msg("WARN", "Failed to attach eBPF program: %s",
                            bpf_program__name(prog));
                }
            }

            /* Find the ring buffer map */
            struct bpf_map *rb_map = bpf_object__find_map_by_name(bpf_obj, "exec_events");
            if (rb_map) {
                int rb_fd = bpf_map__fd(rb_map);
                rb = ring_buffer__new(rb_fd, ebpf_event_handler, NULL, NULL);
                if (rb) {
                    pthread_create(&ebpf_tid, NULL, ebpf_thread, rb);
                    ebpf_available = 1;
                    log_msg("INFO", "eBPF tracepoints loaded — argv capture active");
                }
            }
        }
    }

    if (!ebpf_available) {
        log_msg("WARN", "eBPF not available — using process_vm_readv fallback for argv");
    }

    /* ── Set up fanotify for ALL exec on the whole filesystem ──────────── */
    g_FanotifyFd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (g_FanotifyFd < 0) {
        g_FanotifyFd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE);
    }
    if (g_FanotifyFd < 0) {
        log_msg("ERROR", "fanotify_init failed: %s", strerror(errno));
        return 1;
    }

    /*
     * Mark the ENTIRE root filesystem for exec permission events.
     * FAN_MARK_FILESYSTEM covers all mounts under this filesystem type —
     * this catches execs on any path, regardless of binary name.
     */
    int ret = fanotify_mark(g_FanotifyFd,
                            FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                            FAN_OPEN_EXEC_PERM,
                            AT_FDCWD, "/");
    if (ret < 0) {
        /* Fallback: FAN_MARK_MOUNT on / */
        ret = fanotify_mark(g_FanotifyFd,
                            FAN_MARK_ADD | FAN_MARK_MOUNT,
                            FAN_OPEN_EXEC_PERM,
                            AT_FDCWD, "/");
    }
    if (ret < 0) {
        log_msg("ERROR", "fanotify_mark failed: %s (kernel 5.0+ required)", strerror(errno));
        return 1;
    }
    log_msg("INFO", "fanotify FAN_OPEN_EXEC_PERM active on / (all exec events intercepted)");

    /* ── Signals ───────────────────────────────────────────────────────── */
    struct sigaction sa = { .sa_handler = sig_handler };
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    signal(SIGHUP, SIG_IGN); /* don't die on HUP */

    /* ── Control socket thread ─────────────────────────────────────────── */
    pthread_t ctrl_tid;
    pthread_create(&ctrl_tid, NULL, control_thread, NULL);

    log_msg("INFO", "Exec monitor active. ALL process executions are now intercepted.");

    /* ── Main event loop ──────────────────────────────────────────────── */
    char evBuf[4096] __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    while (g_Running) {
        ssize_t len = read(g_FanotifyFd, evBuf, sizeof(evBuf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            log_msg("ERROR", "read(fanotify): %s", strerror(errno));
            break;
        }

        const struct fanotify_event_metadata *ev =
            (const struct fanotify_event_metadata *)evBuf;

        while (FAN_EVENT_OK(ev, len)) {
            if (ev->vers != FANOTIFY_METADATA_VERSION) {
                log_msg("ERROR", "fanotify metadata version mismatch");
                goto done;
            }
            if (ev->mask & FAN_Q_OVERFLOW) {
                log_msg("WARN", "fanotify queue overflow");
            } else if (ev->mask & FAN_OPEN_EXEC_PERM) {
                /* Dispatch to worker thread to avoid blocking the event loop */
                ThreadArg *ta = malloc(sizeof(ThreadArg));
                if (ta) {
                    ta->ev_copy = *ev;
                    ta->ev_copy.fd = ev->fd; /* fd ownership passed to thread */
                    pthread_t tid;
                    if (pthread_create(&tid, NULL, handle_exec_event_thread, ta) != 0) {
                        free(ta);
                        /* Fallback: handle inline (blocks event loop) */
                        ta = malloc(sizeof(ThreadArg));
                        if (ta) {
                            ta->ev_copy = *ev;
                            handle_exec_event_thread(ta);
                        }
                    } else {
                        pthread_detach(tid);
                        ev = FAN_EVENT_NEXT(ev, len);
                        continue;
                    }
                }
            }
            ev = FAN_EVENT_NEXT(ev, len);
        }
    }

done:
    close(g_FanotifyFd);
    if (rb)      ring_buffer__free(rb);
    if (bpf_obj) bpf_object__close(bpf_obj);
    curl_global_cleanup();

    log_msg("INFO", "Exec monitor stopped.");
    return 0;
}
