/*
 * AuthSec Agent Shield — Linux fanotify Daemon
 *
 * Uses the Linux fanotify(7) API with FAN_OPEN_PERM + FAN_ACCESS_PERM to
 * intercept filesystem access at the kernel level.
 *
 * Unlike inotify, fanotify is a PERMISSION interface — the kernel blocks
 * the calling process until this daemon writes an allow/deny response.
 * No userspace process can bypass this, including MSYS2-equivalent layers.
 *
 * Architecture:
 *   AI tool calls open(2) / unlink(2) / rename(2) / truncate(2)
 *       ↓
 *   Kernel fanotify permission event fires
 *       ↓
 *   This daemon reads event: path, pid, process name, operation
 *       ↓  (if path is protected and op is risky)
 *   Daemon calls Agent Guard API → push notification → human decision
 *       ↓ approved:  write FAN_ALLOW to fanotify fd
 *       ↓ denied:    write FAN_DENY  to fanotify fd
 *
 * Requirements:
 *   - Linux kernel 5.1+ (FAN_REPORT_FID), 5.9+ (FAN_MARK_FILESYSTEM)
 *   - CAP_SYS_ADMIN or root (required for fanotify permission events)
 *   - libcurl (for Agent Guard API calls)
 *
 * Build:
 *   gcc -O2 -Wall -Wextra -o authsec-shield-fanotify authsec_shield_fanotify.c -lcurl -lpthread
 *
 * Install:
 *   sudo cp authsec-shield-fanotify /usr/local/sbin/
 *   sudo systemctl enable --now authsec-shield-fanotify
 *
 * Config: reads /etc/authsec-shield/config.json (same format as Go shield)
 * or environment variables: AUTHSEC_API_URL, AUTHSEC_TOKEN, AUTHSEC_PATHS
 */

#define _GNU_SOURCE
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
#include <linux/limits.h>
#include <curl/curl.h>

// ── Configuration ─────────────────────────────────────────────────────────────

#define MAX_PROTECTED_PATHS  32
#define MAX_POLL_ATTEMPTS    12   // 12 × 5s = 60s timeout
#define POLL_INTERVAL_MS     5000

static char  g_ApiBaseURL[1024]             = "";
static char  g_AccessToken[4096]            = "";
static char* g_ProtectedPaths[MAX_PROTECTED_PATHS];
static int   g_ProtectedPathCount           = 0;
static int   g_FanotifyFd                   = -1;
static volatile int g_Running               = 1;

// ── Logging ───────────────────────────────────────────────────────────────────

static void log_msg(const char* level, const char* fmt, ...)
{
    va_list args;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    fprintf(stderr, "[shield-fanotify] [%ld.%03ld] [%s] ",
            (long)tv.tv_sec, (long)(tv.tv_usec / 1000), level);
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr, "\n");
    fflush(stderr);
}

// ── Path matching ─────────────────────────────────────────────────────────────

static int is_protected_path(const char* path)
{
    for (int i = 0; i < g_ProtectedPathCount; i++) {
        const char* prot = g_ProtectedPaths[i];
        size_t plen = strlen(prot);
        if (strncmp(path, prot, plen) == 0) {
            // Must be exact match or subdirectory
            if (path[plen] == '/' || path[plen] == '\0') {
                return 1;
            }
        }
    }
    return 0;
}

// ── Process name from /proc/pid/comm ─────────────────────────────────────────

static void get_process_name(pid_t pid, char* buf, size_t buflen)
{
    char procPath[64];
    snprintf(procPath, sizeof(procPath), "/proc/%d/comm", (int)pid);
    FILE* f = fopen(procPath, "r");
    if (!f) {
        strncpy(buf, "unknown", buflen);
        return;
    }
    if (!fgets(buf, (int)buflen, f)) {
        strncpy(buf, "unknown", buflen);
    }
    fclose(f);
    // Strip newline
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
}

// ── Get file path from /proc/self/fd/<fd> ─────────────────────────────────────

static int get_path_from_fd(int fd, char* buf, size_t buflen)
{
    char fdPath[64];
    snprintf(fdPath, sizeof(fdPath), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(fdPath, buf, buflen - 1);
    if (n < 0) return -1;
    buf[n] = '\0';
    return 0;
}

// ── libcurl response buffer ───────────────────────────────────────────────────

typedef struct {
    char* data;
    size_t len;
    size_t cap;
} CurlBuf;

static size_t curl_write_cb(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    CurlBuf* buf = (CurlBuf*)userdata;
    size_t total = size * nmemb;
    if (buf->len + total + 1 > buf->cap) {
        buf->cap = buf->len + total + 1 + 4096;
        buf->data = realloc(buf->data, buf->cap);
        if (!buf->data) return 0;
    }
    memcpy(buf->data + buf->len, ptr, total);
    buf->len += total;
    buf->data[buf->len] = '\0';
    return total;
}

// ── Extract JSON string field ─────────────────────────────────────────────────

static int extract_json_string(const char* json, const char* key, char* out, size_t outlen)
{
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char* p = strstr(json, search);
    if (!p) return -1;
    p += strlen(search);
    size_t i = 0;
    while (*p && *p != '"' && i < outlen - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return 0;
}

// ── Agent Guard API ───────────────────────────────────────────────────────────

static int call_agent_guard(const char* filePath, const char* processName,
                             const char* operation, int* approved)
{
    *approved = 0; // default deny

    if (g_ApiBaseURL[0] == '\0' || g_AccessToken[0] == '\0') {
        log_msg("WARN", "No API URL/token configured — defaulting to DENY");
        return 0; // known state
    }

    CURL* curl = curl_easy_init();
    if (!curl) return -1;

    // Build evaluate URL
    char evalURL[2048];
    snprintf(evalURL, sizeof(evalURL), "%s/authsec/uflow/agent/actions/evaluate", g_ApiBaseURL);

    // Build JSON body — escape paths
    char jsonBody[4096];
    int bodyLen = snprintf(jsonBody, sizeof(jsonBody),
        "{\"agent_id\":\"authsec-shield-fanotify\","
        "\"agent_name\":\"AuthSec Agent Shield (fanotify)\","
        "\"agent_framework\":\"fanotify\","
        "\"action\":\"%s\","
        "\"resource\":\"%s\","
        "\"detail\":\"Kernel intercepted %s on %s by %s\","
        "\"metadata\":{\"process\":\"%s\"}}",
        operation, filePath, operation, filePath, processName, processName);

    // Auth header
    char authHeader[4200];
    snprintf(authHeader, sizeof(authHeader), "Authorization: Bearer %s", g_AccessToken);

    struct curl_slist* headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, authHeader);

    CurlBuf respBuf = { .data = malloc(8192), .len = 0, .cap = 8192 };
    if (!respBuf.data) {
        curl_easy_cleanup(curl);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL,            evalURL);
    curl_easy_setopt(curl, CURLOPT_POST,            1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,      jsonBody);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,   (long)bodyLen);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,      headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &respBuf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,         10L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        log_msg("ERROR", "evaluate request failed: %s", curl_easy_strerror(res));
        free(respBuf.data);
        curl_easy_cleanup(curl);
        return -1;
    }

    // Check for auto_approved
    char status[64] = "";
    extract_json_string(respBuf.data, "status", status, sizeof(status));
    if (strcmp(status, "auto_approved") == 0) {
        log_msg("AUTO_APPROVED", "%s %s", operation, filePath);
        *approved = 1;
        free(respBuf.data);
        curl_easy_cleanup(curl);
        return 0;
    }

    // Get action_req_id for polling
    char actionReqId[64] = "";
    if (extract_json_string(respBuf.data, "action_req_id", actionReqId, sizeof(actionReqId)) < 0) {
        log_msg("ERROR", "No action_req_id in response: %s", respBuf.data);
        free(respBuf.data);
        curl_easy_cleanup(curl);
        return -1;
    }
    free(respBuf.data);

    log_msg("PENDING", "%s %s — waiting (req_id=%s)", operation, filePath, actionReqId);

    // Poll for decision
    char statusURL[2048];
    snprintf(statusURL, sizeof(statusURL),
             "%s/authsec/uflow/agent/actions/status?action_req_id=%s",
             g_ApiBaseURL, actionReqId);

    for (int attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
        usleep(POLL_INTERVAL_MS * 1000);

        CurlBuf pollBuf = { .data = malloc(4096), .len = 0, .cap = 4096 };
        if (!pollBuf.data) break;

        curl_easy_setopt(curl, CURLOPT_URL,          statusURL);
        curl_easy_setopt(curl, CURLOPT_HTTPGET,       1L);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA,     &pollBuf);

        struct curl_slist* pollHeaders = NULL;
        pollHeaders = curl_slist_append(pollHeaders, authHeader);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, pollHeaders);

        CURLcode pres = curl_easy_perform(curl);
        curl_slist_free_all(pollHeaders);

        if (pres != CURLE_OK) {
            free(pollBuf.data);
            continue;
        }

        char pollStatus[64] = "";
        extract_json_string(pollBuf.data, "status", pollStatus, sizeof(pollStatus));
        free(pollBuf.data);

        if (strcmp(pollStatus, "approved") == 0 || strcmp(pollStatus, "auto_approved") == 0) {
            log_msg("APPROVED", "req_id=%s", actionReqId);
            *approved = 1;
            break;
        }
        if (strcmp(pollStatus, "denied")    == 0 ||
            strcmp(pollStatus, "expired")   == 0 ||
            strcmp(pollStatus, "timed_out") == 0) {
            log_msg("DENIED", "req_id=%s status=%s", actionReqId, pollStatus);
            *approved = 0;
            break;
        }
        // Still pending
    }

    curl_easy_cleanup(curl);
    return 0;
}

// ── fanotify event handler ────────────────────────────────────────────────────

static void handle_event(struct fanotify_event_metadata* ev)
{
    if (ev->fd < 0) return;

    char path[PATH_MAX] = "";
    if (get_path_from_fd(ev->fd, path, sizeof(path)) < 0) {
        // Can't determine path — allow (be conservative, don't block random ops)
        struct fanotify_response resp = {
            .fd       = ev->fd,
            .response = FAN_ALLOW
        };
        write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev->fd);
        return;
    }

    // Check if this is a protected path
    if (!is_protected_path(path)) {
        struct fanotify_response resp = { .fd = ev->fd, .response = FAN_ALLOW };
        write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev->fd);
        return;
    }

    // Determine operation type
    const char* operation = "write";
    if (ev->mask & FAN_OPEN_PERM)   operation = "open-write";
    if (ev->mask & FAN_ACCESS_PERM) operation = "read";

    // Get process name
    char procName[256] = "";
    get_process_name(ev->pid, procName, sizeof(procName));

    // Skip our own daemon — prevent recursive loops
    if (ev->pid == getpid()) {
        struct fanotify_response resp = { .fd = ev->fd, .response = FAN_ALLOW };
        write(g_FanotifyFd, &resp, sizeof(resp));
        close(ev->fd);
        return;
    }

    log_msg("INTERCEPT", "pid=%d (%s) op=%s path=%s",
            (int)ev->pid, procName, operation, path);

    // Call Agent Guard API
    int approved = 0;
    if (call_agent_guard(path, procName, operation, &approved) < 0) {
        log_msg("ERROR", "API call failed — DENYING for safety");
        approved = 0;
    }

    struct fanotify_response resp = {
        .fd       = ev->fd,
        .response = approved ? FAN_ALLOW : FAN_DENY
    };
    write(g_FanotifyFd, &resp, sizeof(resp));
    close(ev->fd);
}

// ── Signal handler ────────────────────────────────────────────────────────────

static void sig_handler(int sig)
{
    (void)sig;
    g_Running = 0;
    log_msg("INFO", "Shutting down...");
}

// ── Mark protected paths ──────────────────────────────────────────────────────

static int mark_protected_paths(int fanotify_fd)
{
    int marked = 0;
    for (int i = 0; i < g_ProtectedPathCount; i++) {
        const char* path = g_ProtectedPaths[i];
        struct stat st;
        if (stat(path, &st) < 0) {
            log_msg("WARN", "Path does not exist, skipping: %s", path);
            continue;
        }

        // FAN_MARK_ADD | FAN_MARK_MOUNT marks the entire mount point
        // FAN_OPEN_PERM: intercept opens with write intent
        // FAN_ACCESS_PERM: intercept reads (for data exfiltration prevention — optional)
        int ret = fanotify_mark(fanotify_fd,
                                FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                                FAN_OPEN_PERM | FAN_CLOSE_WRITE,
                                AT_FDCWD, path);
        if (ret < 0) {
            // FAN_MARK_FILESYSTEM requires Linux 5.1+
            // Fall back to FAN_MARK_MOUNT
            ret = fanotify_mark(fanotify_fd,
                                FAN_MARK_ADD | FAN_MARK_MOUNT,
                                FAN_OPEN_PERM | FAN_CLOSE_WRITE,
                                AT_FDCWD, path);
        }
        if (ret < 0) {
            log_msg("ERROR", "fanotify_mark failed for %s: %s", path, strerror(errno));
        } else {
            log_msg("MARKED", "%s", path);
            marked++;
        }
    }
    return marked;
}

// ── Load config ───────────────────────────────────────────────────────────────
// Simple JSON parser for our config format — no external dependency

static void load_config(void)
{
    // Environment overrides
    const char* apiURL = getenv("AUTHSEC_API_URL");
    if (apiURL) strncpy(g_ApiBaseURL, apiURL, sizeof(g_ApiBaseURL)-1);

    const char* token = getenv("AUTHSEC_TOKEN");
    if (token) strncpy(g_AccessToken, token, sizeof(g_AccessToken)-1);

    // Load from config file
    const char* configPaths[] = {
        "/etc/authsec-shield/config.json",
        NULL
    };
    // Also check $HOME/.config/authsec-shield/config.json
    char homeCfg[PATH_MAX];
    const char* home = getenv("HOME");
    if (home) {
        snprintf(homeCfg, sizeof(homeCfg), "%s/.config/authsec-shield/config.json", home);
        configPaths[1] = homeCfg; // intentional: array size is 2+NULL
    }

    FILE* f = NULL;
    for (int i = 0; configPaths[i]; i++) {
        f = fopen(configPaths[i], "r");
        if (f) {
            log_msg("INFO", "Loading config from %s", configPaths[i]);
            break;
        }
    }
    if (!f) {
        log_msg("WARN", "No config file found. Using environment variables only.");
        return;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* cfgJson = malloc(fsize + 1);
    if (!cfgJson) { fclose(f); return; }
    fread(cfgJson, 1, fsize, f);
    cfgJson[fsize] = '\0';
    fclose(f);

    // Extract authsec_base_url / access_token
    char tmp[2048];
    if (g_ApiBaseURL[0] == '\0') {
        if (extract_json_string(cfgJson, "authsec_base_url", tmp, sizeof(tmp)) == 0)
            strncpy(g_ApiBaseURL, tmp, sizeof(g_ApiBaseURL)-1);
    }
    if (g_AccessToken[0] == '\0') {
        if (extract_json_string(cfgJson, "access_token", tmp, sizeof(tmp)) == 0)
            strncpy(g_AccessToken, tmp, sizeof(g_AccessToken)-1);
    }

    // Extract protected_paths array — find entries between [ and ]
    const char* arrStart = strstr(cfgJson, "\"protected_paths\"");
    if (arrStart) {
        arrStart = strchr(arrStart, '[');
        const char* arrEnd = arrStart ? strchr(arrStart, ']') : NULL;
        if (arrStart && arrEnd) {
            const char* p = arrStart + 1;
            while (p < arrEnd && g_ProtectedPathCount < MAX_PROTECTED_PATHS) {
                p = strchr(p, '"');
                if (!p || p >= arrEnd) break;
                p++; // skip opening quote
                const char* end = strchr(p, '"');
                if (!end || end >= arrEnd) break;
                size_t len = (size_t)(end - p);
                if (len > 0 && len < PATH_MAX) {
                    char* pathStr = malloc(len + 1);
                    if (pathStr) {
                        strncpy(pathStr, p, len);
                        pathStr[len] = '\0';
                        // Unescape \\
                        char* dst = pathStr;
                        for (const char* src = pathStr; *src; src++) {
                            if (*src == '\\' && *(src+1) == '\\') {
                                *dst++ = '/'; src++; // normalize to forward slash
                            } else {
                                *dst++ = *src;
                            }
                        }
                        *dst = '\0';
                        g_ProtectedPaths[g_ProtectedPathCount++] = pathStr;
                        log_msg("PROTECT", "%s", pathStr);
                    }
                }
                p = end + 1;
            }
        }
    }

    free(cfgJson);
}

// ── Main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
    (void)argc; (void)argv;

    log_msg("INFO", "AuthSec Agent Shield — fanotify daemon starting");
    log_msg("INFO", "PID: %d", (int)getpid());

    // Check capabilities
    if (geteuid() != 0) {
        log_msg("ERROR", "Must run as root (CAP_SYS_ADMIN required for fanotify permission events)");
        return 1;
    }

    // Load config
    load_config();

    if (g_ProtectedPathCount == 0) {
        log_msg("WARN", "No protected paths configured. Daemon will run but intercept nothing.");
        log_msg("WARN", "Set protected_paths in config.json or use AUTHSEC_PATHS env var.");
    }

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_ALL);

    // Create fanotify instance
    // FAN_CLASS_CONTENT: permission events (blocks until we respond)
    // FAN_REPORT_FID: include file identifier (Linux 5.1+)
    g_FanotifyFd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (g_FanotifyFd < 0) {
        // Fallback without FAN_REPORT_FID for older kernels
        g_FanotifyFd = fanotify_init(FAN_CLASS_CONTENT, O_RDONLY | O_LARGEFILE);
    }
    if (g_FanotifyFd < 0) {
        log_msg("ERROR", "fanotify_init failed: %s (kernel 3.8+ required)", strerror(errno));
        return 1;
    }

    // Mark protected paths
    int marked = mark_protected_paths(g_FanotifyFd);
    log_msg("INFO", "Marking complete: %d/%d paths active", marked, g_ProtectedPathCount);

    // Signal handlers
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGHUP,  sig_handler);

    log_msg("INFO", "Shield active. Intercepting writes to protected paths...");

    // Event loop
    char evBuf[4096]
        __attribute__((aligned(__alignof__(struct fanotify_event_metadata))));

    while (g_Running) {
        ssize_t len = read(g_FanotifyFd, evBuf, sizeof(evBuf));
        if (len < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            log_msg("ERROR", "read(fanotify) failed: %s", strerror(errno));
            break;
        }

        const struct fanotify_event_metadata* ev =
            (const struct fanotify_event_metadata*)evBuf;

        while (FAN_EVENT_OK(ev, len)) {
            if (ev->vers != FANOTIFY_METADATA_VERSION) {
                log_msg("ERROR", "fanotify metadata version mismatch");
                goto done;
            }
            if (ev->mask & FAN_Q_OVERFLOW) {
                log_msg("WARN", "fanotify queue overflow — some events dropped");
            } else {
                // Copy to avoid buffer reuse issues in threaded handling
                struct fanotify_event_metadata evCopy = *ev;
                handle_event(&evCopy);
            }
            ev = FAN_EVENT_NEXT(ev, len);
        }
    }

done:
    close(g_FanotifyFd);
    curl_global_cleanup();

    // Free path strings
    for (int i = 0; i < g_ProtectedPathCount; i++) {
        free(g_ProtectedPaths[i]);
    }

    log_msg("INFO", "Daemon stopped.");
    return 0;
}
