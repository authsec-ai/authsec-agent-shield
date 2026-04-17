/*
 * AuthSec Agent Shield — eBPF exec argument capture program
 *
 * Attached to: tracepoint/syscalls/sys_enter_execve
 *              tracepoint/syscalls/sys_enter_execveat
 *
 * Fires synchronously inside the execve syscall, BEFORE the binary is loaded.
 * Reads the full argv[] from userspace and pushes it to a BPF ring buffer.
 * The userspace daemon reads the ring buffer and uses argv for risk scoring,
 * then correlates with the fanotify FAN_OPEN_EXEC_PERM event by PID.
 *
 * Build:
 *   clang -target bpf -O2 -g \
 *     -I/usr/include/bpf \
 *     -I/usr/include/linux \
 *     -D__TARGET_ARCH_x86 \
 *     -c authsec_execmon_ebpf.c -o authsec_execmon_ebpf.o
 *
 * Requirements: Linux 5.8+ (BPF_MAP_TYPE_RINGBUF)
 *               Fallback to BPF_MAP_TYPE_PERF_EVENT_ARRAY for 5.0-5.7 is
 *               implemented in the userspace loader (authsec_execmon.c).
 */

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "authsec_execmon_ebpf.h"

char LICENSE[] SEC("license") = "GPL";

struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    unsigned long args[6];
};

/* Ring buffer map — zero-copy, ordered, lower overhead than perf event array */
struct {
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);   /* 256 KB */
} exec_events SEC(".maps");

/*
 * Per-CPU scratch space — avoids large stack allocation in eBPF
 * (eBPF stack limit is 512 bytes; exec_event is ~4.4 KB)
 */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct exec_event);
} scratch SEC(".maps");

/* ── Helper: read argv[] from userspace into a flat null-separated buffer ── */
static __always_inline int read_argv(const char *const *user_argv,
                                     char *out, __u32 outlen,
                                     __u32 *written)
{
    __u32 offset = 0;

    /* Unroll up to 32 args — eBPF verifier requires bounded loops */
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        const char *argp = NULL;

        if (bpf_probe_read_user(&argp, sizeof(argp), &user_argv[i]) < 0)
            break;
        if (!argp)
            break;

        __u32 remaining = outlen - offset;
        if (remaining == 0)
            break;

        int n = bpf_probe_read_user_str(out + offset, remaining, argp);
        if (n < 0)
            break;

        offset += (__u32)n;  /* n includes the null terminator */
    }

    *written = offset;
    return 0;
}

/* ── tracepoint/syscalls/sys_enter_execve ──────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e)
        return 0;

    /* PID / UID / comm */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->argv_len = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* Parent PID is filled by userspace fallback when needed. */
    e->ppid = 0;

    /* filename (ctx->args[0] = const char __user *filename) */
    bpf_probe_read_user_str(e->filename, sizeof(e->filename),
                            (const char *)ctx->args[0]);

    /* argv (ctx->args[1] = const char __user *const __user *argv) */
    const char *const *user_argv = (const char *const *)ctx->args[1];
    read_argv(user_argv, e->argv, sizeof(e->argv), &e->argv_len);

    bpf_ringbuf_submit(e, 0);

    return 0;
}

/* ── tracepoint/syscalls/sys_enter_execveat ─────────────────────────────── */
SEC("tracepoint/syscalls/sys_enter_execveat")
int tracepoint__sys_enter_execveat(struct trace_event_raw_sys_enter *ctx)
{
    struct exec_event *e = bpf_ringbuf_reserve(&exec_events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid  = (__u32)(pid_tgid >> 32);
    e->ppid = 0;
    e->uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->argv_len = 0;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    e->ppid = 0;

    /* execveat: args[1] = pathname, args[2] = argv */
    bpf_probe_read_user_str(e->filename, sizeof(e->filename),
                            (const char *)ctx->args[1]);

    const char *const *user_argv = (const char *const *)ctx->args[2];
    read_argv(user_argv, e->argv, sizeof(e->argv), &e->argv_len);

    bpf_ringbuf_submit(e, 0);

    return 0;
}
