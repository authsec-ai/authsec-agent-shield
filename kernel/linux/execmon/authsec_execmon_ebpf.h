/*
 * AuthSec Agent Shield — shared structs between eBPF program and userspace daemon
 */
#pragma once

#define EXEC_ARGV_MAX  4096
#define EXEC_PATH_MAX   256
#define EXEC_COMM_MAX    16

/*
 * exec_event is pushed into the BPF ring buffer by the eBPF tracepoint program
 * and consumed by the userspace daemon to correlate with fanotify events.
 *
 * Layout matches what bpf_probe_read_user_str produces: each argument is a
 * null-terminated string, arguments are concatenated, total length in argv_len.
 * This is the same format as /proc/PID/cmdline.
 */
struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[EXEC_COMM_MAX];           /* process name of caller (pre-exec) */
    char  filename[EXEC_PATH_MAX];       /* argv[0] / path passed to execve   */
    char  argv[EXEC_ARGV_MAX];           /* all args, null-separated           */
    __u32 argv_len;                      /* total bytes used in argv[]         */
    __u64 timestamp_ns;                  /* bpf_ktime_get_ns()                 */
};
