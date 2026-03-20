// RubyGuardian eBPF Probe - Execve Monitor
// Traces all execve() system calls to detect process execution by Ruby processes.
// Compiled with: clang -O2 -target bpf -c execve_monitor.c -o execve_monitor.o
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
// This probe attaches to the sys_enter_execve tracepoint and captures:
//   - Process ID and thread group ID
//   - Parent process ID
//   - Executable path
//   - Command-line arguments (first 4)
//   - Timestamp

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_FILENAME_LEN 256
#define MAX_ARGS 4
#define MAX_ARG_LEN 128

struct execve_event {
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u64 timestamp;
    char filename[MAX_FILENAME_LEN];
    char args[MAX_ARGS][MAX_ARG_LEN];
    __u8 arg_count;
};

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// PID filter map - only trace these PIDs (Ruby processes)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);  // 0 = filter by PID, 1 = trace all
} config SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    // Check if we should filter by PID
    __u32 key = 0;
    __u8 *trace_all = bpf_map_lookup_elem(&config, &key);
    if (trace_all && *trace_all == 0) {
        __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
        if (!watched)
            return 0;
    }

    struct execve_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->tgid = tgid;
    event->timestamp = bpf_ktime_get_ns();
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get parent PID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid),
                          &task->real_parent->tgid);

    // Read filename (first argument to execve)
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);

    // Read argv
    const char *const *argv = (const char *const *)ctx->args[1];
    event->arg_count = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg = NULL;
        bpf_probe_read_user(&arg, sizeof(arg), &argv[i]);
        if (!arg)
            break;
        bpf_probe_read_user_str(event->args[i], MAX_ARG_LEN, arg);
        event->arg_count++;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
