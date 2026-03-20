// RubyGuardian eBPF Probe - File Monitor
// Traces file open/read/write operations from Ruby processes to detect:
//   - Credential file access (T1552 - Unsecured Credentials)
//   - Configuration tampering (T1543 - Create or Modify System Process)
//   - Gem directory manipulation (T1195 - Supply Chain Compromise)
//
// Compiled with: clang -O2 -target bpf -c file_monitor.c -o file_monitor.o

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 256
#define MAX_COMM_LEN 16

struct file_event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    __u32 flags;          // O_RDONLY, O_WRONLY, O_RDWR, etc.
    __u32 mode;
    char path[MAX_PATH_LEN];
    char comm[MAX_COMM_LEN];
    __u8 event_type;      // 0=open, 1=read, 2=write, 3=unlink
};

// Ring buffer for file events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} file_events SEC(".maps");

// Watched PIDs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

// Sensitive path prefixes to monitor
// Populated from userspace with paths like /etc/passwd, ~/.ssh, gem paths
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[64]);
    __type(value, __u8);     // sensitivity level: 1=low, 2=medium, 3=high, 4=critical
} sensitive_paths SEC(".maps");

// Per-PID file operation counters (for anomaly detection)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} file_op_count SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched)
        return 0;

    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = 0;  // open

    // Read flags and path
    event->flags = (__u32)ctx->args[2];
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(event->path, sizeof(event->path), pathname);
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Increment file op counter
    __u64 *count = bpf_map_lookup_elem(&file_op_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&file_op_count, &pid, &init, BPF_ANY);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched)
        return 0;

    struct file_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->event_type = 3;  // unlink

    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(event->path, sizeof(event->path), pathname);
    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
