// RubyGuardian eBPF Probe - Network Monitor
// Traces TCP connect() calls from Ruby processes to detect C2 callbacks,
// data exfiltration, and reverse shell connections.
//
// MITRE ATT&CK: T1071 (Application Layer Protocol), T1048 (Exfiltration)
// Compiled with: clang -O2 -target bpf -c network_monitor.c -o network_monitor.o

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define MAX_COMM_LEN 16

struct connect_event {
    __u32 pid;
    __u32 uid;
    __u64 timestamp;
    __u32 dest_addr;      // IPv4 destination
    __u16 dest_port;
    __u16 protocol;       // IPPROTO_TCP or IPPROTO_UDP
    char comm[MAX_COMM_LEN];
    __u64 bytes_sent;     // approximate
};

// Ring buffer for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} connect_events SEC(".maps");

// Suspicious port list (common C2 ports)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} suspicious_ports SEC(".maps");

// Connection counter per PID
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} conn_count SEC(".maps");

// Watched PIDs (Ruby processes)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} watched_pids SEC(".maps");

SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Only trace watched PIDs
    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched)
        return 0;

    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk)
        return 0;

    struct connect_event *event = bpf_ringbuf_reserve(&connect_events, sizeof(*event), 0);
    if (!event)
        return 0;

    event->pid = pid;
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event->timestamp = bpf_ktime_get_ns();
    event->protocol = IPPROTO_TCP;

    // Read destination address and port from sock struct
    bpf_probe_read_kernel(&event->dest_addr, sizeof(event->dest_addr),
                          &sk->__sk_common.skc_daddr);
    __u16 dport;
    bpf_probe_read_kernel(&dport, sizeof(dport),
                          &sk->__sk_common.skc_dport);
    event->dest_port = bpf_ntohs(dport);

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    // Increment connection counter
    __u64 *count = bpf_map_lookup_elem(&conn_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 init = 1;
        bpf_map_update_elem(&conn_count, &pid, &init, BPF_ANY);
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int trace_tcp_send(struct pt_regs *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    __u8 *watched = bpf_map_lookup_elem(&watched_pids, &pid);
    if (!watched)
        return 0;

    // Track bytes sent for exfiltration detection
    size_t size = (size_t)PT_REGS_PARM3(ctx);

    __u64 *count = bpf_map_lookup_elem(&conn_count, &pid);
    if (count) {
        __sync_fetch_and_add(count, size);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
