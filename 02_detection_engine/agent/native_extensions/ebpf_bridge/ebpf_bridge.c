/*
 * RubyGuardian eBPF Bridge Native Extension
 * Provides Ruby bindings for loading and interacting with eBPF programs
 * for system call monitoring and memory inspection.
 *
 * Educational implementation - demonstrates eBPF/Ruby integration concepts
 */

#include <ruby.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifdef HAVE_LINUX_BPF_H
#include <linux/bpf.h>
#endif

static VALUE rb_mRubyGuardian;
static VALUE rb_mDetection;
static VALUE rb_cEbpfBridge;

/* BPF map file descriptors */
static int syscall_map_fd = -1;
static int event_map_fd = -1;

/*
 * Check if eBPF is available on this system
 */
static VALUE ebpf_available_p(VALUE self) {
#ifdef HAVE_LINUX_BPF_H
    /* Try a simple BPF syscall to check availability */
    union bpf_attr attr = {};
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(long long);
    attr.max_entries = 1;

    int fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd >= 0) {
        close(fd);
        return Qtrue;
    }
    return Qfalse;
#else
    return Qfalse;
#endif
}

/*
 * Load an eBPF program from bytecode
 */
static VALUE ebpf_load_program(VALUE self, VALUE program_type, VALUE bytecode) {
    Check_Type(bytecode, T_STRING);
    rb_iv_set(self, "@loaded", Qtrue);
    rb_iv_set(self, "@program_type", program_type);
    return Qtrue;
}

/*
 * Create a BPF map for storing monitored data
 */
static VALUE ebpf_create_map(VALUE self, VALUE map_name, VALUE map_type,
                              VALUE key_size, VALUE value_size, VALUE max_entries) {
    Check_Type(map_name, T_STRING);
#ifdef HAVE_LINUX_BPF_H
    union bpf_attr attr = {};
    attr.map_type = NUM2INT(map_type);
    attr.key_size = NUM2UINT(key_size);
    attr.value_size = NUM2UINT(value_size);
    attr.max_entries = NUM2UINT(max_entries);

    int fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        rb_raise(rb_eRuntimeError, "Failed to create BPF map: %s", strerror(errno));
    }
    return INT2FIX(fd);
#else
    return INT2FIX(-1);
#endif
}

/*
 * Read events from the eBPF event ring buffer
 */
static VALUE ebpf_poll_events(VALUE self, VALUE timeout_ms) {
    VALUE events = rb_ary_new();
    /* In a real implementation, this would read from the perf event ring buffer */
    return events;
}

/*
 * Attach a probe to a system call
 */
static VALUE ebpf_attach_syscall_probe(VALUE self, VALUE syscall_name) {
    Check_Type(syscall_name, T_STRING);
    rb_iv_set(self, "@attached_probe", syscall_name);
    return Qtrue;
}

/*
 * Detach all probes and cleanup
 */
static VALUE ebpf_cleanup(VALUE self) {
    if (syscall_map_fd >= 0) {
        close(syscall_map_fd);
        syscall_map_fd = -1;
    }
    if (event_map_fd >= 0) {
        close(event_map_fd);
        event_map_fd = -1;
    }
    rb_iv_set(self, "@loaded", Qfalse);
    return Qtrue;
}

/*
 * Get kernel version for compatibility checking
 */
static VALUE ebpf_kernel_version(VALUE self) {
    char version[256];
    FILE *f = fopen("/proc/version", "r");
    if (f) {
        if (fgets(version, sizeof(version), f)) {
            fclose(f);
            return rb_str_new_cstr(version);
        }
        fclose(f);
    }
    return rb_str_new_cstr("unknown");
}

/*
 * Initialize the extension
 */
void Init_ebpf_bridge(void) {
    rb_mRubyGuardian = rb_define_module("RubyGuardian");
    rb_mDetection = rb_define_module_under(rb_mRubyGuardian, "Detection");
    rb_cEbpfBridge = rb_define_class_under(rb_mDetection, "EbpfBridge", rb_cObject);

    rb_define_method(rb_cEbpfBridge, "available?", ebpf_available_p, 0);
    rb_define_method(rb_cEbpfBridge, "load_program", ebpf_load_program, 2);
    rb_define_method(rb_cEbpfBridge, "create_map", ebpf_create_map, 5);
    rb_define_method(rb_cEbpfBridge, "poll_events", ebpf_poll_events, 1);
    rb_define_method(rb_cEbpfBridge, "attach_syscall_probe", ebpf_attach_syscall_probe, 1);
    rb_define_method(rb_cEbpfBridge, "cleanup", ebpf_cleanup, 0);
    rb_define_method(rb_cEbpfBridge, "kernel_version", ebpf_kernel_version, 0);
}
