/*
 * RubyGuardian ptrace Helper Native Extension
 * Provides Ruby bindings for ptrace-based process inspection
 * Used to inspect memory and register state of monitored Ruby processes
 */

#include <ruby.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#ifdef HAVE_SYS_PTRACE_H
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#endif

static VALUE rb_mRubyGuardian;
static VALUE rb_mDetection;
static VALUE rb_cPtraceHelper;

/*
 * Attach to a process for inspection
 */
static VALUE ptrace_attach(VALUE self, VALUE pid) {
#ifdef HAVE_SYS_PTRACE_H
    pid_t target = NUM2INT(pid);
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0) {
        rb_raise(rb_eRuntimeError, "ptrace attach failed for pid %d: %s",
                 target, strerror(errno));
    }
    int status;
    waitpid(target, &status, 0);
    rb_iv_set(self, "@attached_pid", pid);
    return Qtrue;
#else
    rb_raise(rb_eNotImpError, "ptrace not available on this platform");
    return Qfalse;
#endif
}

/*
 * Detach from a process
 */
static VALUE ptrace_detach(VALUE self, VALUE pid) {
#ifdef HAVE_SYS_PTRACE_H
    pid_t target = NUM2INT(pid);
    if (ptrace(PTRACE_DETACH, target, NULL, NULL) < 0) {
        rb_raise(rb_eRuntimeError, "ptrace detach failed: %s", strerror(errno));
    }
    rb_iv_set(self, "@attached_pid", Qnil);
    return Qtrue;
#else
    rb_raise(rb_eNotImpError, "ptrace not available");
    return Qfalse;
#endif
}

/*
 * Read a word from process memory
 */
static VALUE ptrace_peek_data(VALUE self, VALUE pid, VALUE address) {
#ifdef HAVE_SYS_PTRACE_H
    pid_t target = NUM2INT(pid);
    unsigned long addr = NUM2ULONG(address);
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, target, (void *)addr, NULL);
    if (errno != 0) {
        rb_raise(rb_eRuntimeError, "ptrace peekdata failed at %lx: %s",
                 addr, strerror(errno));
    }
    return LONG2NUM(data);
#else
    rb_raise(rb_eNotImpError, "ptrace not available");
    return Qnil;
#endif
}

/*
 * Read a region of process memory
 */
static VALUE ptrace_read_memory(VALUE self, VALUE pid, VALUE address, VALUE length) {
#ifdef HAVE_SYS_PTRACE_H
    pid_t target = NUM2INT(pid);
    unsigned long addr = NUM2ULONG(address);
    size_t len = NUM2ULONG(length);
    size_t words = (len + sizeof(long) - 1) / sizeof(long);

    VALUE result = rb_str_buf_new(len);
    char *buf = RSTRING_PTR(result);

    for (size_t i = 0; i < words; i++) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, target,
                           (void *)(addr + i * sizeof(long)), NULL);
        if (errno != 0) break;
        memcpy(buf + i * sizeof(long), &data,
               (i == words - 1) ? len - i * sizeof(long) : sizeof(long));
    }

    rb_str_set_len(result, len);
    return result;
#else
    rb_raise(rb_eNotImpError, "ptrace not available");
    return Qnil;
#endif
}

/*
 * Get register state of the target process
 */
static VALUE ptrace_get_registers(VALUE self, VALUE pid) {
#if defined(HAVE_SYS_PTRACE_H) && defined(__x86_64__)
    pid_t target = NUM2INT(pid);
    struct user_regs_struct regs;

    if (ptrace(PTRACE_GETREGS, target, NULL, &regs) < 0) {
        rb_raise(rb_eRuntimeError, "ptrace getregs failed: %s", strerror(errno));
    }

    VALUE hash = rb_hash_new();
    rb_hash_aset(hash, rb_str_new_cstr("rip"), ULONG2NUM(regs.rip));
    rb_hash_aset(hash, rb_str_new_cstr("rsp"), ULONG2NUM(regs.rsp));
    rb_hash_aset(hash, rb_str_new_cstr("rbp"), ULONG2NUM(regs.rbp));
    rb_hash_aset(hash, rb_str_new_cstr("rax"), ULONG2NUM(regs.rax));
    rb_hash_aset(hash, rb_str_new_cstr("rdi"), ULONG2NUM(regs.rdi));
    rb_hash_aset(hash, rb_str_new_cstr("rsi"), ULONG2NUM(regs.rsi));
    rb_hash_aset(hash, rb_str_new_cstr("rdx"), ULONG2NUM(regs.rdx));
    return hash;
#else
    rb_raise(rb_eNotImpError, "Register access not available on this platform");
    return Qnil;
#endif
}

/*
 * Read /proc/pid/maps for memory layout
 */
static VALUE ptrace_read_maps(VALUE self, VALUE pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", NUM2INT(pid));

    FILE *f = fopen(path, "r");
    if (!f) {
        rb_raise(rb_eRuntimeError, "Cannot read %s: %s", path, strerror(errno));
    }

    VALUE maps = rb_ary_new();
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        rb_ary_push(maps, rb_str_new_cstr(line));
    }
    fclose(f);
    return maps;
}

void Init_ptrace_helper(void) {
    rb_mRubyGuardian = rb_define_module("RubyGuardian");
    rb_mDetection = rb_define_module_under(rb_mRubyGuardian, "Detection");
    rb_cPtraceHelper = rb_define_class_under(rb_mDetection, "PtraceHelper", rb_cObject);

    rb_define_method(rb_cPtraceHelper, "attach", ptrace_attach, 1);
    rb_define_method(rb_cPtraceHelper, "detach", ptrace_detach, 1);
    rb_define_method(rb_cPtraceHelper, "peek_data", ptrace_peek_data, 2);
    rb_define_method(rb_cPtraceHelper, "read_memory", ptrace_read_memory, 3);
    rb_define_method(rb_cPtraceHelper, "get_registers", ptrace_get_registers, 1);
    rb_define_method(rb_cPtraceHelper, "read_maps", ptrace_read_maps, 1);
}
