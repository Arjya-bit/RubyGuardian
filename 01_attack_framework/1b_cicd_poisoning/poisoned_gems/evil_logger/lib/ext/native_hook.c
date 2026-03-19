/*
 * =============================================================================
 * RubyGuardian Phase 1b -- Native Hook C Extension Stub
 *
 * EDUCATIONAL PURPOSE ONLY -- Authorized security research.
 * DO NOT compile or use this extension outside controlled lab environments.
 *
 * This C extension demonstrates how trojanized gems can use native code to:
 *   1. Hook Ruby method dispatch at the C level (harder to detect)
 *   2. Access process memory directly (bypass Ruby sandbox)
 *   3. Execute system calls without Ruby-level tracing
 *   4. Hide functionality from Ruby-level introspection tools
 *
 * MITRE ATT&CK:
 *   T1055     - Process Injection
 *   T1106     - Native API
 *   T1195.001 - Supply Chain Compromise
 *
 * DETECTION METHODS:
 *   - Audit C extensions in all gems (extconf.rb presence)
 *   - Compile with AddressSanitizer to detect memory corruption
 *   - Use Valgrind/strace during gem test suites
 *   - Static analysis of C source for suspicious syscalls
 *   - Monitor dlopen/dlsym calls for unexpected libraries
 * =============================================================================
 */

#include <ruby.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Module and class references */
static VALUE mNativeHook;
static VALUE cHookManager;

/*
 * EDUCATIONAL: This struct would track installed hooks in a real attack.
 * Each hook records the original method entry and the replacement.
 */
typedef struct {
    const char *class_name;
    const char *method_name;
    VALUE original_method;
    int active;
} hook_entry_t;

#define MAX_HOOKS 64
static hook_entry_t hook_table[MAX_HOOKS];
static int hook_count = 0;

/*
 * Get information about the Ruby VM internals.
 *
 * EDUCATIONAL: This demonstrates how C extensions can access Ruby internals
 * that are not exposed at the Ruby level. Real malware uses this to:
 *   - Read object internals (bypass encapsulation)
 *   - Modify frozen strings/objects
 *   - Access internal data structures
 *
 * SAFETY: This implementation only returns read-only diagnostic info.
 */
static VALUE
native_hook_vm_info(VALUE self)
{
    VALUE info = rb_hash_new();

    rb_hash_aset(info, rb_str_new_cstr("ruby_version"),
                 rb_str_new_cstr(ruby_version));
    rb_hash_aset(info, rb_str_new_cstr("ruby_platform"),
                 rb_str_new_cstr(ruby_platform));
    rb_hash_aset(info, rb_str_new_cstr("hook_count"),
                 INT2FIX(hook_count));
    rb_hash_aset(info, rb_str_new_cstr("max_hooks"),
                 INT2FIX(MAX_HOOKS));
    rb_hash_aset(info, rb_str_new_cstr("educational_only"),
                 Qtrue);

    return info;
}

/*
 * Simulate registering a native hook (does NOT actually hook).
 *
 * EDUCATIONAL: In a real attack, this would use rb_define_method to
 * replace a target method with a C function that intercepts calls.
 * The C-level hook is harder to detect than Ruby-level prepend because:
 *   - It doesn't appear in ancestors/method_defined? checks
 *   - TracePoint :call events may not fire for C methods
 *   - Ruby-level method inspection shows the C method, not the wrapper
 *
 * SAFETY: This implementation only records metadata, does not hook.
 */
static VALUE
native_hook_register(VALUE self, VALUE class_name, VALUE method_name)
{
    if (hook_count >= MAX_HOOKS) {
        rb_raise(rb_eRuntimeError, "Hook table full (max %d)", MAX_HOOKS);
    }

    /* Record the hook registration (simulation only) */
    hook_entry_t *entry = &hook_table[hook_count];
    entry->class_name = StringValueCStr(class_name);
    entry->method_name = StringValueCStr(method_name);
    entry->original_method = Qnil;
    entry->active = 0; /* NOT actually installed */
    hook_count++;

    /* Return registration metadata */
    VALUE result = rb_hash_new();
    rb_hash_aset(result, rb_str_new_cstr("status"),
                 rb_str_new_cstr("registered_simulation"));
    rb_hash_aset(result, rb_str_new_cstr("class"),
                 class_name);
    rb_hash_aset(result, rb_str_new_cstr("method"),
                 method_name);
    rb_hash_aset(result, rb_str_new_cstr("index"),
                 INT2FIX(hook_count - 1));
    rb_hash_aset(result, rb_str_new_cstr("warning"),
                 rb_str_new_cstr("EDUCATIONAL: Hook NOT actually installed"));

    return result;
}

/*
 * List all registered hooks.
 */
static VALUE
native_hook_list(VALUE self)
{
    VALUE list = rb_ary_new2(hook_count);

    for (int i = 0; i < hook_count; i++) {
        VALUE entry = rb_hash_new();
        rb_hash_aset(entry, rb_str_new_cstr("index"), INT2FIX(i));
        rb_hash_aset(entry, rb_str_new_cstr("class"),
                     rb_str_new_cstr(hook_table[i].class_name));
        rb_hash_aset(entry, rb_str_new_cstr("method"),
                     rb_str_new_cstr(hook_table[i].method_name));
        rb_hash_aset(entry, rb_str_new_cstr("active"),
                     hook_table[i].active ? Qtrue : Qfalse);
        rb_ary_push(list, entry);
    }

    return list;
}

/*
 * Demonstrate reading process memory info (read-only, safe).
 *
 * EDUCATIONAL: C extensions can read /proc/self/maps to understand the
 * process memory layout. This is used by attackers to:
 *   - Find loaded libraries for ROP gadgets
 *   - Locate heap/stack for exploitation
 *   - Detect ASLR layout for injection
 *
 * SAFETY: Only reads own process info, no modification.
 */
static VALUE
native_hook_proc_maps(VALUE self)
{
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) {
        return rb_str_new_cstr("Could not read /proc/self/maps");
    }

    VALUE result = rb_ary_new();
    char line[512];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < 20) {
        /* Remove trailing newline */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        rb_ary_push(result, rb_str_new_cstr(line));
        count++;
    }

    fclose(f);
    return result;
}

/*
 * Reset the hook table (for testing).
 */
static VALUE
native_hook_reset(VALUE self)
{
    memset(hook_table, 0, sizeof(hook_table));
    hook_count = 0;
    return Qtrue;
}

/*
 * Extension initialization entry point.
 *
 * EDUCATIONAL: Init_native_hook is called automatically when the extension
 * is loaded via require. A malicious extension would perform its payload
 * setup here, before any Ruby code has a chance to inspect it.
 */
void
Init_native_hook(void)
{
    /* Define the NativeHook module under EvilLogger */
    VALUE mEvilLogger = rb_define_module("EvilLogger");
    mNativeHook = rb_define_module_under(mEvilLogger, "NativeHook");

    /* Define the HookManager class */
    cHookManager = rb_define_class_under(mNativeHook, "HookManager", rb_cObject);

    /* Register methods */
    rb_define_singleton_method(mNativeHook, "vm_info",
                                native_hook_vm_info, 0);
    rb_define_singleton_method(mNativeHook, "register_hook",
                                native_hook_register, 2);
    rb_define_singleton_method(mNativeHook, "list_hooks",
                                native_hook_list, 0);
    rb_define_singleton_method(mNativeHook, "proc_maps",
                                native_hook_proc_maps, 0);
    rb_define_singleton_method(mNativeHook, "reset!",
                                native_hook_reset, 0);

    /* EDUCATIONAL: Print a warning when loaded */
    fprintf(stderr,
        "[EDUCATIONAL] EvilLogger NativeHook extension loaded.\n"
        "[EDUCATIONAL] This is a security research tool. Do not use in production.\n");
}
