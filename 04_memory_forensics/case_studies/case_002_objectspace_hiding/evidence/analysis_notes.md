# Case 002: ObjectSpace Object Hiding Attack

## Summary

An advanced persistence technique was discovered in a compromised Sidekiq
worker process where the attacker used Ruby's `ObjectSpace` API to hide
malicious objects from standard introspection and monitoring tools. The
backdoor survived process restarts by injecting itself into the Ruby VM's
internal method table and evading garbage collection through deliberate
reference manipulation.

## Timeline

- **T-21d**: Attacker gains initial access through a deserialization
  vulnerability in a Sidekiq job that processes untrusted YAML input.
- **T-14d**: Attacker deploys a persistence mechanism that hides malicious
  Class and Module objects from `ObjectSpace.each_object` enumeration.
- **T-7d**: Monitoring tools (NewRelic, Datadog) fail to detect the
  backdoor because they rely on ObjectSpace for Ruby-level introspection.
- **T-0**: RubyGuardian memory forensics detects hidden objects by directly
  scanning the heap at the RValue level, bypassing ObjectSpace enumeration.

## Memory Forensic Findings

### ObjectSpace Evasion Technique

The attacker used the following technique to hide objects:

1. **`ObjectSpace.define_finalizer`** was set on the malicious class to
   prevent garbage collection by creating a reference cycle.
2. **`rb_gc_unregister_address`** was called via FFI to unlink the object
   from the GC's mark table while maintaining a raw pointer reference.
3. **Method entries** were injected directly into the method table of
   `BasicObject` using `rb_define_method` through a C extension, making
   the backdoor accessible from any Ruby object.

### Heap Analysis

Memory dump analysis revealed:

1. **Hidden Objects Found**: 7 `T_CLASS` and 3 `T_MODULE` objects were
   found in non-heap anonymous memory regions (`mmap`'d pages) that are
   not enumerable via `ObjectSpace.each_object`.

2. **Reference Graph Anomaly**: The hidden objects formed a closed
   reference cycle with no inbound references from the normal heap. This
   is a signature of deliberate GC evasion.

3. **Method Table Injection**: The hidden `T_CLASS` object at address
   `0x7f8a2c100040` had a method table containing 4 methods:
   - `__bg_connect` -- Establishes reverse shell
   - `__bg_exfil` -- Exfiltrates data via DNS tunneling
   - `__bg_persist` -- Re-injects on process restart
   - `__bg_cleanup` -- Removes forensic traces

4. **Zombie Object Pattern**: 147 `T_ZOMBIE` objects were found adjacent
   to the hidden objects, suggesting the attacker's cleanup routine was
   partially removing traces but leaving zombie residue.

### String Evidence

Strings extracted from the hidden objects' instance variables:

- DNS tunneling domain: `data.ns1.example-analytics.net`
- Exfiltration encoding: XOR with key `0x5A` followed by Base32
- Cron-like schedule string: `*/5 * * * *` (every 5 minutes)
- Persistence file: `/usr/lib/ruby/vendor_ruby/json/ext/generator.rb`
  (disguised as a legitimate Ruby stdlib file)

### IOC Scan Results

- **YARA**: 3 rules matched (objectspace_manipulation, ffi_suspicious_call,
  method_table_injection)
- **Heuristic**: 8 hits for `objectspace_manipulation`, `define_method_injection`,
  and `process_manipulation` patterns
- **Hidden Objects**: 10 objects found outside normal heap (7 classes, 3 modules)

## Root Cause

The initial access vector was a Sidekiq job that called `YAML.load` on
user-supplied input without sanitization. The attacker crafted a YAML
payload that exploited Ruby's `Psych` YAML parser to instantiate an
arbitrary class with `instance_variable_set` calls that set up the
persistence mechanism.

## Recommendations

1. Replace all `YAML.load` calls with `YAML.safe_load` with explicit
   permitted classes
2. Deploy RubyGuardian's heap scanner in continuous monitoring mode to
   detect objects outside normal heap regions
3. Audit all FFI usage in application dependencies
4. Implement integrity checking on Ruby stdlib files
5. Use memory forensics to verify ObjectSpace consistency periodically

## Evidence Artifacts

- Memory dump: `case_002_sidekiq_worker_8891.dump.gz`
- Hidden object RValue dumps: `hidden_objects_*.bin`
- Method table reconstruction: `method_table_dump.json`
- Reference graph: `ref_graph.dot`
