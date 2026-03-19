# Phase 1d - ObjectSpace Persistence Evasion

## Educational Security Research Module

> **DISCLAIMER**: This module is strictly for educational and authorized security
> research purposes. The techniques demonstrated here illustrate how attackers
> may persist malicious code in Ruby process memory using ObjectSpace. Understanding
> these techniques is essential for building effective detection and forensic tools.

## Overview

Ruby's `ObjectSpace` module provides introspection into every live object in the
Ruby VM heap. This module explores how an attacker who has achieved code execution
in a Ruby process (e.g., via deserialization, eval injection, or dependency
confusion) can persist payloads in memory without touching disk.

### Key Concepts

1. **ObjectSpace Injection** - Inserting objects into the Ruby heap that survive
   between requests in long-running processes (Rails, Puma, Sidekiq).
2. **Heap Hiding** - Attaching payloads to legitimate framework objects so they
   appear as normal application data.
3. **GC Anchoring** - Preventing the garbage collector from reclaiming payload
   objects by maintaining strong references.
4. **Ghost Classes** - Creating anonymous classes/modules that have no traceable
   source file location.
5. **Method Patching** - Monkey-patching existing methods to execute payload code
   on every invocation.
6. **Callback Installation** - Leveraging Rails lifecycle callbacks to re-trigger
   payloads.
7. **Memory Cloaking** - Hiding objects from `ObjectSpace.each_object` enumeration.

## Directory Structure

```
1d_objectspace_persistence/
├── README.md
├── docs/
│   ├── ruby_vm_internals.md
│   ├── objectspace_api_reference.md
│   ├── rails_memory_model.md
│   ├── garbage_collector_evasion.md
│   └── forensic_countermeasures.md
├── lib/
│   ├── objectspace_injector.rb
│   ├── heap_hider.rb
│   ├── gc_anchor.rb
│   ├── ghost_class.rb
│   ├── method_patcher.rb
│   ├── callback_installer.rb
│   └── memory_cloaker.rb
├── target_apps/
│   ├── vulnerable_rails_app/
│   └── vulnerable_sinatra_app/
├── specs/
│   ├── objectspace_injector_spec.rb
│   ├── heap_hider_spec.rb
│   ├── gc_anchor_spec.rb
│   ├── ghost_class_spec.rb
│   └── integration/
│       ├── rails_injection_spec.rb
│       └── persistence_survival_spec.rb
└── scripts/
    ├── inject_into_rails.rb
    ├── enumerate_hidden_objects.rb
    ├── dump_objectspace.rb
    └── gc_stress_test.rb
```

## Quick Start

```bash
# 1. Start the vulnerable Rails target
cd target_apps/vulnerable_rails_app
docker-compose up -d

# 2. Run the injection script
cd ../../scripts
ruby inject_into_rails.rb --target http://localhost:3000

# 3. Verify persistence survives GC
ruby gc_stress_test.rb --target http://localhost:3000

# 4. Enumerate hidden objects (forensic perspective)
ruby enumerate_hidden_objects.rb --target http://localhost:3000

# 5. Run the test suite
cd ..
bundle exec rspec specs/
```

## Detection Guidance

Defenders should focus on:

- Periodic `ObjectSpace.each_object` audits comparing against a known baseline
- Monitoring for anonymous classes/modules (`Class#name` returning `nil`)
- Tracking `TracePoint` events for method redefinitions
- Watching for objects with no valid `source_location`
- Memory growth analysis between GC cycles
- Using `ObjectSpace.dump_all` to create heap snapshots for offline analysis

## References

- [Ruby ObjectSpace Documentation](https://ruby-doc.org/stdlib/libdoc/objspace/rdoc/ObjectSpace.html)
- [Ruby Under a Microscope - Pat Shaughnessy](https://patshaughnessy.net/ruby-under-a-microscope)
- [Ruby Hacking Guide](https://ruby-hacking-guide.github.io/)
- [GC Compaction in Ruby 2.7+](https://bugs.ruby-lang.org/issues/15626)
