# RubyGuardian Phase 1a — Process Hollowing Module

> **AUTHORIZED SECURITY RESEARCH ONLY**
> All payloads in this module are benign (calculator launch, `id` command).
> This code is intended for educational purposes and authorized red-team engagements.

## Overview

Process hollowing (aka RunPE) is an advanced code injection technique in which a
legitimate process is created in a **suspended state**, its original executable
image is **unmapped** from memory, and a **new payload** is written into the
resulting cavity. When the thread is resumed, the operating system executes the
injected code under the identity of the hollowed process.

This module implements the technique end-to-end in **Ruby** using **FFI**
(Foreign Function Interface) bindings to native OS APIs, demonstrating that
high-level languages can perform low-level process manipulation traditionally
associated with C/C++.

## MITRE ATT&CK Mapping

| Field              | Value                                              |
|--------------------|----------------------------------------------------|
| **Technique**      | T1055.012 — Process Injection: Process Hollowing    |
| **Tactic**         | Defense Evasion, Privilege Escalation               |
| **Platforms**      | Windows, Linux (via ptrace-based variant)           |
| **Permissions**    | User (same-privilege), Administrator (cross-session)|
| **Data Sources**   | Process monitoring, API monitoring, File monitoring |
| **Detection**      | Sysmon Event 8 (CreateRemoteThread), hollowed image |

### Sub-technique Detail

T1055.012 is a sub-technique of T1055 (Process Injection). The key differentiator
from other injection methods is that the **entire image** is replaced rather than
injecting a single thread or DLL. This makes the hollowed process appear
legitimate in task managers and process listings because the PEB
(Process Environment Block) still references the original executable path.

## Attack Flow

```
1. CreateProcess(SUSPENDED)     — spawn target (e.g., svchost.exe)
2. NtUnmapViewOfSection         — remove original PE image
3. VirtualAllocEx               — allocate memory at preferred base
4. WriteProcessMemory           — write PE headers + sections
5. SetThreadContext             — point EIP/RIP to new entry point
6. ResumeThread                 — execute injected code
```

## Module Structure

```
1a_process_hollowing/
├── README.md                          # This file
├── docs/
│   ├── process_hollowing_theory.md    # Deep-dive theory
│   ├── ruby_ffi_internals.md          # FFI architecture
│   ├── windows_api_reference.md       # Win32/NT API docs
│   ├── linux_syscall_reference.md     # Linux ptrace/mmap docs
│   └── detection_evasion_notes.md     # Blue-team perspective
├── lib/
│   ├── hollower.rb                    # Main orchestrator
│   ├── ffi_bindings/
│   │   ├── windows_api.rb             # kernel32 + ntdll bindings
│   │   ├── linux_syscalls.rb          # libc + ptrace bindings
│   │   └── common_types.rb            # Shared type definitions
│   ├── memory_manager.rb              # Memory allocation engine
│   ├── process_spawner.rb             # Suspended process creation
│   ├── section_mapper.rb              # PE/ELF section mapping
│   ├── thread_hijacker.rb             # Thread context manipulation
│   ├── payload_injector.rb            # Shellcode writer
│   └── anti_analysis.rb              # Anti-debug & anti-VM
├── payloads/
│   ├── README.md                      # Payload overview
│   ├── shellcode/
│   │   └── README.md                  # Shellcode descriptions (no binaries)
│   └── generators/
│       ├── shellcode_generator.rb     # Generate benign shellcode
│       ├── encoder.rb                 # XOR / AES / polymorphic
│       └── stager.rb                  # Multi-stage delivery
├── specs/
│   ├── hollower_spec.rb               # Core engine tests
│   ├── ffi_bindings_spec.rb           # FFI binding tests
│   ├── memory_manager_spec.rb         # Memory management tests
│   └── integration/
│       ├── hollow_notepad_spec.rb     # Windows integration test
│       └── hollow_sleep_spec.rb       # Linux integration test
└── scripts/
    ├── run_hollow_demo.rb             # End-to-end demo
    ├── generate_sysmon_events.rb      # Telemetry generation
    └── cleanup.rb                     # Environment cleanup
```

## Quick Start

```bash
# Install dependencies
gem install ffi
gem install rspec

# Run the demo (benign payload only)
ruby scripts/run_hollow_demo.rb --target notepad.exe --payload calc

# Run tests
rspec specs/

# Generate detection telemetry
ruby scripts/generate_sysmon_events.rb
```

## Requirements

- Ruby >= 3.0
- `ffi` gem >= 1.15
- Windows 10/11 or Linux 5.x+ (for ptrace variant)
- Administrator/root for cross-process operations

## Legal Disclaimer

This module is provided for **authorized security research and education only**.
Unauthorized use of process injection techniques against systems you do not own
or have explicit permission to test is illegal under the CFAA (18 U.S.C. § 1030)
and equivalent international laws. The authors accept no liability for misuse.

## References

- [MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)
- [Elastic Security: Process Hollowing](https://www.elastic.co/blog/process-hollowing-and-portable-executable-relocations)
- [hasherezade — Process Hollowing explained](https://github.com/hasherezade/libpeconv)
- Leitch, J. (2013). "Process Hollowing"
