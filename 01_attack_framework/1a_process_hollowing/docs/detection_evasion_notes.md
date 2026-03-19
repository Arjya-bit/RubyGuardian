# Detection & Evasion Notes — Blue Team Perspective

> This document is written from a **defender's perspective** to help security
> teams understand how to detect process hollowing and what evasion techniques
> attackers may employ.

## 1. Detection Strategies

### 1.1 Sysmon Events

Microsoft Sysmon provides the most granular telemetry for detecting hollowing:

| Event ID | Name                      | Relevance                          |
|----------|---------------------------|------------------------------------|
| 1        | Process Create            | Baseline: log the CREATE_SUSPENDED |
| 8        | CreateRemoteThread        | If thread injection is also used   |
| 10       | Process Access            | Cross-process handle operations    |
| 25       | Process Tampering         | **Primary detection**: image change|

**Sysmon Event 25** (introduced in Sysmon 13.0) specifically detects when a
process image has been replaced after creation. This is the single best
detection for hollowing.

**Sysmon configuration for hollowing detection**:

```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>
    <!-- Process Tampering — detects hollowing -->
    <ProcessTampering onmatch="exclude" />

    <!-- Process Access — cross-process operations -->
    <ProcessAccess onmatch="include">
      <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
      <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
    </ProcessAccess>

    <!-- Process Create with CREATE_SUSPENDED -->
    <ProcessCreate onmatch="include">
      <ParentCommandLine condition="contains">-suspended</ParentCommandLine>
    </ProcessCreate>
  </EventFiltering>
</Sysmon>
```

### 1.2 ETW (Event Tracing for Windows)

ETW providers that detect hollowing:

| Provider                         | Events                              |
|----------------------------------|-------------------------------------|
| Microsoft-Windows-Kernel-Process | Process/thread creation             |
| Microsoft-Windows-Kernel-Memory  | VirtualAlloc cross-process          |
| Microsoft-Windows-Threat-Intel   | NtUnmapViewOfSection, NtSetContext  |

The **Threat Intelligence** ETW provider is particularly valuable because it
captures the exact APIs used in hollowing without Sysmon.

### 1.3 Memory Forensics

Memory scanning is the most reliable detection method:

**Indicators of hollowing in memory**:

1. **Unbacked executable pages** — Memory regions with EXECUTE permission that
   are not backed by a file on disk (MEM_PRIVATE instead of MEM_IMAGE)

2. **PE header mismatch** — The PE header in memory does not match the PE
   header of the file on disk that the process was created from

3. **VAD (Virtual Address Descriptor) anomalies** — The VAD tree shows
   sections mapped at unexpected addresses or with unexpected protections

4. **PEB.ImageBaseAddress mismatch** — The PEB points to an image that
   differs from the file path in the PEB's process parameters

**Tools for memory-based detection**:
- pe-sieve (hasherezade) — Scans for replaced PE images
- Moneta — Detects unbacked executable memory
- Volatility — Full memory forensics framework

### 1.4 Behavioral Detection

Pattern-based detection rules:

```
RULE: Process Hollowing Sequence
  WHEN process.created WITH flags CONTAINS CREATE_SUSPENDED
  AND  NtUnmapViewOfSection called on SAME process
  AND  VirtualAllocEx called on SAME process
  AND  WriteProcessMemory called on SAME process
  AND  SetThreadContext called on SAME process
  AND  ResumeThread called on SAME process
  WITHIN 5 seconds
  THEN alert("Process Hollowing Detected")
```

### 1.5 Linux Detection

On Linux, detection relies on:

| Source                     | Indicator                              |
|----------------------------|----------------------------------------|
| `/proc/pid/maps`           | RWX regions not backed by files        |
| `audit.log`                | ptrace attach events                   |
| eBPF tracepoints           | `sys_enter_ptrace`, `sys_enter_mmap`   |
| `/proc/pid/exe` → readlink | Mismatch with expected executable      |
| `/proc/pid/status`         | TracerPid != 0 (being traced)          |

**Auditd rule for ptrace monitoring**:

```
-a always,exit -F arch=b64 -S ptrace -k process_injection
-a always,exit -F arch=b64 -S process_vm_writev -k process_injection
```

## 2. Evasion Techniques (Attacker Perspective)

Understanding evasion helps defenders build more robust detections.

### 2.1 API Unhooking

Many EDRs hook API functions by patching the first bytes of the function in
ntdll.dll. Attackers can:

1. **Load a fresh ntdll.dll** from disk and use the clean copy
2. **Direct syscalls** — Skip ntdll.dll entirely and use `syscall` instruction
3. **Patch the hooks back** — Read ntdll from disk, compare, restore original

**Detection counter**: Monitor for file reads of system DLLs, or use
kernel-level (ETW Threat-Intel) monitoring that cannot be unhooked from
user-mode.

### 2.2 PPID Spoofing

Attackers can set an arbitrary parent process ID to make the hollowed process
appear as a child of a legitimate process:

```
STARTUPINFOEX with PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
```

**Detection counter**: Cross-reference ETW process creation events (which show
the real parent) with the process tree.

### 2.3 Transacted Hollowing (Process Doppelganging)

A more advanced variant using NTFS transactions:

1. Create NTFS transaction
2. Write payload to a transacted file
3. Create section from the transacted file
4. Rollback transaction (file disappears from disk)
5. Create process from the in-memory section

**Detection counter**: Monitor `NtCreateTransaction` + `NtCreateSection`
sequences, or use Sysmon Event 25.

### 2.4 Phantom/Herpaderp Variants

- **Process Herpaderping** — Modify the on-disk file after section creation
  but before process creation callbacks fire
- **Process Ghosting** — Delete the file while it has a delete-pending state

**Detection counter**: Sysmon 13.x+ Event 25 catches all these variants.

### 2.5 Timing and Anti-Analysis

See `anti_analysis.rb` for implementation details:

- **Sleep-based sandbox evasion** — Delay execution to outlast sandbox analysis
- **Accelerated time detection** — Detect if sleep was fast-forwarded
- **Hardware fingerprinting** — Check CPU count, RAM, disk size
- **Debugger detection** — `IsDebuggerPresent`, hardware breakpoint checks

## 3. Detection Engineering Recommendations

### 3.1 High-Confidence Rules

| Rule                                              | False Positive Rate |
|---------------------------------------------------|---------------------|
| Sysmon Event 25 (ProcessTampering)                | Very Low            |
| Unbacked RWX memory in system processes           | Low                 |
| NtUnmapViewOfSection on a newly created process   | Low                 |
| CREATE_SUSPENDED → WriteProcessMemory → Resume    | Medium              |

### 3.2 YARA Rules for Memory Scanning

```yara
rule ProcessHollowing_Indicator {
    meta:
        description = "Detects common process hollowing artifacts in memory"
        author = "RubyGuardian"
        reference = "T1055.012"

    strings:
        // PE header at unexpected location (not image base)
        $mz = { 4D 5A }
        // Common hollowing tool strings
        $s1 = "NtUnmapViewOfSection" ascii
        $s2 = "ZwUnmapViewOfSection" ascii
        $s3 = "VirtualAllocEx" ascii

    condition:
        $mz at 0 and any of ($s*)
}
```

### 3.3 Sigma Rules

```yaml
title: Process Hollowing via CREATE_SUSPENDED and Memory Write
id: 4ae1f1b0-1a2b-3c4d-5e6f-7a8b9c0d1e2f
status: experimental
description: Detects the creation of a suspended process followed by memory manipulation
logsource:
    category: process_access
    product: windows
detection:
    selection:
        GrantedAccess|contains:
            - '0x1FFFFF'
            - '0x1F0FFF'
        CallTrace|contains:
            - 'ntdll.dll'
    condition: selection
level: high
tags:
    - attack.defense_evasion
    - attack.t1055.012
```

## 4. Recommended Defensive Stack

| Layer         | Tool                  | Coverage                       |
|---------------|-----------------------|--------------------------------|
| Kernel        | ETW Threat-Intel      | Syscall-level monitoring       |
| User-mode     | Sysmon                | Process + memory events        |
| Network       | Zeek/Suricata         | C2 communication detection     |
| Memory        | pe-sieve / Moneta     | In-memory artifact scanning    |
| SIEM          | Elastic / Splunk      | Correlation and alerting       |
| EDR           | Various               | Real-time behavioral detection |

## References

- [Sysmon Event 25 Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [pe-sieve](https://github.com/hasherezade/pe-sieve)
- [Elastic Process Injection Detection](https://www.elastic.co/guide/en/security/current/process-injection.html)
