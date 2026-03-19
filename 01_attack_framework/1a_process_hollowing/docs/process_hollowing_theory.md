# Process Hollowing — Theory Deep Dive

## 1. Definition

Process hollowing is a code injection technique where an attacker:

1. Creates a legitimate process in a **suspended** state
2. **Unmaps** (hollows out) the original executable image from memory
3. **Writes** a malicious PE/ELF image into the freed address space
4. **Resumes** the process, causing it to execute the injected code

The technique is also known as **RunPE** in the malware development community.

## 2. Historical Context

Process hollowing has been used in the wild since at least 2011 and gained
prominence through malware families such as:

- **Dridex** — Banking trojan using hollowed svchost.exe
- **Osiris** — Credential stealer hollowing explorer.exe
- **FormBook** — Information stealer with multiple hollowing targets
- **DarkComet** — RAT using RunPE for persistence

The technique predates many modern EDR solutions, which is why it remains
effective against systems without memory-scanning capabilities.

## 3. Why Process Hollowing Works

### 3.1 Process Identity Deception

When a process is hollowed, the following artifacts remain unchanged:

| Artifact                      | Source                    | Spoofed? |
|-------------------------------|---------------------------|----------|
| Process name in Task Manager  | PEB → ImageBaseAddress    | Yes      |
| Command line arguments        | PEB → ProcessParameters   | Yes      |
| Parent process ID             | Kernel EPROCESS structure | Yes      |
| Digital signature on disk     | Filesystem                | Yes      |
| Loaded modules list           | PEB → Ldr                | Partial  |

The key insight is that **process metadata is set at creation time** and is not
re-validated when the image in memory changes.

### 3.2 Address Space Layout

A typical Windows process address space after hollowing:

```
0x00000000 ┌──────────────────────┐
           │   NULL page guard    │
0x00010000 ├──────────────────────┤
           │   PEB (unchanged)    │  ← Still references original EXE
0x00400000 ├──────────────────────┤
           │   INJECTED PE IMAGE  │  ← Replaced content
           │   .text (code)       │
           │   .rdata (read-only) │
           │   .data (globals)    │
           │   .rsrc (resources)  │
0x10000000 ├──────────────────────┤
           │   Loaded DLLs        │  ← Legitimate ntdll, kernel32, etc.
0x7FFE0000 ├──────────────────────┤
           │   KUSER_SHARED_DATA  │
0x7FFFFFFF └──────────────────────┘
```

### 3.3 Thread Execution Hijacking

The initial thread of the suspended process never executes any code from the
original image. The Windows loader sets up the thread to begin at
`ntdll!RtlUserThreadStart`, which eventually calls the entry point specified
in the PE header. By modifying the thread context (specifically the `Eax`/`Rcx`
register on x86/x64), we redirect execution to our injected entry point.

## 4. Step-by-Step Technical Walkthrough

### Step 1: Create Suspended Process

```
CreateProcessW(
  lpApplicationName:  "C:\\Windows\\System32\\svchost.exe",
  dwCreationFlags:    CREATE_SUSPENDED (0x4),
  lpProcessInformation: → receives PID + thread handle
)
```

The process is loaded into memory but the main thread is frozen before
`RtlUserThreadStart` runs.

### Step 2: Query Process Information

```
NtQueryInformationProcess(
  ProcessHandle,
  ProcessBasicInformation,  → returns PEB address
)
ReadProcessMemory(PEB + 0x10) → ImageBaseAddress
```

We need the PEB address to find the original image base, which tells us
where to unmap.

### Step 3: Unmap Original Image

```
NtUnmapViewOfSection(
  ProcessHandle,
  ImageBaseAddress    ← address from Step 2
)
```

This removes the entire original PE image from the process address space.
The memory region becomes free.

### Step 4: Allocate New Memory

```
VirtualAllocEx(
  ProcessHandle,
  lpAddress:    PreferredBase (from injected PE),
  dwSize:       SizeOfImage,
  flAllocationType: MEM_COMMIT | MEM_RESERVE,
  flProtect:    PAGE_EXECUTE_READWRITE
)
```

We allocate at the **preferred base** of our payload PE to avoid
relocation issues. If the base is occupied, we must apply relocations.

### Step 5: Write PE Sections

```
# Write headers
WriteProcessMemory(ProcessHandle, BaseAddress, PEHeaders, SizeOfHeaders)

# Write each section
for section in PE.sections:
  WriteProcessMemory(
    ProcessHandle,
    BaseAddress + section.VirtualAddress,
    section.RawData,
    section.SizeOfRawData
  )
```

### Step 6: Fix Thread Context

```
ctx = GetThreadContext(ThreadHandle)
ctx.Eax = BaseAddress + AddressOfEntryPoint   # x86
# OR
ctx.Rcx = BaseAddress + AddressOfEntryPoint   # x64
SetThreadContext(ThreadHandle, ctx)

# Also update PEB.ImageBaseAddress
WriteProcessMemory(ProcessHandle, PEB+0x10, &BaseAddress, sizeof(PVOID))
```

### Step 7: Resume Execution

```
ResumeThread(ThreadHandle)
```

The thread wakes up and begins executing at our injected entry point.

## 5. Linux Variant (ptrace-based)

On Linux, the equivalent technique uses `ptrace`:

1. `fork()` + `execve()` a benign binary (e.g., `/usr/bin/sleep`)
2. `ptrace(PTRACE_ATTACH, pid)` — attach to the child
3. `process_vm_writev()` or `ptrace(PTRACE_POKETEXT)` — write shellcode
4. Modify `RIP` via `ptrace(PTRACE_SETREGS)` — redirect execution
5. `ptrace(PTRACE_DETACH)` — let the process run

The Linux variant is less "clean" because there is no direct equivalent
of `NtUnmapViewOfSection`. Instead, we overwrite the `.text` section
in-place using `process_vm_writev` (requires `CAP_SYS_PTRACE` or same UID).

## 6. Limitations and Failure Modes

| Issue                           | Cause                          | Mitigation            |
|---------------------------------|--------------------------------|-----------------------|
| Base address conflict           | ASLR randomizes image base     | Apply relocations     |
| DEP enforcement                 | W^X policy prevents RWX pages  | Use proper protections|
| CFG (Control Flow Guard)        | Indirect call validation       | Clear CFG bitmap      |
| CIG (Code Integrity Guard)      | Only signed images allowed     | Not bypassable easily |
| Process creation callbacks      | Kernel callbacks fire on create| Use existing process  |

## 7. Detection Strategies

See `detection_evasion_notes.md` for a comprehensive blue-team perspective.

Key indicators:

- **Sysmon Event ID 25** — Process image change (tamper)
- Memory regions with `PAGE_EXECUTE_READWRITE` protection
- Discrepancy between on-disk image and in-memory image
- Unbacked executable memory regions
- Thread start address outside known modules

## References

- Leitch, J. (2013). "Process Hollowing"
- [hasherezade — PE-sieve](https://github.com/hasherezade/pe-sieve)
- [MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)
