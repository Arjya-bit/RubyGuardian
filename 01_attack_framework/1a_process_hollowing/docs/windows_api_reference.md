# Windows API Reference — Process Hollowing

## Overview

Process hollowing on Windows requires functions from two system libraries:

- **kernel32.dll** — High-level process and memory management
- **ntdll.dll** — Native API (lower-level, less documented)

## 1. kernel32.dll Functions

### CreateProcessW

Creates a new process and its primary thread.

```c
BOOL CreateProcessW(
  LPCWSTR               lpApplicationName,    // Path to executable
  LPWSTR                lpCommandLine,         // Command line string
  LPSECURITY_ATTRIBUTES lpProcessAttributes,   // Process security
  LPSECURITY_ATTRIBUTES lpThreadAttributes,    // Thread security
  BOOL                  bInheritHandles,       // Handle inheritance
  DWORD                 dwCreationFlags,       // CREATE_SUSPENDED = 0x4
  LPVOID                lpEnvironment,         // Environment block
  LPCWSTR               lpCurrentDirectory,    // Working directory
  LPSTARTUPINFOW        lpStartupInfo,         // Startup parameters
  LPPROCESS_INFORMATION lpProcessInformation   // Output: handles + IDs
);
```

**Key flag**: `CREATE_SUSPENDED (0x00000004)` — Creates the process with its
primary thread in a suspended state. The thread does not run until
`ResumeThread` is called.

**Return value**: Non-zero on success, zero on failure. Call `GetLastError()`
for error code.

### VirtualAllocEx

Reserves, commits, or changes the state of memory in a remote process.

```c
LPVOID VirtualAllocEx(
  HANDLE hProcess,          // Target process handle
  LPVOID lpAddress,         // Desired base address (or NULL)
  SIZE_T dwSize,            // Size in bytes
  DWORD  flAllocationType,  // MEM_COMMIT | MEM_RESERVE
  DWORD  flProtect          // PAGE_EXECUTE_READWRITE
);
```

**Allocation types**:
- `MEM_COMMIT (0x1000)` — Allocates physical storage (RAM or pagefile)
- `MEM_RESERVE (0x2000)` — Reserves address space without backing
- `MEM_COMMIT | MEM_RESERVE (0x3000)` — Reserve and commit in one call

**Protection flags**:
- `PAGE_EXECUTE_READWRITE (0x40)` — Full RWX (needed during write phase)
- `PAGE_EXECUTE_READ (0x20)` — Final protection for code sections
- `PAGE_READWRITE (0x04)` — Data sections
- `PAGE_READONLY (0x02)` — Read-only data

### WriteProcessMemory

Writes data to a memory region in a remote process.

```c
BOOL WriteProcessMemory(
  HANDLE  hProcess,                // Target process handle
  LPVOID  lpBaseAddress,           // Destination address in target
  LPCVOID lpBuffer,                // Source buffer in our process
  SIZE_T  nSize,                   // Number of bytes to write
  SIZE_T  *lpNumberOfBytesWritten  // Output: bytes actually written
);
```

**Notes**:
- The target region must be writable (PAGE_READWRITE or PAGE_EXECUTE_READWRITE)
- Crosses process boundary via kernel transition
- Requires PROCESS_VM_WRITE + PROCESS_VM_OPERATION access rights

### ReadProcessMemory

Reads data from a memory region in a remote process.

```c
BOOL ReadProcessMemory(
  HANDLE  hProcess,             // Target process handle
  LPCVOID lpBaseAddress,        // Source address in target
  LPVOID  lpBuffer,             // Destination buffer in our process
  SIZE_T  nSize,                // Number of bytes to read
  SIZE_T  *lpNumberOfBytesRead  // Output: bytes actually read
);
```

### GetThreadContext

Retrieves the context (register state) of a thread.

```c
BOOL GetThreadContext(
  HANDLE    hThread,   // Thread handle
  LPCONTEXT lpContext   // Output: register state
);
```

**CONTEXT structure** (x64, key fields):

```c
typedef struct _CONTEXT {
  DWORD64 Rax, Rcx, Rdx, Rbx;    // General-purpose registers
  DWORD64 Rsp, Rbp, Rsi, Rdi;    // Stack and index registers
  DWORD64 R8, R9, R10, R11;      // Extended registers
  DWORD64 R12, R13, R14, R15;
  DWORD64 Rip;                    // Instruction pointer
  // ... segment registers, flags, debug registers, etc.
  DWORD   ContextFlags;           // Which register groups to get/set
} CONTEXT;
```

**ContextFlags values**:
- `CONTEXT_FULL (0x10000B)` — Control + integer + segments
- `CONTEXT_ALL (0x10001F)` — All register groups

### SetThreadContext

Sets the context (register state) of a suspended thread.

```c
BOOL SetThreadContext(
  HANDLE        hThread,   // Thread handle (must be suspended)
  const CONTEXT *lpContext  // New register state
);
```

**Critical for hollowing**: We modify `Rcx` (x64) or `Eax` (x86) to point
to the entry point of our injected PE image.

### ResumeThread

Decrements the suspend count of a thread. When the count reaches zero,
the thread resumes execution.

```c
DWORD ResumeThread(
  HANDLE hThread   // Thread handle
);
```

**Return value**: Previous suspend count, or `(DWORD)-1` on failure.

### VirtualProtectEx

Changes the protection on a region of memory in a remote process.

```c
BOOL VirtualProtectEx(
  HANDLE hProcess,        // Target process handle
  LPVOID lpAddress,       // Region base address
  SIZE_T dwSize,          // Region size
  DWORD  flNewProtect,    // New protection flags
  PDWORD lpflOldProtect   // Output: previous protection
);
```

Used after writing to change RWX regions to proper section protections.

### CloseHandle

Closes an open kernel object handle.

```c
BOOL CloseHandle(
  HANDLE hObject   // Handle to close
);
```

Always close process and thread handles when done.

## 2. ntdll.dll Functions

### NtUnmapViewOfSection

Unmaps a mapped view of a section from the address space of a process.

```c
NTSTATUS NtUnmapViewOfSection(
  HANDLE ProcessHandle,   // Target process
  PVOID  BaseAddress      // Base address of the section to unmap
);
```

**This is the "hollowing" step** — removes the original PE image from memory.

**Return value**: `STATUS_SUCCESS (0)` on success.

**Note**: This is an undocumented NT API. The function ordinal may change
between Windows versions, but the name has been stable since Windows XP.

### NtQueryInformationProcess

Retrieves information about a process.

```c
NTSTATUS NtQueryInformationProcess(
  HANDLE           ProcessHandle,
  PROCESSINFOCLASS ProcessInformationClass,  // 0 = ProcessBasicInformation
  PVOID            ProcessInformation,       // Output buffer
  ULONG            ProcessInformationLength, // Buffer size
  PULONG           ReturnLength              // Output: actual size
);
```

**PROCESS_BASIC_INFORMATION structure**:

```c
typedef struct _PROCESS_BASIC_INFORMATION {
  PVOID     Reserved1;          // ExitStatus
  PPEB      PebBaseAddress;     // *** PEB address — what we need ***
  PVOID     Reserved2[2];       // AffinityMask, BasePriority
  ULONG_PTR UniqueProcessId;    // PID
  PVOID     Reserved3;          // InheritedFromUniqueProcessId
} PROCESS_BASIC_INFORMATION;
```

From the PEB, we read `ImageBaseAddress` at offset `+0x10` (x64) to find
where the original image is loaded.

### NtReadVirtualMemory / NtWriteVirtualMemory

Lower-level alternatives to ReadProcessMemory / WriteProcessMemory.
Same semantics but bypass some kernel32 wrapper checks.

## 3. Required Process Access Rights

When opening or creating a process for hollowing, we need these access flags:

| Flag                         | Value      | Purpose                    |
|------------------------------|------------|----------------------------|
| PROCESS_CREATE_THREAD        | 0x0002     | Create remote threads      |
| PROCESS_VM_OPERATION         | 0x0008     | VirtualAllocEx/ProtectEx   |
| PROCESS_VM_READ              | 0x0010     | ReadProcessMemory          |
| PROCESS_VM_WRITE             | 0x0020     | WriteProcessMemory         |
| PROCESS_QUERY_INFORMATION    | 0x0400     | NtQueryInformationProcess  |
| PROCESS_ALL_ACCESS           | 0x001FFFFF | All of the above + more    |

`CreateProcessW` with `CREATE_SUSPENDED` returns handles with full access
by default.

## 4. Error Handling

All kernel32 functions return `FALSE` (0) on failure. Use `GetLastError()` to
retrieve the error code:

| Error Code | Name                       | Common Cause                |
|------------|----------------------------|-----------------------------|
| 5          | ERROR_ACCESS_DENIED        | Insufficient privileges     |
| 6          | ERROR_INVALID_HANDLE       | Handle was closed or invalid|
| 87         | ERROR_INVALID_PARAMETER    | Bad argument                |
| 299        | ERROR_PARTIAL_COPY         | ReadProcessMemory partial   |
| 487        | ERROR_INVALID_ADDRESS      | VirtualAllocEx bad address  |
| 998        | ERROR_NOACCESS             | Memory protection violation |

NT APIs return NTSTATUS codes where `>= 0` is success and `< 0` is failure.

## References

- [Microsoft Win32 API Documentation](https://learn.microsoft.com/en-us/windows/win32/api/)
- [NtInternals — Undocumented NT API](http://undocumented.ntinternals.net/)
- [ReactOS source code](https://reactos.org/) — Open-source NT API reference
