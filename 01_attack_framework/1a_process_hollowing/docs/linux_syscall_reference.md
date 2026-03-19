# Linux Syscall Reference — Process Hollowing via ptrace

## Overview

Linux does not have a direct equivalent to Windows' `NtUnmapViewOfSection`.
Instead, process hollowing on Linux uses a combination of:

- **ptrace** — Process tracing (attach, read/write memory, set registers)
- **process_vm_writev** — High-performance cross-process memory writes
- **mmap/munmap** — Memory mapping (within the traced process)
- **/proc/pid/mem** — Direct memory access via procfs

## 1. ptrace System Call

The `ptrace` syscall is the primary mechanism for process manipulation on Linux.

```c
long ptrace(
  enum __ptrace_request request,  // Operation to perform
  pid_t pid,                       // Target process ID
  void *addr,                      // Address (request-specific)
  void *data                       // Data (request-specific)
);
```

### ptrace Requests Used in Hollowing

#### PTRACE_ATTACH (16)

Attach to a running process, sending it SIGSTOP.

```c
ptrace(PTRACE_ATTACH, target_pid, NULL, NULL);
waitpid(target_pid, &status, 0);  // Wait for SIGSTOP
```

- Requires same UID or `CAP_SYS_PTRACE`
- Yama LSM may restrict to parent-child only (see `/proc/sys/kernel/yama/ptrace_scope`)

**Yama ptrace_scope values**:
| Value | Meaning                                    |
|-------|--------------------------------------------|
| 0     | Classic ptrace — any process can attach    |
| 1     | Restricted — only direct parent can attach |
| 2     | Admin-only — CAP_SYS_PTRACE required      |
| 3     | Disabled — no ptrace attach allowed        |

#### PTRACE_SEIZE (0x4206)

Modern alternative to PTRACE_ATTACH. Does not send SIGSTOP automatically.

```c
ptrace(PTRACE_SEIZE, target_pid, NULL, PTRACE_O_TRACESYSGOOD);
ptrace(PTRACE_INTERRUPT, target_pid, NULL, NULL);
waitpid(target_pid, &status, 0);
```

#### PTRACE_PEEKTEXT / PTRACE_POKETEXT (1 / 4)

Read or write a word (8 bytes on x86_64) at the given address.

```c
// Read
long word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);

// Write
ptrace(PTRACE_POKETEXT, pid, addr, new_word);
```

**Limitations**: Only operates on word-sized chunks. For bulk writes,
`process_vm_writev` is significantly faster.

#### PTRACE_GETREGS / PTRACE_SETREGS (12 / 13)

Read or write all general-purpose registers.

```c
struct user_regs_struct regs;
ptrace(PTRACE_GETREGS, pid, NULL, &regs);

// Modify instruction pointer
regs.rip = new_entry_point;
ptrace(PTRACE_SETREGS, pid, NULL, &regs);
```

**user_regs_struct layout (x86_64)**:

```c
struct user_regs_struct {
  unsigned long long r15, r14, r13, r12;
  unsigned long long rbp, rbx;
  unsigned long long r11, r10, r9, r8;
  unsigned long long rax, rcx, rdx, rsi, rdi;
  unsigned long long orig_rax;
  unsigned long long rip;          // *** Instruction pointer ***
  unsigned long long cs, eflags;
  unsigned long long rsp, ss;      // Stack pointer
  unsigned long long fs_base, gs_base;
  unsigned long long ds, es, fs, gs;
};
```

#### PTRACE_DETACH (17)

Detach from the traced process, allowing it to continue.

```c
ptrace(PTRACE_DETACH, pid, NULL, NULL);
```

The process resumes execution at the current `RIP` value.

## 2. process_vm_writev / process_vm_readv

High-performance cross-process memory I/O (Linux 3.2+).

```c
#include <sys/uio.h>

ssize_t process_vm_writev(
  pid_t pid,
  const struct iovec *local_iov,   // Source buffers (our process)
  unsigned long liovcnt,            // Number of source iovecs
  const struct iovec *remote_iov,  // Destination buffers (target)
  unsigned long riovcnt,            // Number of dest iovecs
  unsigned long flags               // Must be 0
);
```

**Advantages over PTRACE_POKETEXT**:
- Can write arbitrary byte counts (not word-aligned)
- Single syscall for large transfers
- Significantly faster for bulk writes (10-100x)

**Requirements**: Same as ptrace — same UID or `CAP_SYS_PTRACE`.

## 3. /proc/pid/mem

Direct memory access through the proc filesystem.

```ruby
# Ruby example: write shellcode to target process
File.open("/proc/#{pid}/mem", "r+b") do |mem|
  mem.seek(target_address)
  mem.write(shellcode)
end
```

**Requirements**:
- Must be ptracing the target process first (or same process)
- Bypasses page protection checks when ptracing
- Requires `PTRACE_ATTACH` or `PTRACE_SEIZE` first

## 4. mmap Injection via ptrace Syscall Injection

To allocate new memory in the target, we can inject a `mmap` syscall:

```
1. Save current register state (PTRACE_GETREGS)
2. Save instruction bytes at current RIP (PTRACE_PEEKTEXT)
3. Write a `syscall` instruction (0x0F 0x05) at RIP
4. Set registers for mmap:
   rax = 9 (SYS_mmap)
   rdi = 0 (addr - let kernel choose)
   rsi = size
   rdx = PROT_READ | PROT_WRITE | PROT_EXEC (0x7)
   r10 = MAP_PRIVATE | MAP_ANONYMOUS (0x22)
   r8  = -1 (fd)
   r9  = 0 (offset)
5. Single-step (PTRACE_SINGLESTEP)
6. Read rax — contains the new mapping address
7. Restore original registers and instruction bytes
```

This is the Linux equivalent of `VirtualAllocEx`.

## 5. ELF Structure for Section Mapping

When hollowing on Linux, we work with ELF (Executable and Linkable Format):

```
ELF Header (64 bytes on x86_64)
├── e_entry      — Entry point virtual address
├── e_phoff      — Program header table offset
├── e_phnum      — Number of program headers
Program Headers (LOAD segments)
├── p_type       — PT_LOAD (1)
├── p_offset     — File offset
├── p_vaddr      — Virtual address
├── p_memsz      — Size in memory
├── p_filesz     — Size in file
├── p_flags      — PF_X | PF_W | PF_R
Sections
├── .text        — Executable code
├── .rodata      — Read-only data
├── .data        — Initialized data
├── .bss         — Uninitialized data (zero-filled)
└── .dynamic     — Dynamic linking info
```

## 6. Key Differences from Windows Hollowing

| Aspect                  | Windows                    | Linux                      |
|-------------------------|----------------------------|----------------------------|
| Suspend at creation     | CREATE_SUSPENDED flag      | fork() + SIGSTOP           |
| Unmap original image    | NtUnmapViewOfSection       | munmap via syscall inject  |
| Allocate memory         | VirtualAllocEx             | mmap via syscall inject    |
| Write payload           | WriteProcessMemory         | process_vm_writev          |
| Set instruction pointer | SetThreadContext            | PTRACE_SETREGS             |
| Resume execution        | ResumeThread               | PTRACE_DETACH              |
| Image format            | PE (Portable Executable)   | ELF                        |
| Security model          | Token-based                | UID + capabilities         |

## 7. Relevant Syscall Numbers (x86_64)

| Syscall           | Number | Purpose                        |
|-------------------|--------|--------------------------------|
| read              | 0      | Read from fd                   |
| write             | 1      | Write to fd                    |
| mmap              | 9      | Map memory                     |
| mprotect          | 10     | Change memory protection       |
| munmap            | 11     | Unmap memory                   |
| ptrace            | 101    | Process trace                  |
| process_vm_readv  | 310    | Cross-process read             |
| process_vm_writev | 311    | Cross-process write            |
| fork              | 57     | Create child process           |
| execve            | 59     | Execute program                |
| kill              | 62     | Send signal                    |
| waitpid           | 61     | Wait for child state change    |

## References

- `man 2 ptrace` — ptrace(2) manual page
- `man 2 process_vm_writev` — process_vm_writev(2) manual page
- [Linux kernel ptrace implementation](https://elixir.bootlin.com/linux/latest/source/kernel/ptrace.c)
- [Yama LSM documentation](https://www.kernel.org/doc/Documentation/admin-guide/LSM/Yama.rst)
