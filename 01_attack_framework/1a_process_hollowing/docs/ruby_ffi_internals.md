# Ruby FFI Internals — Architecture and Usage

## 1. What is FFI?

FFI (Foreign Function Interface) is a mechanism that allows Ruby code to call
functions defined in shared libraries (DLLs on Windows, `.so` on Linux) without
writing a C extension. The `ffi` gem provides a pure-Ruby DSL for defining
bindings to native functions.

For process hollowing, FFI is essential because we need direct access to:
- Windows API (kernel32.dll, ntdll.dll)
- Linux syscalls via libc (ptrace, mmap, process_vm_writev)

## 2. FFI Architecture

```
┌─────────────────────────────────────────┐
│           Ruby Application              │
│  (hollower.rb, memory_manager.rb, ...)  │
├─────────────────────────────────────────┤
│           FFI Gem Layer                 │
│  • Type mapping (Ruby ↔ C)             │
│  • Function resolution (dlsym)          │
│  • Memory management (pointers)         │
│  • Callback support                     │
├─────────────────────────────────────────┤
│         libffi (C library)              │
│  • Calling convention handling          │
│  • Stack frame construction             │
│  • Architecture-specific ABI            │
├─────────────────────────────────────────┤
│        Operating System                 │
│  • kernel32.dll / ntdll.dll (Windows)   │
│  • libc.so.6 / libpthread.so (Linux)   │
└─────────────────────────────────────────┘
```

## 3. Core FFI Concepts

### 3.1 Attaching to Libraries

```ruby
require 'ffi'

module Kernel32
  extend FFI::Library

  # On Windows, load kernel32.dll
  ffi_lib 'kernel32'

  # Declare function signatures
  attach_function :CreateProcessW, [
    :pointer,   # lpApplicationName
    :pointer,   # lpCommandLine
    :pointer,   # lpProcessAttributes
    :pointer,   # lpThreadAttributes
    :bool,      # bInheritHandles
    :uint32,    # dwCreationFlags
    :pointer,   # lpEnvironment
    :pointer,   # lpCurrentDirectory
    :pointer,   # lpStartupInfo
    :pointer    # lpProcessInformation
  ], :bool
end
```

### 3.2 FFI Type Mapping

| FFI Type      | C Equivalent    | Ruby Equivalent | Size    |
|---------------|-----------------|-----------------|---------|
| `:int8`       | `int8_t`        | Integer         | 1 byte  |
| `:uint8`      | `uint8_t`       | Integer         | 1 byte  |
| `:int16`      | `int16_t`       | Integer         | 2 bytes |
| `:uint16`     | `uint16_t`      | Integer         | 2 bytes |
| `:int32`      | `int32_t`       | Integer         | 4 bytes |
| `:uint32`     | `uint32_t`      | Integer         | 4 bytes |
| `:int64`      | `int64_t`       | Integer         | 8 bytes |
| `:uint64`     | `uint64_t`      | Integer         | 8 bytes |
| `:float`      | `float`         | Float           | 4 bytes |
| `:double`     | `double`        | Float           | 8 bytes |
| `:pointer`    | `void *`        | FFI::Pointer    | 4/8 bytes|
| `:string`     | `char *`        | String          | varies  |
| `:bool`       | `BOOL` (Win32)  | true/false      | 4 bytes |

### 3.3 Structs

FFI structs map directly to C structures, preserving memory layout:

```ruby
class PROCESS_INFORMATION < FFI::Struct
  layout :hProcess,    :pointer,   # HANDLE
         :hThread,     :pointer,   # HANDLE
         :dwProcessId, :uint32,    # DWORD
         :dwThreadId,  :uint32     # DWORD
end
```

Struct instances can be passed as pointers to native functions, and fields
can be read/written using hash-style access (`pi[:hProcess]`).

### 3.4 Memory Pointers

```ruby
# Allocate a buffer for WriteProcessMemory
buffer = FFI::MemoryPointer.new(:uint8, 4096)

# Write data into the buffer
buffer.put_bytes(0, shellcode_bytes)

# Read data back
data = buffer.get_bytes(0, 4096)

# Get the native address (for passing to APIs)
address = buffer.address  # => Integer (native pointer value)
```

### 3.5 Callbacks

Some Windows APIs require callback functions (e.g., EnumProcessModules):

```ruby
# Define callback type
callback :enum_proc, [:pointer, :long], :bool

# Use in function attachment
attach_function :EnumWindows, [:enum_proc, :long], :bool

# Create a callback instance
my_callback = FFI::Function.new(:bool, [:pointer, :long]) do |hwnd, lparam|
  # Process each window handle
  true  # Continue enumeration
end
```

## 4. FFI Performance Considerations

### 4.1 Call Overhead

Each FFI call incurs approximately 2-5 microseconds of overhead compared to a
direct C call. For process hollowing, this is negligible because:

- API calls themselves take milliseconds (kernel transitions)
- We make relatively few calls (< 20 for a complete hollow)
- The bottleneck is I/O, not function call overhead

### 4.2 Memory Safety

FFI bypasses Ruby's garbage collector for native memory. Key rules:

1. **Always free manually allocated memory** — Use `FFI::MemoryPointer`
   (auto-freed) instead of raw `FFI::Pointer.new` when possible
2. **Pin references** — Keep Ruby references to callback objects alive
   to prevent GC from collecting them while native code holds a pointer
3. **Buffer overflows** — FFI does not bounds-check pointer writes;
   writing past allocated size will corrupt memory

### 4.3 Thread Safety

Ruby's GVL (Global VM Lock) is released during FFI calls by default, meaning:

- Other Ruby threads can run while a blocking FFI call executes
- Native code must not call back into Ruby without re-acquiring the GVL
- Use `blocking: true` on `attach_function` for long-running calls

```ruby
attach_function :WaitForSingleObject,
  [:pointer, :uint32], :uint32,
  blocking: true  # Release GVL during wait
```

## 5. FFI in This Module

Our module organizes FFI bindings into three files:

| File                      | Purpose                        |
|---------------------------|--------------------------------|
| `common_types.rb`         | Shared struct and type defs    |
| `windows_api.rb`          | kernel32 + ntdll bindings      |
| `linux_syscalls.rb`       | libc + ptrace bindings         |

The main `hollower.rb` engine auto-detects the platform and loads the
appropriate bindings at runtime.

## References

- [ffi gem documentation](https://github.com/ffi/ffi/wiki)
- [libffi project](https://sourceware.org/libffi/)
- [Ruby FFI Memory Management](https://github.com/ffi/ffi/wiki/Pointers)
