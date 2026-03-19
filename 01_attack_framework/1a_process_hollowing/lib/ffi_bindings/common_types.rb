# frozen_string_literal: true

# RubyGuardian Phase 1a — Common FFI Type Definitions
#
# Shared type definitions, constants, and structures used by both
# Windows and Linux FFI bindings. These map native C types to Ruby
# FFI types for cross-platform process hollowing.
#
# EDUCATIONAL PURPOSE ONLY — Authorized security research.

require 'ffi'

module RubyGuardian
  module ProcessHollowing
    module FFIBindings
      # ──────────────────────────────────────────────────────────────
      # Platform Detection
      # ──────────────────────────────────────────────────────────────

      PLATFORM = case RbConfig::CONFIG['host_os']
                 when /mswin|mingw|cygwin/ then :windows
                 when /linux/              then :linux
                 when /darwin/             then :macos
                 else :unknown
                 end

      ARCH = case RbConfig::CONFIG['host_cpu']
             when /x86_64|x64|amd64/ then :x64
             when /i[3-6]86|x86/     then :x86
             when /aarch64|arm64/    then :arm64
             else :unknown
             end

      # ──────────────────────────────────────────────────────────────
      # Windows Constants
      # ──────────────────────────────────────────────────────────────

      module WinConstants
        # Process creation flags
        CREATE_SUSPENDED          = 0x00000004
        CREATE_NO_WINDOW          = 0x08000000
        DETACHED_PROCESS          = 0x00000008
        CREATE_NEW_CONSOLE        = 0x00000010

        # Process access rights
        PROCESS_ALL_ACCESS        = 0x001FFFFF
        PROCESS_CREATE_THREAD     = 0x00000002
        PROCESS_VM_OPERATION      = 0x00000008
        PROCESS_VM_READ           = 0x00000010
        PROCESS_VM_WRITE          = 0x00000020
        PROCESS_QUERY_INFORMATION = 0x00000400

        # Memory allocation types
        MEM_COMMIT                = 0x00001000
        MEM_RESERVE               = 0x00002000
        MEM_RELEASE               = 0x00008000
        MEM_DECOMMIT              = 0x00004000

        # Memory protection flags
        PAGE_NOACCESS             = 0x01
        PAGE_READONLY             = 0x02
        PAGE_READWRITE            = 0x04
        PAGE_WRITECOPY            = 0x08
        PAGE_EXECUTE              = 0x10
        PAGE_EXECUTE_READ         = 0x20
        PAGE_EXECUTE_READWRITE    = 0x40
        PAGE_EXECUTE_WRITECOPY    = 0x80
        PAGE_GUARD                = 0x100

        # Thread context flags (x64)
        CONTEXT_AMD64             = 0x00100000
        CONTEXT_CONTROL           = CONTEXT_AMD64 | 0x01
        CONTEXT_INTEGER           = CONTEXT_AMD64 | 0x02
        CONTEXT_SEGMENTS          = CONTEXT_AMD64 | 0x04
        CONTEXT_FLOATING_POINT    = CONTEXT_AMD64 | 0x08
        CONTEXT_DEBUG_REGISTERS   = CONTEXT_AMD64 | 0x10
        CONTEXT_FULL              = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS
        CONTEXT_ALL               = CONTEXT_FULL | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS

        # Thread context flags (x86)
        CONTEXT_I386              = 0x00010000
        CONTEXT_X86_FULL          = CONTEXT_I386 | 0x07

        # NTSTATUS codes
        STATUS_SUCCESS            = 0x00000000

        # PE format constants
        IMAGE_DOS_SIGNATURE       = 0x5A4D      # "MZ"
        IMAGE_NT_SIGNATURE        = 0x00004550   # "PE\0\0"
        IMAGE_FILE_MACHINE_I386   = 0x014C
        IMAGE_FILE_MACHINE_AMD64  = 0x8664

        # PE section characteristics
        IMAGE_SCN_MEM_EXECUTE     = 0x20000000
        IMAGE_SCN_MEM_READ        = 0x40000000
        IMAGE_SCN_MEM_WRITE       = 0x80000000

        # Map PE section characteristics to memory protection
        SECTION_PROTECTION_MAP = {
          0                                                         => PAGE_NOACCESS,
          IMAGE_SCN_MEM_READ                                        => PAGE_READONLY,
          IMAGE_SCN_MEM_WRITE                                       => PAGE_READWRITE,
          IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE                  => PAGE_READWRITE,
          IMAGE_SCN_MEM_EXECUTE                                     => PAGE_EXECUTE,
          IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ                => PAGE_EXECUTE_READ,
          IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE               => PAGE_EXECUTE_READWRITE,
          IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE => PAGE_EXECUTE_READWRITE
        }.freeze
      end

      # ──────────────────────────────────────────────────────────────
      # Linux Constants
      # ──────────────────────────────────────────────────────────────

      module LinuxConstants
        # ptrace request codes
        PTRACE_TRACEME       = 0
        PTRACE_PEEKTEXT      = 1
        PTRACE_PEEKDATA      = 2
        PTRACE_POKETEXT      = 4
        PTRACE_POKEDATA      = 5
        PTRACE_CONT          = 7
        PTRACE_SINGLESTEP    = 9
        PTRACE_GETREGS       = 12
        PTRACE_SETREGS       = 13
        PTRACE_ATTACH        = 16
        PTRACE_DETACH        = 17
        PTRACE_SEIZE         = 0x4206
        PTRACE_INTERRUPT     = 0x4207

        # mmap protection flags
        PROT_NONE             = 0x0
        PROT_READ             = 0x1
        PROT_WRITE            = 0x2
        PROT_EXEC             = 0x4
        PROT_RWX              = PROT_READ | PROT_WRITE | PROT_EXEC

        # mmap flags
        MAP_SHARED            = 0x01
        MAP_PRIVATE           = 0x02
        MAP_FIXED             = 0x10
        MAP_ANONYMOUS         = 0x20

        # Signals
        SIGSTOP               = 19
        SIGCONT               = 18
        SIGTRAP               = 5

        # Syscall numbers (x86_64)
        SYS_MMAP              = 9
        SYS_MPROTECT          = 10
        SYS_MUNMAP            = 11
        SYS_PTRACE            = 101
        SYS_PROCESS_VM_READV  = 310
        SYS_PROCESS_VM_WRITEV = 311

        # ELF constants
        ELF_MAGIC             = "\x7FELF"
        ET_EXEC               = 2
        ET_DYN                = 3
        PT_LOAD               = 1
        PF_X                  = 0x1
        PF_W                  = 0x2
        PF_R                  = 0x4
      end

      # ──────────────────────────────────────────────────────────────
      # Windows Structures (FFI::Struct)
      # ──────────────────────────────────────────────────────────────

      # STARTUPINFOW — Parameters for CreateProcessW
      class StartupInfo < FFI::Struct
        layout :cb,              :uint32,
               :lpReserved,      :pointer,
               :lpDesktop,       :pointer,
               :lpTitle,         :pointer,
               :dwX,             :uint32,
               :dwY,             :uint32,
               :dwXSize,         :uint32,
               :dwYSize,         :uint32,
               :dwXCountChars,   :uint32,
               :dwYCountChars,   :uint32,
               :dwFillAttribute, :uint32,
               :dwFlags,         :uint32,
               :wShowWindow,     :uint16,
               :cbReserved2,     :uint16,
               :lpReserved2,     :pointer,
               :hStdInput,       :pointer,
               :hStdOutput,      :pointer,
               :hStdError,       :pointer
      end

      # PROCESS_INFORMATION — Output from CreateProcessW
      class ProcessInformation < FFI::Struct
        layout :hProcess,    :pointer,
               :hThread,     :pointer,
               :dwProcessId, :uint32,
               :dwThreadId,  :uint32
      end

      # PROCESS_BASIC_INFORMATION — Output from NtQueryInformationProcess
      class ProcessBasicInformation < FFI::Struct
        layout :ExitStatus,                   :ulong,
               :PebBaseAddress,               :pointer,
               :AffinityMask,                 :pointer,
               :BasePriority,                 :long,
               :UniqueProcessId,              :pointer,
               :InheritedFromUniqueProcessId, :pointer
      end

      # CONTEXT structure for x64 (simplified — key registers only)
      # Full CONTEXT is 1232 bytes; we define the critical fields
      class Context64 < FFI::Struct
        # Note: This is a simplified layout. The real CONTEXT structure has
        # additional fields for FP, SSE, and debug registers. We include
        # padding to maintain correct offsets for the fields we use.
        layout :P1Home,       :uint64,
               :P2Home,       :uint64,
               :P3Home,       :uint64,
               :P4Home,       :uint64,
               :P5Home,       :uint64,
               :P6Home,       :uint64,
               :ContextFlags, :uint32,
               :MxCsr,        :uint32,
               :SegCs,        :uint16,
               :SegDs,        :uint16,
               :SegEs,        :uint16,
               :SegFs,        :uint16,
               :SegGs,        :uint16,
               :SegSs,        :uint16,
               :EFlags,       :uint32,
               :Dr0,          :uint64,
               :Dr1,          :uint64,
               :Dr2,          :uint64,
               :Dr3,          :uint64,
               :Dr6,          :uint64,
               :Dr7,          :uint64,
               :Rax,          :uint64,
               :Rcx,          :uint64,
               :Rdx,          :uint64,
               :Rbx,          :uint64,
               :Rsp,          :uint64,
               :Rbp,          :uint64,
               :Rsi,          :uint64,
               :Rdi,          :uint64,
               :R8,           :uint64,
               :R9,           :uint64,
               :R10,          :uint64,
               :R11,          :uint64,
               :R12,          :uint64,
               :R13,          :uint64,
               :R14,          :uint64,
               :R15,          :uint64,
               :Rip,          :uint64
               # Remaining fields (XMM, FP state) omitted for brevity
      end

      # IMAGE_DOS_HEADER — First structure in a PE file
      class ImageDosHeader < FFI::Struct
        layout :e_magic,    :uint16,   # Must be 0x5A4D ("MZ")
               :e_cblp,     :uint16,
               :e_cp,       :uint16,
               :e_crlc,     :uint16,
               :e_cparhdr,  :uint16,
               :e_minalloc, :uint16,
               :e_maxalloc, :uint16,
               :e_ss,       :uint16,
               :e_sp,       :uint16,
               :e_csum,     :uint16,
               :e_ip,       :uint16,
               :e_cs,       :uint16,
               :e_lfarlc,   :uint16,
               :e_ovno,     :uint16,
               :e_res,      [:uint16, 4],
               :e_oemid,    :uint16,
               :e_oeminfo,  :uint16,
               :e_res2,     [:uint16, 10],
               :e_lfanew,   :int32     # Offset to PE signature
      end

      # IMAGE_FILE_HEADER — COFF header after PE signature
      class ImageFileHeader < FFI::Struct
        layout :Machine,              :uint16,
               :NumberOfSections,     :uint16,
               :TimeDateStamp,        :uint32,
               :PointerToSymbolTable, :uint32,
               :NumberOfSymbols,      :uint32,
               :SizeOfOptionalHeader, :uint16,
               :Characteristics,      :uint16
      end

      # IMAGE_SECTION_HEADER — Describes a PE section
      class ImageSectionHeader < FFI::Struct
        layout :Name,                 [:uint8, 8],
               :VirtualSize,          :uint32,
               :VirtualAddress,       :uint32,
               :SizeOfRawData,        :uint32,
               :PointerToRawData,     :uint32,
               :PointerToRelocations, :uint32,
               :PointerToLinenumbers, :uint32,
               :NumberOfRelocations,  :uint16,
               :NumberOfLinenumbers,  :uint16,
               :Characteristics,      :uint32
      end

      # ──────────────────────────────────────────────────────────────
      # Linux Structures
      # ──────────────────────────────────────────────────────────────

      # user_regs_struct — Register state for ptrace (x86_64)
      class UserRegsStruct < FFI::Struct
        layout :r15,      :uint64,
               :r14,      :uint64,
               :r13,      :uint64,
               :r12,      :uint64,
               :rbp,      :uint64,
               :rbx,      :uint64,
               :r11,      :uint64,
               :r10,      :uint64,
               :r9,       :uint64,
               :r8,       :uint64,
               :rax,      :uint64,
               :rcx,      :uint64,
               :rdx,      :uint64,
               :rsi,      :uint64,
               :rdi,      :uint64,
               :orig_rax, :uint64,
               :rip,      :uint64,
               :cs,       :uint64,
               :eflags,   :uint64,
               :rsp,      :uint64,
               :ss,       :uint64,
               :fs_base,  :uint64,
               :gs_base,  :uint64,
               :ds,       :uint64,
               :es,       :uint64,
               :fs,       :uint64,
               :gs,       :uint64
      end

      # iovec — Scatter/gather I/O vector (for process_vm_writev)
      class Iovec < FFI::Struct
        layout :iov_base, :pointer,
               :iov_len,  :size_t
      end

      # ELF64 Header
      class Elf64Header < FFI::Struct
        layout :e_ident,     [:uint8, 16],
               :e_type,      :uint16,
               :e_machine,   :uint16,
               :e_version,   :uint32,
               :e_entry,     :uint64,
               :e_phoff,     :uint64,
               :e_shoff,     :uint64,
               :e_flags,     :uint32,
               :e_ehsize,    :uint16,
               :e_phentsize, :uint16,
               :e_phnum,     :uint16,
               :e_shentsize, :uint16,
               :e_shnum,     :uint16,
               :e_shstrndx,  :uint16
      end

      # ELF64 Program Header
      class Elf64ProgramHeader < FFI::Struct
        layout :p_type,   :uint32,
               :p_flags,  :uint32,
               :p_offset, :uint64,
               :p_vaddr,  :uint64,
               :p_paddr,  :uint64,
               :p_filesz, :uint64,
               :p_memsz,  :uint64,
               :p_align,  :uint64
      end

      # ──────────────────────────────────────────────────────────────
      # Utility Methods
      # ──────────────────────────────────────────────────────────────

      module TypeUtils
        module_function

        # Convert a Ruby string to a UTF-16LE encoded null-terminated
        # FFI::MemoryPointer (required for Windows W-suffix APIs).
        #
        # @param str [String] The Ruby string to convert
        # @return [FFI::MemoryPointer] Pointer to UTF-16LE encoded string
        def to_wide_string(str)
          wide = str.encode('UTF-16LE') + "\x00\x00".force_encoding('UTF-16LE')
          ptr = FFI::MemoryPointer.new(:uint8, wide.bytesize)
          ptr.put_bytes(0, wide.bytes.pack('C*'))
          ptr
        end

        # Convert a memory protection constant to a human-readable string.
        #
        # @param protect [Integer] Memory protection flag
        # @return [String] Human-readable protection string
        def protection_to_string(protect)
          case protect
          when WinConstants::PAGE_NOACCESS          then 'PAGE_NOACCESS'
          when WinConstants::PAGE_READONLY          then 'PAGE_READONLY'
          when WinConstants::PAGE_READWRITE         then 'PAGE_READWRITE'
          when WinConstants::PAGE_EXECUTE           then 'PAGE_EXECUTE'
          when WinConstants::PAGE_EXECUTE_READ      then 'PAGE_EXECUTE_READ'
          when WinConstants::PAGE_EXECUTE_READWRITE then 'PAGE_EXECUTE_READWRITE'
          else "UNKNOWN(0x#{protect.to_s(16)})"
          end
        end

        # Map PE section characteristics to appropriate memory protection.
        #
        # @param characteristics [Integer] Section characteristics from PE header
        # @return [Integer] Corresponding memory protection constant
        def section_characteristics_to_protection(characteristics)
          # Extract only the memory-relevant flags
          mem_flags = characteristics & (
            WinConstants::IMAGE_SCN_MEM_EXECUTE |
            WinConstants::IMAGE_SCN_MEM_READ |
            WinConstants::IMAGE_SCN_MEM_WRITE
          )
          WinConstants::SECTION_PROTECTION_MAP.fetch(mem_flags, WinConstants::PAGE_READONLY)
        end

        # Convert Linux ELF program header flags to mmap protection flags.
        #
        # @param flags [Integer] ELF p_flags value
        # @return [Integer] mmap PROT_* flags
        def elf_flags_to_mmap_prot(flags)
          prot = LinuxConstants::PROT_NONE
          prot |= LinuxConstants::PROT_READ  if (flags & LinuxConstants::PF_R) != 0
          prot |= LinuxConstants::PROT_WRITE if (flags & LinuxConstants::PF_W) != 0
          prot |= LinuxConstants::PROT_EXEC  if (flags & LinuxConstants::PF_X) != 0
          prot
        end

        # Align an address down to the nearest page boundary.
        #
        # @param address [Integer] Address to align
        # @param page_size [Integer] Page size (default 4096)
        # @return [Integer] Page-aligned address
        def page_align_down(address, page_size = 4096)
          address & ~(page_size - 1)
        end

        # Align a size up to the nearest page boundary.
        #
        # @param size [Integer] Size to align
        # @param page_size [Integer] Page size (default 4096)
        # @return [Integer] Page-aligned size
        def page_align_up(size, page_size = 4096)
          (size + page_size - 1) & ~(page_size - 1)
        end
      end
    end
  end
end
