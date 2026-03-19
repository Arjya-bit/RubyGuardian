# frozen_string_literal: true

# RubyGuardian Detection Engine - System Call Tracer
# ===================================================
# Traces system calls made by Ruby processes using eBPF (preferred) or
# ptrace (fallback). Detects suspicious syscall patterns and sequences
# that indicate runtime attacks.

require "concurrent"

module RubyGuardian
  module Detection
    class SyscallTracer
      # Common syscall numbers for x86_64 Linux
      SYSCALL_MAP = {
        0   => :read,      1   => :write,     2   => :open,
        3   => :close,     9   => :mmap,      10  => :mprotect,
        11  => :munmap,    56  => :clone,     57  => :fork,
        59  => :execve,    62  => :kill,      101 => :ptrace,
        232 => :epoll_wait, 257 => :openat,
        310 => :process_vm_readv,  311 => :process_vm_writev,
        319 => :memfd_create,
        41  => :socket,    42  => :connect,   44  => :sendto,
        45  => :recvfrom,  46  => :sendmsg,   47  => :recvmsg
      }.freeze

      # Suspicious syscall sequences that may indicate attacks
      SUSPICIOUS_SEQUENCES = {
        process_hollowing: %i[fork ptrace mmap process_vm_writev],
        fileless_exec: %i[memfd_create write execve],
        memory_injection: %i[mmap mprotect write],
        shellcode_load: %i[mmap mprotect],
        credential_dump: %i[ptrace process_vm_readv],
        reverse_shell: %i[socket connect execve]
      }.freeze

      attr_reader :state

      def initialize(config:, event_collector:, logger:)
        @config = config
        @event_collector = event_collector
        @logger = logger
        @state = :initialized
        @method = config.fetch("method", "ebpf")
        @fallback_method = config.fetch("fallback_method", "ptrace")
        @traced_syscalls = resolve_traced_syscalls(config.fetch("traced_syscalls", []))
        @sequence_window_ms = config.fetch("sequence_window_ms", 5000)
        @syscall_buffers = Concurrent::Map.new  # pid -> [timestamped syscalls]
        @active_tracers = Concurrent::Map.new
        @event_count = Concurrent::AtomicFixnum.new(0)
        @ebpf_bridge = nil
        @ptrace_helper = nil
        @scheduler = nil
        @buffer_cleaner = nil
        @mutex = Mutex.new
      end

      def start
        @logger.info("SyscallTracer starting (method: #{@method})")
        @state = :starting

        if @method == "ebpf"
          start_ebpf_tracing
        else
          start_ptrace_tracing
        end

        start_sequence_detector
        start_buffer_cleaner

        @state = :running
        @logger.info("SyscallTracer started successfully")
      rescue StandardError => e
        @logger.warn("Primary method '#{@method}' failed: #{e.message}")
        if @method != @fallback_method
          @logger.info("Falling back to #{@fallback_method}")
          @method = @fallback_method
          retry
        end
        @state = :error
        raise
      end

      def stop
        @logger.info("SyscallTracer stopping")
        @scheduler&.shutdown
        @buffer_cleaner&.shutdown
        stop_ebpf_tracing
        stop_ptrace_tracing
        @state = :stopped
        @logger.info("SyscallTracer stopped (events: #{@event_count.value})")
      end

      def reconfigure(new_config)
        @config = new_config
        @traced_syscalls = resolve_traced_syscalls(new_config.fetch("traced_syscalls", []))
        @sequence_window_ms = new_config.fetch("sequence_window_ms", 5000)
      end

      def status
        {
          state: @state,
          method: @method,
          traced_pids: @active_tracers.size,
          buffered_events: total_buffered_events,
          event_count: @event_count.value
        }
      end

      # Record a syscall event from any source (eBPF callback, ptrace, audit)
      def record_syscall(pid:, syscall_nr:, args: [], ret: 0, timestamp: nil)
        timestamp ||= Time.now.to_f
        syscall_name = SYSCALL_MAP[syscall_nr] || :"unknown_#{syscall_nr}"

        return unless @traced_syscalls.include?(syscall_name)

        entry = {
          pid: pid,
          syscall: syscall_name,
          syscall_nr: syscall_nr,
          args: args,
          ret: ret,
          timestamp: timestamp
        }

        buffer = (@syscall_buffers[pid] ||= Concurrent::Array.new)
        buffer.push(entry)

        # Trim buffer if too large
        buffer.shift if buffer.size > 500

        emit_syscall_event(entry)
        check_immediate_alerts(entry)
      end

      # Attach tracing to a specific PID
      def attach(pid)
        return if @active_tracers.key?(pid)

        @logger.debug("Attaching syscall tracer to PID #{pid}")

        case @method
        when "ebpf"
          attach_ebpf(pid)
        when "ptrace"
          attach_ptrace(pid)
        when "audit"
          attach_audit(pid)
        end

        @active_tracers[pid] = {
          method: @method,
          attached_at: Time.now,
          syscall_count: 0
        }
      end

      # Detach tracing from a specific PID
      def detach(pid)
        return unless @active_tracers.key?(pid)

        @logger.debug("Detaching syscall tracer from PID #{pid}")

        case @method
        when "ebpf"
          detach_ebpf(pid)
        when "ptrace"
          detach_ptrace(pid)
        end

        @active_tracers.delete(pid)
        @syscall_buffers.delete(pid)
      end

      private

      def resolve_traced_syscalls(names)
        names.map(&:to_sym).to_set
      end

      def start_ebpf_tracing
        @logger.info("Initializing eBPF-based syscall tracing")

        begin
          require_relative "native_extensions/ebpf_bridge/ebpf_bridge"
          @ebpf_bridge = RubyGuardian::Detection::Native::EbpfBridge.new
          @ebpf_bridge.load_probes(@traced_syscalls.to_a)
          @ebpf_bridge.on_event { |event| handle_ebpf_event(event) }
          @logger.info("eBPF probes loaded successfully")
        rescue LoadError => e
          @logger.warn("eBPF bridge not available: #{e.message}")
          raise
        end
      end

      def stop_ebpf_tracing
        @ebpf_bridge&.unload_probes
        @ebpf_bridge = nil
      end

      def start_ptrace_tracing
        @logger.info("Initializing ptrace-based syscall tracing")

        begin
          require_relative "native_extensions/ptrace_helper/ptrace_helper"
          @ptrace_helper = RubyGuardian::Detection::Native::PtraceHelper.new
          @logger.info("ptrace helper loaded successfully")
        rescue LoadError => e
          @logger.warn("ptrace helper not available: #{e.message}")
          raise
        end
      end

      def stop_ptrace_tracing
        @active_tracers.each_pair do |pid, info|
          detach_ptrace(pid) if info[:method] == "ptrace"
        end
        @ptrace_helper = nil
      end

      def attach_ebpf(pid)
        @ebpf_bridge&.attach_pid(pid)
      end

      def detach_ebpf(pid)
        @ebpf_bridge&.detach_pid(pid)
      end

      def attach_ptrace(pid)
        @ptrace_helper&.attach(pid)

        # Start a reader thread for this pid
        Thread.new do
          Thread.current.name = "ptrace-reader-#{pid}"
          ptrace_read_loop(pid)
        end
      end

      def detach_ptrace(pid)
        @ptrace_helper&.detach(pid)
      end

      def attach_audit(pid)
        @logger.debug("Audit-based tracing for PID #{pid} (passive mode)")
        # Audit-based tracing relies on auditd rules already being in place
      end

      def handle_ebpf_event(event)
        record_syscall(
          pid: event[:pid],
          syscall_nr: event[:syscall_nr],
          args: event[:args] || [],
          ret: event[:ret] || 0,
          timestamp: event[:timestamp]
        )
      end

      def ptrace_read_loop(pid)
        loop do
          break unless @active_tracers.key?(pid)

          event = @ptrace_helper&.wait_for_syscall(pid)
          break unless event

          record_syscall(
            pid: pid,
            syscall_nr: event[:syscall_nr],
            args: event[:args] || [],
            ret: event[:ret] || 0
          )
        end
      rescue StandardError => e
        @logger.debug("ptrace read loop ended for PID #{pid}: #{e.message}")
        @active_tracers.delete(pid)
      end

      # Periodically check syscall buffers for suspicious sequences
      def start_sequence_detector
        @scheduler = Concurrent::TimerTask.new(
          execution_interval: 1.0,
          timeout_interval: 5.0
        ) { detect_sequences }

        @scheduler.execute
      end

      # Clean old entries from syscall buffers
      def start_buffer_cleaner
        @buffer_cleaner = Concurrent::TimerTask.new(
          execution_interval: 10.0,
          timeout_interval: 15.0
        ) { clean_buffers }

        @buffer_cleaner.execute
      end

      def detect_sequences
        cutoff = Time.now.to_f - (@sequence_window_ms / 1000.0)

        @syscall_buffers.each_pair do |pid, buffer|
          recent = buffer.select { |e| e[:timestamp] >= cutoff }
          next if recent.size < 2

          recent_syscalls = recent.map { |e| e[:syscall] }

          SUSPICIOUS_SEQUENCES.each do |attack_type, pattern|
            if subsequence_match?(recent_syscalls, pattern)
              emit_sequence_alert(pid, attack_type, pattern, recent)
            end
          end
        end
      rescue StandardError => e
        @logger.error("Sequence detection error: #{e.message}")
      end

      # Check if pattern is a subsequence of the observed syscalls
      def subsequence_match?(observed, pattern)
        pattern_idx = 0
        observed.each do |syscall|
          if syscall == pattern[pattern_idx]
            pattern_idx += 1
            return true if pattern_idx >= pattern.size
          end
        end
        false
      end

      def clean_buffers
        cutoff = Time.now.to_f - (@sequence_window_ms / 1000.0) * 2

        @syscall_buffers.each_pair do |pid, buffer|
          buffer.reject! { |e| e[:timestamp] < cutoff }
          @syscall_buffers.delete(pid) if buffer.empty?
        end
      end

      def check_immediate_alerts(entry)
        case entry[:syscall]
        when :memfd_create
          emit_event(:syscall_memfd_create, {
            pid: entry[:pid],
            severity: :high,
            description: "Process created anonymous memory-backed file (memfd_create)"
          })

        when :ptrace
          emit_event(:syscall_ptrace_call, {
            pid: entry[:pid],
            args: entry[:args],
            severity: :high,
            description: "Process invoked ptrace syscall"
          })

        when :process_vm_readv, :process_vm_writev
          emit_event(:syscall_cross_process_memory, {
            pid: entry[:pid],
            syscall: entry[:syscall],
            target_pid: entry[:args]&.first,
            severity: :critical,
            description: "Cross-process memory access detected"
          })

        when :execve
          check_suspicious_execve(entry)
        end
      end

      def check_suspicious_execve(entry)
        # Check if execve is from a memfd or /dev/shm path
        path = extract_execve_path(entry[:args])
        return unless path

        if path.include?("/proc/self/fd/") || path.include?("memfd:")
          emit_event(:syscall_fileless_exec, {
            pid: entry[:pid],
            path: path,
            severity: :critical,
            description: "Fileless execution detected via memfd"
          })
        elsif path.start_with?("/dev/shm/")
          emit_event(:syscall_shm_exec, {
            pid: entry[:pid],
            path: path,
            severity: :high,
            description: "Execution from shared memory"
          })
        elsif path.start_with?("/tmp/") || path.start_with?("/var/tmp/")
          emit_event(:syscall_temp_exec, {
            pid: entry[:pid],
            path: path,
            severity: :medium,
            description: "Execution from temporary directory"
          })
        end
      end

      def extract_execve_path(args)
        return nil unless args.is_a?(Array) && !args.empty?

        args.first.to_s
      end

      def emit_sequence_alert(pid, attack_type, pattern, events)
        emit_event(:syscall_sequence_detected, {
          pid: pid,
          attack_type: attack_type,
          pattern: pattern,
          matched_syscalls: events.map { |e| { syscall: e[:syscall], timestamp: e[:timestamp] } },
          window_ms: @sequence_window_ms,
          severity: :critical,
          description: "Suspicious syscall sequence detected: #{attack_type}"
        })
      end

      def emit_syscall_event(entry)
        @event_count.increment
        event = {
          source: :syscall_tracer,
          type: :syscall_observed,
          timestamp: entry[:timestamp],
          data: entry
        }
        @event_collector.push(event)
      end

      def emit_event(type, data)
        @event_count.increment
        event = {
          source: :syscall_tracer,
          type: type,
          timestamp: Time.now.to_f,
          data: data
        }
        @event_collector.push(event)
        @logger.info("SyscallTracer alert: #{type} - #{data[:description]}")
      end

      def total_buffered_events
        @syscall_buffers.values.sum(&:size)
      end
    end
  end
end
