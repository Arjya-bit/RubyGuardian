# frozen_string_literal: true

module RubyGuardian
  module Honeypot
    module CaptureEngine
      # ExecTrap intercepts and logs all command execution calls made by
      # analyzed scripts. It monkey-patches Kernel#system, Kernel#exec,
      # Kernel#`, IO.popen, Open3 methods, and Process.spawn to capture
      # every attempt to shell out from Ruby code.
      class ExecTrap
        TRAPPED_METHODS = %i[system exec `].freeze

        attr_reader :captures, :started_at

        def initialize(log_dir:, sample_id:, logger: nil)
          @log_dir = log_dir
          @sample_id = sample_id
          @logger = logger || default_logger
          @captures = []
          @started_at = nil
          @mutex = Mutex.new
          @original_methods = {}
        end

        # Activate all exec traps. Call this before executing the sample.
        def activate!
          @started_at = Time.now.utc
          @logger.info("[ExecTrap] Activating traps for sample #{@sample_id}")

          trap_kernel_system
          trap_kernel_exec
          trap_kernel_backtick
          trap_io_popen
          trap_process_spawn
          trap_open3

          self
        end

        # Deactivate traps and restore original methods.
        def deactivate!
          @logger.info("[ExecTrap] Deactivating traps for sample #{@sample_id}")
          restore_original_methods
          flush_captures
          self
        end

        # Record a captured exec call.
        def record(method:, command:, args: [], caller_location: nil)
          entry = {
            timestamp: Time.now.utc.iso8601(6),
            sample_id: @sample_id,
            method: method.to_s,
            command: command.to_s,
            args: args.map(&:to_s),
            caller_location: caller_location || extract_caller,
            elapsed_ms: elapsed_ms,
            pid: Process.pid,
            uid: Process.uid,
            env_snapshot: filtered_env
          }

          @mutex.synchronize { @captures << entry }
          @logger.warn("[ExecTrap] Captured #{method}: #{command} #{args.join(' ')}")
          entry
        end

        # Write all captures to disk as JSON.
        def flush_captures
          return if @captures.empty?

          output_path = File.join(@log_dir, "exec_captures_#{@sample_id}.json")
          File.write(output_path, JSON.pretty_generate(report_data))
          @logger.info("[ExecTrap] Flushed #{@captures.size} captures to #{output_path}")
        end

        # Summary statistics of captured exec calls.
        def summary
          {
            sample_id: @sample_id,
            total_captures: @captures.size,
            unique_commands: @captures.map { |c| c[:command] }.uniq.size,
            methods_used: @captures.map { |c| c[:method] }.tally,
            first_capture_at: @captures.first&.dig(:timestamp),
            last_capture_at: @captures.last&.dig(:timestamp)
          }
        end

        private

        def trap_kernel_system
          trap = self
          @original_methods[:system] = Kernel.instance_method(:system)

          Kernel.define_method(:system) do |*args, **kwargs|
            trap.record(method: :system, command: args.first, args: args[1..], caller_location: caller_locations(1, 1).first.to_s)
            # Return false to simulate command failure (do not actually execute)
            false
          end
        end

        def trap_kernel_exec
          trap = self
          @original_methods[:exec] = Kernel.instance_method(:exec)

          Kernel.define_method(:exec) do |*args|
            trap.record(method: :exec, command: args.first, args: args[1..], caller_location: caller_locations(1, 1).first.to_s)
            raise Errno::ENOENT, "No such file or directory - #{args.first}"
          end
        end

        def trap_kernel_backtick
          trap = self
          @original_methods[:backtick] = Kernel.instance_method(:`)

          Kernel.define_method(:`) do |cmd|
            trap.record(method: :backtick, command: cmd, caller_location: caller_locations(1, 1).first.to_s)
            "" # Return empty string
          end
        end

        def trap_io_popen
          trap = self
          @original_methods[:io_popen] = IO.method(:popen)

          IO.define_singleton_method(:popen) do |*args, &block|
            cmd = args.first
            trap.record(method: :io_popen, command: cmd.is_a?(Array) ? cmd.join(" ") : cmd.to_s,
                        caller_location: caller_locations(1, 1).first.to_s)
            StringIO.new("") # Return empty IO-like object
          end
        end

        def trap_process_spawn
          trap = self
          @original_methods[:process_spawn] = Process.method(:spawn)

          Process.define_singleton_method(:spawn) do |*args|
            trap.record(method: :process_spawn, command: args.first, args: args[1..],
                        caller_location: caller_locations(1, 1).first.to_s)
            -1 # Return fake PID
          end
        end

        def trap_open3
          return unless defined?(Open3)

          trap = self
          %i[capture3 popen3 pipeline].each do |m|
            next unless Open3.respond_to?(m)

            @original_methods[:"open3_#{m}"] = Open3.method(m)
            Open3.define_singleton_method(m) do |*args, &block|
              trap.record(method: :"open3_#{m}", command: args.first, args: args[1..],
                          caller_location: caller_locations(1, 1).first.to_s)
              ["", "", nil]
            end
          end
        end

        def restore_original_methods
          @original_methods.each do |name, method_obj|
            case name
            when :system, :exec, :backtick
              Kernel.define_method(name == :backtick ? :` : name, method_obj)
            when :io_popen
              IO.define_singleton_method(:popen, method_obj)
            when :process_spawn
              Process.define_singleton_method(:spawn, method_obj)
            when /^open3_(.+)/
              Open3.define_singleton_method(Regexp.last_match(1).to_sym, method_obj) if defined?(Open3)
            end
          end
          @original_methods.clear
        end

        def extract_caller
          caller_locations(3, 1).first&.to_s || "unknown"
        end

        def elapsed_ms
          return 0 unless @started_at
          ((Time.now.utc - @started_at) * 1000).round(2)
        end

        def filtered_env
          sensitive_keys = %w[PATH HOME USER SHELL RUBY_VERSION GEM_HOME]
          ENV.select { |k, _| sensitive_keys.include?(k) }
        end

        def report_data
          {
            sample_id: @sample_id,
            started_at: @started_at&.iso8601,
            ended_at: Time.now.utc.iso8601,
            summary: summary,
            captures: @captures
          }
        end

        def default_logger
          require "logger"
          Logger.new($stdout, progname: "RubyGuardian::ExecTrap")
        end
      end
    end
  end
end
