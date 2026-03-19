# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1d -- ObjectSpace Persistence: Callback Installer
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT use these techniques on systems without explicit authorization.
#
# Demonstrates how attackers install hidden callbacks using Ruby's built-in
# callback mechanisms: at_exit, TracePoint, and set_trace_func. These callbacks
# persist for the lifetime of the process and execute automatically on certain
# events, providing stealthy persistence within a running Ruby application.
#
# MITRE ATT&CK: T1546 - Event Triggered Execution
#
# FORENSIC DETECTION:
# - Enumerate at_exit handlers via ObjectSpace scanning for Proc objects
# - Check TracePoint.stat for active trace points
# - Monitor set_trace_func registrations via TracePoint on :c_call
# - Audit Proc#source_location for callbacks from unexpected files
# =============================================================================

require 'objspace'

module RubyGuardian
  module ObjectSpacePersistence
    class CallbackInstaller
      # Track all installed callbacks for educational auditing
      attr_reader :installed_callbacks, :logger

      def initialize(logger: nil, dry_run: true)
        @logger = logger
        @dry_run = dry_run
        @installed_callbacks = []
        @tracepoints = []
        @original_trace_func = nil
      end

      # Install an at_exit callback that executes when the Ruby process exits.
      #
      # EDUCATIONAL: at_exit handlers are stored in a LIFO stack and execute
      # during Kernel#exit or normal process termination. They cannot be
      # enumerated or removed through any public Ruby API, making them an
      # excellent persistence mechanism.
      #
      # DETECTION: Scan ObjectSpace for Proc objects whose source_location
      # does not match known application code paths.
      #
      # @param tag [String] Identifier for this callback
      # @param block [Proc] Code to execute at process exit
      # @return [Hash] Installation record
      def install_at_exit(tag: 'unnamed', &block)
        log("Installing at_exit callback: #{tag}")

        record = {
          type: :at_exit,
          tag: tag,
          installed_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          callback_proc = block || proc {
            log("at_exit callback fired: #{tag}")
          }
          at_exit(&callback_proc)
          record[:source_location] = callback_proc.source_location
          record[:proc_object_id] = callback_proc.object_id
        end

        @installed_callbacks << record
        log("  Installed at_exit '#{tag}' (dry_run=#{@dry_run})")
        record
      end

      # Install a TracePoint callback that fires on specific Ruby VM events.
      #
      # EDUCATIONAL: TracePoint hooks into the Ruby VM's event system and can
      # monitor method calls, class definitions, line execution, and more.
      # An attacker can use TracePoint to intercept sensitive method calls
      # (e.g., authentication) and exfiltrate arguments or modify behavior.
      #
      # DETECTION:
      # - TracePoint.stat shows if any tracepoints are active
      # - Enumerate TracePoint objects via ObjectSpace.each_object(TracePoint)
      # - Performance degradation from active tracepoints is a side-channel indicator
      #
      # @param events [Array<Symbol>] Events to trace (:call, :return, :line, etc.)
      # @param tag [String] Identifier for this callback
      # @param filter_class [Class, nil] Only fire for methods on this class
      # @param block [Proc] Handler code
      # @return [Hash] Installation record
      def install_tracepoint(events: [:call], tag: 'unnamed', filter_class: nil, &block)
        log("Installing TracePoint for events #{events.inspect}: #{tag}")

        record = {
          type: :tracepoint,
          tag: tag,
          events: events,
          filter_class: filter_class&.name,
          installed_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          handler = block || proc { |tp|
            next if filter_class && tp.defined_class != filter_class

            log("TracePoint[#{tag}] #{tp.event}: #{tp.defined_class}##{tp.method_id} at #{tp.path}:#{tp.lineno}")
          }

          tp = TracePoint.new(*events, &handler)
          tp.enable
          @tracepoints << tp
          record[:tracepoint_object_id] = tp.object_id
          record[:source_location] = handler.source_location
        end

        @installed_callbacks << record
        log("  TracePoint '#{tag}' enabled for #{events.inspect}")
        record
      end

      # Install a method-specific interceptor using TracePoint.
      #
      # EDUCATIONAL: By filtering TracePoint to specific classes and methods,
      # an attacker can silently monitor authentication checks, SQL queries,
      # session management, or any other sensitive operation.
      #
      # @param target_class [Class] Class to monitor
      # @param method_name [Symbol] Method to intercept
      # @param on_call [Proc, nil] Handler for method entry
      # @param on_return [Proc, nil] Handler for method return
      # @return [Hash] Installation record
      def install_method_interceptor(target_class:, method_name:, on_call: nil, on_return: nil)
        tag = "intercept_#{target_class.name}##{method_name}"
        log("Installing method interceptor: #{tag}")

        record = {
          type: :method_interceptor,
          tag: tag,
          target_class: target_class.name,
          method_name: method_name,
          installed_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          tp = TracePoint.new(:call, :return) do |trace|
            next unless trace.defined_class == target_class
            next unless trace.method_id == method_name

            case trace.event
            when :call
              on_call&.call(trace)
            when :return
              on_return&.call(trace)
            end
          end
          tp.enable
          @tracepoints << tp
          record[:tracepoint_object_id] = tp.object_id
        end

        @installed_callbacks << record
        record
      end

      # Install a legacy set_trace_func callback.
      #
      # EDUCATIONAL: set_trace_func is the older tracing API (pre-TracePoint).
      # Only one set_trace_func can be active at a time. It receives events
      # for every Ruby operation, making it powerful but performance-heavy.
      # Attackers may use it to intercept specific operations in legacy apps.
      #
      # DETECTION: Call set_trace_func(nil) to clear; check if application
      # performance degrades unexpectedly (active trace func is expensive).
      #
      # @param tag [String] Identifier for this callback
      # @param block [Proc] Trace function (event, file, line, id, binding, classname)
      # @return [Hash] Installation record
      def install_set_trace_func(tag: 'unnamed', &block)
        log("Installing set_trace_func: #{tag}")

        record = {
          type: :set_trace_func,
          tag: tag,
          installed_at: Time.now.utc.iso8601,
          dry_run: @dry_run
        }

        unless @dry_run
          @original_trace_func = nil # Cannot retrieve existing one
          handler = block || proc { |event, file, line, id, _bind, classname|
            if event == 'call'
              log("trace_func[#{tag}] #{classname}##{id} at #{file}:#{line}")
            end
          }
          set_trace_func(handler)
          record[:source_location] = handler.source_location
        end

        @installed_callbacks << record
        record
      end

      # Scan the current process for active TracePoint objects.
      #
      # FORENSIC TOOL: Use this to detect unauthorized tracepoints.
      #
      # @return [Array<Hash>] Information about each active TracePoint
      def self.scan_for_tracepoints
        findings = []
        ObjectSpace.each_object(TracePoint) do |tp|
          findings << {
            object_id: tp.object_id,
            enabled: tp.enabled?,
            inspect: tp.inspect
          }
        end
        findings
      end

      # Scan for Proc objects that might be at_exit handlers.
      #
      # FORENSIC TOOL: at_exit handlers cannot be enumerated directly,
      # but scanning for Proc objects with suspicious source locations
      # can reveal them.
      #
      # @return [Array<Hash>] Suspicious Proc objects
      def self.scan_for_suspicious_procs
        suspicious = []
        ObjectSpace.each_object(Proc) do |p|
          loc = p.source_location
          next unless loc

          file, _line = loc
          # Flag procs from eval, non-standard paths, or temp directories
          if file&.include?('(eval)') || file&.start_with?('/tmp') || file&.include?('payload')
            suspicious << {
              object_id: p.object_id,
              source_location: loc,
              arity: p.arity,
              lambda: p.lambda?
            }
          end
        end
        suspicious
      end

      # Remove all installed callbacks (cleanup for testing).
      #
      # @return [Integer] Number of callbacks removed
      def cleanup!
        count = 0

        @tracepoints.each do |tp|
          tp.disable if tp.enabled?
          count += 1
        end
        @tracepoints.clear

        # Clear set_trace_func if we installed one
        if @installed_callbacks.any? { |c| c[:type] == :set_trace_func && !c[:dry_run] }
          set_trace_func(nil)
          count += 1
        end

        # Note: at_exit handlers cannot be removed
        at_exit_count = @installed_callbacks.count { |c| c[:type] == :at_exit && !c[:dry_run] }
        if at_exit_count > 0
          log("WARNING: #{at_exit_count} at_exit handlers cannot be removed")
        end

        @installed_callbacks.clear
        log("Cleaned up #{count} callbacks")
        count
      end

      # Summary of all installed callbacks.
      #
      # @return [Hash] Summary report
      def summary
        {
          total_installed: @installed_callbacks.size,
          by_type: @installed_callbacks.group_by { |c| c[:type] }.transform_values(&:size),
          active_tracepoints: @tracepoints.count(&:enabled?),
          dry_run: @dry_run,
          callbacks: @installed_callbacks
        }
      end

      def describe
        <<~DESC
          Callback Installer (T1546 - Event Triggered Execution)
          ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
          Ruby provides several callback mechanisms that persist for
          the lifetime of a process:

          - at_exit: Execute code during process shutdown (LIFO stack)
          - TracePoint: Hook into Ruby VM events (call, return, line, etc.)
          - set_trace_func: Legacy global trace function

          These are legitimate Ruby features used for debugging, profiling,
          and cleanup. Malicious use is difficult to detect because the
          callbacks blend in with framework instrumentation.
        DESC
      end

      private

      def log(message)
        @logger&.info("[CallbackInstaller] #{message}")
      end
    end
  end
end
