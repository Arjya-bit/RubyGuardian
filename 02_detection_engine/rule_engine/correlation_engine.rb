# frozen_string_literal: true

# RubyGuardian Detection Engine - Correlation Engine
# ===================================================
# Correlates security events across multiple monitors and time windows
# to detect multi-stage attack patterns. Maintains sliding windows of
# events grouped by process, session, and attack pattern to identify
# threats that no single monitor would catch independently.

require "concurrent"
require "securerandom"
require "set"

module RubyGuardian
  module Detection
    module RuleEngine
      class CorrelationEngine
        # Pre-defined correlation patterns for common multi-stage attacks
        ATTACK_PATTERNS = {
          fileless_execution: {
            name: "Fileless Code Execution Chain",
            description: "Detects combination of eval/load with network activity and memory manipulation",
            severity: :critical,
            required_sources: %w[process_monitor memory_inspector],
            event_types: %i[
              process_exec_detected process_memfd_detected
              memory_rwx_detected eval_call_detected
            ],
            min_events: 2,
            window_seconds: 120,
            mitre_attack: { tactic: "defense-evasion", technique: "T1027.011" }
          },
          reverse_shell_setup: {
            name: "Reverse Shell Construction",
            description: "Detects socket creation followed by process spawn and IO redirection",
            severity: :critical,
            required_sources: %w[network_monitor process_monitor syscall_tracer],
            event_types: %i[
              network_outbound_connection process_fork_detected
              process_exec_detected process_spawn_non_ruby
            ],
            min_events: 2,
            window_seconds: 30,
            mitre_attack: { tactic: "execution", technique: "T1059.004" }
          },
          data_exfiltration: {
            name: "Data Exfiltration Pattern",
            description: "Detects file reads followed by network data transfer or DNS tunneling",
            severity: :high,
            required_sources: %w[file_monitor network_monitor],
            event_types: %i[
              filesystem_sensitive_read filesystem_bulk_read
              network_large_transfer network_dns_tunnel_suspected
              network_beaconing_detected
            ],
            min_events: 2,
            window_seconds: 300,
            mitre_attack: { tactic: "exfiltration", technique: "T1041" }
          },
          privilege_escalation: {
            name: "Privilege Escalation Attempt",
            description: "Detects combination of process manipulation and sensitive file access",
            severity: :critical,
            required_sources: %w[process_monitor syscall_tracer file_monitor],
            event_types: %i[
              process_ptrace_detected syscall_privilege_escalation
              filesystem_sensitive_write process_setuid_detected
            ],
            min_events: 2,
            window_seconds: 60,
            mitre_attack: { tactic: "privilege-escalation", technique: "T1055" }
          },
          supply_chain_attack: {
            name: "Supply Chain Compromise Indicators",
            description: "Detects gem manipulation combined with code execution and network activity",
            severity: :high,
            required_sources: %w[process_monitor objectspace_scanner],
            event_types: %i[
              objectspace_method_redefined objectspace_core_class_tampered
              gem_spec_modified eval_call_detected
            ],
            min_events: 2,
            window_seconds: 180,
            mitre_attack: { tactic: "initial-access", technique: "T1195.002" }
          },
          persistence_mechanism: {
            name: "Persistence Installation",
            description: "Detects file writes to autostart locations combined with code execution",
            severity: :high,
            required_sources: %w[file_monitor process_monitor],
            event_types: %i[
              filesystem_autostart_write filesystem_cron_modification
              process_exec_detected process_spawn_non_ruby
            ],
            min_events: 2,
            window_seconds: 120,
            mitre_attack: { tactic: "persistence", technique: "T1546" }
          }
        }.freeze

        # Maximum number of events to retain per correlation window
        MAX_WINDOW_EVENTS = 500
        # How often to prune expired windows (in process_event calls)
        PRUNE_INTERVAL = 100

        attr_reader :logger, :stats

        def initialize(config:, logger:)
          @config = config || {}
          @logger = logger
          @enabled = @config.fetch("enabled", true)
          @window_seconds = @config.fetch("window_seconds", 60)
          @min_events = @config.fetch("min_events", 3)

          # Event windows keyed by correlation group (e.g., pid, session)
          @event_windows = Concurrent::Map.new
          # Track which patterns have already fired to avoid duplicate alerts
          @fired_patterns = Concurrent::Map.new
          @process_count = Concurrent::AtomicFixnum.new(0)

          @stats = {
            events_processed: Concurrent::AtomicFixnum.new(0),
            correlations_found: Concurrent::AtomicFixnum.new(0),
            patterns_checked: Concurrent::AtomicFixnum.new(0)
          }

          @logger.info("CorrelationEngine initialized (enabled=#{@enabled}, " \
                       "window=#{@window_seconds}s, patterns=#{ATTACK_PATTERNS.size})")
        end

        # Process a single event through the correlation engine.
        # Adds the event to appropriate correlation windows and checks
        # for pattern matches.
        #
        # @param event [Hash] enriched event from EventCollector
        # @return [Array<Hash>] correlation alert objects (may be empty)
        def process_event(event)
          return [] unless @enabled
          return [] unless event.is_a?(Hash)

          @stats[:events_processed].increment
          @process_count.increment
          prune_expired_windows if (@process_count.value % PRUNE_INTERVAL).zero?

          # Determine correlation keys for this event
          correlation_keys = extract_correlation_keys(event)

          # Add event to all relevant windows
          correlation_keys.each do |key|
            add_to_window(key, event)
          end

          # Check all attack patterns against current windows
          alerts = []
          correlation_keys.each do |key|
            window_events = get_window_events(key)
            next if window_events.size < 2

            ATTACK_PATTERNS.each do |pattern_id, pattern|
              @stats[:patterns_checked].increment
              next if already_fired?(key, pattern_id)

              if pattern_matches?(window_events, pattern)
                alert = build_correlation_alert(pattern_id, pattern, window_events, key)
                alerts << alert
                mark_fired(key, pattern_id)
                @stats[:correlations_found].increment

                @logger.warn("Correlation alert: #{pattern[:name]} " \
                             "(key=#{key}, events=#{window_events.size})")
              end
            end
          end

          # Also check for generic multi-source correlation
          correlation_keys.each do |key|
            window_events = get_window_events(key)
            generic_alert = check_generic_correlation(key, window_events)
            alerts << generic_alert if generic_alert
          end

          alerts
        rescue StandardError => e
          @logger.error("CorrelationEngine error: #{e.class}: #{e.message}")
          @logger.debug(e.backtrace&.first(5)&.join("\n"))
          []
        end

        # Get current correlation statistics
        def statistics
          @stats.transform_values { |v| v.is_a?(Concurrent::AtomicFixnum) ? v.value : v }
        end

        # Reset all correlation state (for testing or rule reload)
        def reset!
          @event_windows = Concurrent::Map.new
          @fired_patterns = Concurrent::Map.new
          @process_count = Concurrent::AtomicFixnum.new(0)
        end

        private

        # Extract keys by which this event should be correlated.
        # Events from the same process, session, or host are grouped together.
        #
        # @param event [Hash]
        # @return [Array<String>] correlation keys
        def extract_correlation_keys(event)
          keys = []

          pid = event.dig(:data, :pid) || event[:pid]
          keys << "pid:#{pid}" if pid

          ppid = event.dig(:data, :ppid)
          keys << "pid:#{ppid}" if ppid && ppid != pid

          session = event.dig(:data, :session_id) || event[:session_id]
          keys << "session:#{session}" if session

          # Always correlate by hostname for host-level patterns
          hostname = event[:hostname]
          keys << "host:#{hostname}" if hostname

          # Use a generic key if no specific key found
          keys << "global" if keys.empty?

          keys
        end

        # Add an event to a correlation window, enforcing size limits.
        #
        # @param key [String] correlation key
        # @param event [Hash]
        def add_to_window(key, event)
          window = @event_windows.compute_if_absent(key) do
            { events: [], created_at: Time.now.to_f }
          end

          window[:events] << {
            type: event[:type],
            source: event[:source],
            timestamp: event[:timestamp] || Time.now.to_f,
            severity: event.dig(:data, :severity) || event[:severity_level],
            data_summary: summarize_event_data(event[:data]),
            original_event: event
          }

          # Enforce maximum window size
          if window[:events].size > MAX_WINDOW_EVENTS
            window[:events] = window[:events].last(MAX_WINDOW_EVENTS)
          end
        end

        # Get events from a correlation window.
        #
        # @param key [String] correlation key
        # @return [Array<Hash>]
        def get_window_events(key)
          window = @event_windows[key]
          return [] unless window

          # Filter to only events within the time window
          cutoff = Time.now.to_f - @window_seconds
          window[:events].select do |evt|
            ts = evt[:timestamp]
            ts_float = ts.is_a?(String) ? (Time.parse(ts).to_f rescue 0) : ts.to_f
            ts_float >= cutoff
          end
        end

        # Check if a specific attack pattern matches the events in a window.
        #
        # @param window_events [Array<Hash>] events in the correlation window
        # @param pattern [Hash] attack pattern definition
        # @return [Boolean]
        def pattern_matches?(window_events, pattern)
          # Check minimum event count
          return false if window_events.size < pattern[:min_events]

          # Check if events span the required time window
          pattern_window = pattern[:window_seconds]
          return false unless events_within_window?(window_events, pattern_window)

          # Check if required event types are present
          event_types = Set.new(window_events.map { |e| e[:type] })
          required_types = Set.new(pattern[:event_types])

          # At least min_events of the required types must be present
          matching_types = event_types & required_types
          return false if matching_types.empty?

          # Check if events come from the required sources
          event_sources = Set.new(window_events.map { |e| e[:source]&.to_s })
          required_sources = Set.new(pattern[:required_sources])

          # At least one required source must be present
          matching_sources = event_sources & required_sources
          return false if matching_sources.empty?

          # The pattern matches if we have sufficient type coverage
          # and at least some source diversity
          matching_types.size >= 1 && (matching_sources.size >= 1 || event_sources.size >= 2)
        end

        # Check if events fall within a time window.
        def events_within_window?(events, window_seconds)
          return true if events.size <= 1

          timestamps = events.map do |e|
            ts = e[:timestamp]
            ts.is_a?(String) ? (Time.parse(ts).to_f rescue Time.now.to_f) : ts.to_f
          end

          (timestamps.max - timestamps.min) <= window_seconds
        end

        # Check for generic multi-source correlation (events from different monitors
        # occurring together for the same process/session).
        def check_generic_correlation(key, window_events)
          return nil if already_fired?(key, :generic_multi_source)
          return nil if window_events.size < @min_events

          sources = window_events.map { |e| e[:source]&.to_s }.compact.uniq
          return nil if sources.size < 2

          # Check for high-severity events from multiple sources
          high_severity_events = window_events.select do |e|
            sev = e[:severity]
            sev.is_a?(Integer) ? sev >= 3 : %i[high critical].include?(sev&.to_sym)
          end

          return nil if high_severity_events.size < 2

          high_sources = high_severity_events.map { |e| e[:source]&.to_s }.compact.uniq
          return nil if high_sources.size < 2

          mark_fired(key, :generic_multi_source)
          @stats[:correlations_found].increment

          {
            alert_id: SecureRandom.uuid,
            rule_id: "CORR-GENERIC-001",
            rule_name: "Multi-Source Security Event Correlation",
            description: "Multiple high-severity events detected from #{high_sources.size} " \
                        "different monitors within #{@window_seconds}s window",
            severity: :high,
            score: 75,
            mitre_attack: nil,
            tags: %w[correlation multi-source],
            event: window_events.last[:original_event],
            source: "correlation_engine",
            event_type: :correlation_multi_source,
            timestamp: Time.now.utc.iso8601(3),
            hostname: window_events.last.dig(:original_event, :hostname),
            correlated_events: window_events.size,
            correlated_sources: high_sources,
            metadata: {
              correlation_key: key,
              window_seconds: @window_seconds,
              event_count: window_events.size,
              source_count: sources.size
            }
          }
        end

        # Build a correlation alert from a matched pattern.
        def build_correlation_alert(pattern_id, pattern, window_events, key)
          {
            alert_id: SecureRandom.uuid,
            rule_id: "CORR-#{pattern_id.to_s.upcase}",
            rule_name: pattern[:name],
            description: pattern[:description],
            severity: pattern[:severity],
            score: 85,
            mitre_attack: pattern[:mitre_attack],
            tags: ["correlation", pattern_id.to_s],
            event: window_events.last[:original_event],
            source: "correlation_engine",
            event_type: "correlation_#{pattern_id}".to_sym,
            timestamp: Time.now.utc.iso8601(3),
            hostname: window_events.last.dig(:original_event, :hostname),
            correlated_events: window_events.size,
            correlated_sources: window_events.map { |e| e[:source]&.to_s }.compact.uniq,
            metadata: {
              pattern_id: pattern_id,
              correlation_key: key,
              window_seconds: pattern[:window_seconds],
              event_count: window_events.size,
              event_types: window_events.map { |e| e[:type] }.uniq
            }
          }
        end

        # Create a compact summary of event data for correlation tracking.
        def summarize_event_data(data)
          return {} unless data.is_a?(Hash)

          summary = {}
          summary[:pid] = data[:pid] if data[:pid]
          summary[:cmdline] = data[:cmdline]&.slice(0, 100) if data[:cmdline]
          summary[:path] = data[:path] if data[:path]
          summary[:destination] = data[:destination] if data[:destination]
          summary[:severity] = data[:severity] if data[:severity]
          summary
        end

        # Check if a pattern has already fired for a given key.
        def already_fired?(key, pattern_id)
          fire_key = "#{key}:#{pattern_id}"
          fired_at = @fired_patterns[fire_key]
          return false unless fired_at

          # Allow re-firing after the window expires
          (Time.now.to_f - fired_at) < @window_seconds
        end

        # Mark a pattern as fired for a given key.
        def mark_fired(key, pattern_id)
          fire_key = "#{key}:#{pattern_id}"
          @fired_patterns[fire_key] = Time.now.to_f
        end

        # Remove expired windows and fired pattern records.
        def prune_expired_windows
          cutoff = Time.now.to_f - @window_seconds - 60

          @event_windows.each_pair do |key, window|
            # Remove old events from windows
            window[:events].reject! do |evt|
              ts = evt[:timestamp]
              ts_float = ts.is_a?(String) ? (Time.parse(ts).to_f rescue 0) : ts.to_f
              ts_float < cutoff
            end

            # Remove empty windows
            @event_windows.delete(key) if window[:events].empty?
          end

          @fired_patterns.each_pair do |key, fired_at|
            @fired_patterns.delete(key) if fired_at < cutoff
          end
        end
      end
    end
  end
end
