# frozen_string_literal: true

# RubyGuardian Detection Engine - Rule Engine Core
# =================================================
# Central rule evaluation engine that loads detection rules and signatures,
# compiles them for efficient matching, and evaluates incoming security
# events against the full ruleset. Produces alert objects when rules match.

require "yaml"
require "logger"
require "concurrent"
require "securerandom"

require_relative "rule_parser"
require_relative "rule_compiler"
require_relative "condition_evaluator"
require_relative "correlation_engine"

module RubyGuardian
  module Detection
    module RuleEngine
      class Engine
        SEVERITY_ORDER = %i[info low medium high critical].freeze
        DEFAULT_SENSITIVITY_THRESHOLDS = {
          "low"      => 80,
          "medium"   => 60,
          "high"     => 40,
          "paranoid" => 20
        }.freeze

        attr_reader :rules, :stats, :logger

        # @param config [Hash] the "detection" section of detection_config.yml
        # @param logger [Logger]
        def initialize(config:, logger:)
          @config = config || {}
          @logger = logger
          @rules = []
          @compiled_rules = []
          @mutex = Mutex.new
          @stats = Concurrent::Map.new
          reset_stats

          @sensitivity = @config.fetch("sensitivity", "high")
          @score_threshold = DEFAULT_SENSITIVITY_THRESHOLDS.fetch(@sensitivity, 40)

          @parser = RuleParser.new(logger: logger)
          @compiler = RuleCompiler.new(logger: logger)
          @condition_evaluator = ConditionEvaluator.new(
            thresholds: @config.fetch("thresholds", {}),
            logger: logger
          )
          @correlation_engine = CorrelationEngine.new(
            config: @config.fetch("correlation", {}),
            logger: logger
          )

          @false_positive_enabled = @config.dig("false_positive", "enabled") || false
          @whitelisted_tools = @config.dig("false_positive", "whitelisted_tools") || []
          @alert_cooldowns = Concurrent::Map.new
          @cooldown_seconds = @config.dig("false_positive", "alert_cooldown_seconds") || 300
          @dedup_window = @config.dig("false_positive", "dedup_window_seconds") || 60
          @recent_alerts = Concurrent::Map.new

          load_rules
          logger.info("RuleEngine initialized: #{@compiled_rules.size} compiled rules, " \
                      "sensitivity=#{@sensitivity}, threshold=#{@score_threshold}")
        end

        # Evaluate a single event against all compiled rules.
        # Returns an array of alert hashes for every rule that matched.
        #
        # @param event [Hash] enriched event from EventCollector
        # @return [Array<Hash>] alert objects
        def evaluate(event)
          return [] unless event.is_a?(Hash)

          increment_stat(:events_evaluated)
          alerts = []

          @compiled_rules.each do |compiled_rule|
            next unless event_matches_source?(event, compiled_rule)

            score = @condition_evaluator.evaluate(event, compiled_rule)
            next unless score && score >= @score_threshold

            severity = determine_severity(compiled_rule, score)
            next if suppressed?(compiled_rule, event)

            alert = build_alert(compiled_rule, event, score, severity)
            alerts << alert

            record_alert(compiled_rule, alert)
            increment_stat(:alerts_generated)
            @logger.info("Rule matched: #{compiled_rule[:id]} " \
                         "(score=#{score}, severity=#{severity}) for event #{event[:type]}")
          end

          # Feed the event to the correlation engine for cross-monitor patterns
          correlation_alerts = @correlation_engine.process_event(event)
          correlation_alerts.each do |corr_alert|
            increment_stat(:correlation_alerts)
            alerts << corr_alert
          end

          increment_stat(:events_with_alerts) unless alerts.empty?
          alerts
        rescue StandardError => e
          @logger.error("RuleEngine evaluation error: #{e.class}: #{e.message}")
          @logger.debug(e.backtrace&.first(10)&.join("\n"))
          increment_stat(:evaluation_errors)
          []
        end

        # Reload rules from disk (called on SIGHUP)
        def reload_rules
          @logger.info("Reloading detection rules")
          @mutex.synchronize do
            @rules.clear
            @compiled_rules.clear
            load_rules
          end
          @logger.info("Rules reloaded: #{@compiled_rules.size} compiled rules")
        end

        # Return current statistics
        def statistics
          @stats.each_pair.to_h
        end

        private

        def reset_stats
          %i[events_evaluated alerts_generated correlation_alerts
             events_with_alerts evaluation_errors rules_loaded
             suppressed_alerts].each do |key|
            @stats[key] = Concurrent::AtomicFixnum.new(0)
          end
        end

        def increment_stat(key)
          @stats[key]&.increment
        end

        # Load all rule/signature YAML files from configured directories
        def load_rules
          signature_dirs = @config.fetch("signature_dirs", [])
          signature_dirs.each do |dir|
            full_path = resolve_signature_path(dir)
            unless File.directory?(full_path)
              @logger.warn("Signature directory not found: #{full_path}")
              next
            end

            Dir.glob(File.join(full_path, "**", "*.yml")).sort.each do |file|
              load_rule_file(file)
            end
          end

          @logger.info("Loaded #{@rules.size} rules from #{signature_dirs.size} directories")
          compile_all_rules
        end

        def resolve_signature_path(dir)
          if dir.start_with?("/")
            dir
          else
            File.expand_path(File.join("..", "..", dir), __dir__)
          end
        end

        def load_rule_file(file)
          parsed_rules = @parser.parse_file(file)
          parsed_rules.each do |rule|
            @rules << rule
            @logger.debug("Loaded rule: #{rule[:id]} - #{rule[:name]}")
          end
          increment_stat(:rules_loaded)
        rescue StandardError => e
          @logger.error("Failed to load rule file #{file}: #{e.message}")
        end

        def compile_all_rules
          @compiled_rules = @rules.map { |rule| @compiler.compile(rule) }.compact
          @logger.info("Compiled #{@compiled_rules.size} of #{@rules.size} rules")
        end

        # Check if the event source type is relevant to the rule
        def event_matches_source?(event, compiled_rule)
          rule_sources = compiled_rule[:applicable_sources]
          return true if rule_sources.nil? || rule_sources.empty?

          event_source = event[:source]&.to_s
          rule_sources.any? { |src| event_source&.include?(src) }
        end

        def determine_severity(compiled_rule, score)
          base_severity = compiled_rule[:severity] || :medium

          # Escalate severity if score is very high
          if score >= 90 && severity_index(base_severity) < severity_index(:critical)
            escalated = SEVERITY_ORDER[[severity_index(base_severity) + 1, 4].min]
            @logger.debug("Severity escalated from #{base_severity} to #{escalated} (score=#{score})")
            return escalated
          end

          base_severity
        end

        def severity_index(severity)
          SEVERITY_ORDER.index(severity.to_sym) || 2
        end

        def suppressed?(compiled_rule, event)
          return false unless @false_positive_enabled

          rule_id = compiled_rule[:id]

          # Check whitelisted tools
          cmdline = event.dig(:data, :cmdline) || ""
          if @whitelisted_tools.any? { |tool| cmdline.include?(tool) }
            increment_stat(:suppressed_alerts)
            return true
          end

          # Check cooldown
          last_alert_time = @alert_cooldowns[rule_id]
          if last_alert_time && (Time.now.to_f - last_alert_time) < @cooldown_seconds
            increment_stat(:suppressed_alerts)
            return true
          end

          # Check dedup window
          dedup_key = "#{rule_id}:#{event[:type]}:#{event.dig(:data, :pid)}"
          last_dedup = @recent_alerts[dedup_key]
          if last_dedup && (Time.now.to_f - last_dedup) < @dedup_window
            increment_stat(:suppressed_alerts)
            return true
          end

          false
        end

        def build_alert(compiled_rule, event, score, severity)
          {
            alert_id: SecureRandom.uuid,
            rule_id: compiled_rule[:id],
            rule_name: compiled_rule[:name],
            description: compiled_rule[:description],
            severity: severity,
            score: score,
            mitre_attack: compiled_rule[:mitre_attack],
            tags: compiled_rule[:tags] || [],
            event: event,
            source: event[:source],
            event_type: event[:type],
            timestamp: Time.now.utc.iso8601(3),
            hostname: event[:hostname],
            agent_version: event[:agent_version],
            metadata: {
              sensitivity: @sensitivity,
              score_threshold: @score_threshold,
              rule_count: @compiled_rules.size
            }
          }
        end

        def record_alert(compiled_rule, alert)
          rule_id = compiled_rule[:id]
          @alert_cooldowns[rule_id] = Time.now.to_f

          dedup_key = "#{rule_id}:#{alert[:event_type]}:#{alert.dig(:event, :data, :pid)}"
          @recent_alerts[dedup_key] = Time.now.to_f

          # Prune old entries from recent_alerts map periodically
          prune_recent_alerts if rand < 0.05
        end

        def prune_recent_alerts
          cutoff = Time.now.to_f - @dedup_window
          @recent_alerts.each_pair do |key, timestamp|
            @recent_alerts.delete(key) if timestamp < cutoff
          end
        end
      end
    end
  end
end
