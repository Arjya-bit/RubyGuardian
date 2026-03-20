# frozen_string_literal: true

require 'securerandom'
require 'time'

module RubyGuardian
  module DetectionEngine
    module RuleEngine
      # Correlates multiple events within configurable time windows to detect
      # multi-stage attack chains. Supports temporal ordering, threshold-based
      # correlation, and grouping by key fields (e.g., source IP, user).
      class CorrelationEngine
        DEFAULT_WINDOW  = 300   # 5 minutes
        MAX_WINDOW      = 86_400 # 24 hours
        CLEANUP_INTERVAL = 60   # seconds

        attr_reader :correlation_rules, :stats

        def initialize(options = {})
          @default_window   = options.fetch(:default_window, DEFAULT_WINDOW)
          @max_window        = options.fetch(:max_window, MAX_WINDOW)
          @max_events_per_group = options.fetch(:max_events_per_group, 10_000)
          @correlation_rules = {}
          @event_store       = {}  # group_key => [timestamped events]
          @active_chains     = {}  # chain_id => CorrelationChain
          @mutex             = Mutex.new
          @stats = { events_processed: 0, chains_started: 0, chains_completed: 0,
                     chains_expired: 0, cleanups: 0 }
          @last_cleanup      = Time.now
        end

        # Register a correlation rule that defines a multi-stage detection pattern.
        #
        # @param rule [Hash] correlation rule definition
        #   - :id [String] unique rule identifier
        #   - :name [String] human-readable name
        #   - :stages [Array<Hash>] ordered stages with rule_id references
        #   - :group_by [Array<String>] fields to group correlated events
        #   - :window [Integer] time window in seconds
        #   - :threshold [Integer] minimum occurrences (optional)
        #   - :ordered [Boolean] whether stages must occur in order
        def register_rule(rule)
          validate_correlation_rule!(rule)

          @mutex.synchronize do
            @correlation_rules[rule[:id]] = {
              id:        rule[:id],
              name:      rule[:name],
              stages:    rule[:stages],
              group_by:  Array(rule[:group_by]),
              window:    [rule.fetch(:window, @default_window), @max_window].min,
              threshold: rule.fetch(:threshold, nil),
              ordered:   rule.fetch(:ordered, true),
              severity:  rule.fetch(:severity, 'high'),
              mitre_attack: rule.fetch(:mitre_attack, {})
            }
          end
        end

        # Process an evaluation result and check for correlation matches.
        #
        # @param eval_result [EvaluationResult] result from ConditionEvaluator
        # @param event [Hash] the original event data
        # @return [Array<CorrelationMatch>] completed correlation matches
        def process(eval_result, event)
          return [] unless eval_result.matched

          @stats[:events_processed] += 1
          cleanup_expired if cleanup_due?

          matches = []

          @mutex.synchronize do
            @correlation_rules.each_value do |corr_rule|
              stage_index = find_stage_index(corr_rule, eval_result.rule_id)
              next unless stage_index

              group_key = build_group_key(corr_rule, event)
              store_event(group_key, eval_result, event, stage_index)

              match = check_correlation(corr_rule, group_key)
              if match
                matches << match
                clear_group(group_key, corr_rule[:id])
              end
            end
          end

          matches
        end

        # Manually trigger cleanup of expired correlation windows.
        #
        # @return [Integer] number of expired entries cleaned
        def cleanup_expired
          expired_count = 0
          now = Time.now

          @mutex.synchronize do
            @event_store.each do |group_key, events|
              before_size = events.size
              events.reject! { |e| (now - e[:timestamp]) > resolve_window(group_key) }
              expired_count += (before_size - events.size)
              @event_store.delete(group_key) if events.empty?
            end

            @active_chains.each do |chain_id, chain|
              if (now - chain[:started_at]) > chain[:window]
                @active_chains.delete(chain_id)
                @stats[:chains_expired] += 1
              end
            end

            @stats[:cleanups] += 1
            @last_cleanup = now
          end

          expired_count
        end

        # Get current status of active correlation chains.
        #
        # @return [Array<Hash>] active chain summaries
        def active_chain_status
          @mutex.synchronize do
            @active_chains.map do |id, chain|
              {
                chain_id:     id,
                rule_id:      chain[:rule_id],
                group_key:    chain[:group_key],
                stages_seen:  chain[:stages_seen].to_a,
                started_at:   chain[:started_at],
                event_count:  chain[:events].size
              }
            end
          end
        end

        private

        def validate_correlation_rule!(rule)
          raise ArgumentError, 'Correlation rule must have :id' unless rule[:id]
          raise ArgumentError, 'Correlation rule must have :stages' unless rule[:stages]
          raise ArgumentError, 'Correlation rule must have at least 2 stages' if rule[:stages].size < 2

          rule[:stages].each_with_index do |stage, idx|
            unless stage[:rule_id]
              raise ArgumentError, "Stage #{idx} must reference a :rule_id"
            end
          end
        end

        def find_stage_index(corr_rule, rule_id)
          corr_rule[:stages].index { |s| s[:rule_id] == rule_id }
        end

        def build_group_key(corr_rule, event)
          parts = [corr_rule[:id]]
          corr_rule[:group_by].each do |field|
            value = resolve_field(field, event)
            parts << "#{field}=#{value}"
          end
          parts.join('|')
        end

        def store_event(group_key, eval_result, event, stage_index)
          @event_store[group_key] ||= []
          store = @event_store[group_key]

          if store.size >= @max_events_per_group
            store.shift  # Drop oldest
          end

          store << {
            timestamp:   event[:timestamp] || Time.now,
            rule_id:     eval_result.rule_id,
            stage_index: stage_index,
            severity:    eval_result.severity,
            event:       event
          }
        end

        def check_correlation(corr_rule, group_key)
          events = @event_store[group_key]
          return nil unless events && events.size >= corr_rule[:stages].size

          window_start = Time.now - corr_rule[:window]
          in_window = events.select { |e| e[:timestamp] >= window_start }

          stages_seen = in_window.map { |e| e[:stage_index] }.uniq.sort
          required = (0...corr_rule[:stages].size).to_a

          return nil unless (required - stages_seen).empty?

          # Check ordering if required
          if corr_rule[:ordered]
            return nil unless stages_in_order?(in_window, required)
          end

          # Check threshold if specified
          if corr_rule[:threshold]
            return nil unless in_window.size >= corr_rule[:threshold]
          end

          @stats[:chains_completed] += 1

          CorrelationMatch.new(
            id:             SecureRandom.uuid,
            correlation_rule_id: corr_rule[:id],
            correlation_rule_name: corr_rule[:name],
            severity:       corr_rule[:severity],
            group_key:      group_key,
            matched_events: in_window,
            matched_at:     Time.now,
            mitre_attack:   corr_rule[:mitre_attack]
          )
        end

        def stages_in_order?(events, required_stages)
          last_time = {}
          events.sort_by { |e| e[:timestamp] }.each do |e|
            last_time[e[:stage_index]] = e[:timestamp]
          end

          required_stages.each_cons(2).all? do |a, b|
            last_time[a] && last_time[b] && last_time[a] <= last_time[b]
          end
        end

        def clear_group(group_key, corr_rule_id)
          @event_store.delete(group_key)
          @active_chains.delete_if { |_, v| v[:group_key] == group_key && v[:rule_id] == corr_rule_id }
        end

        def resolve_field(field_path, event)
          parts = field_path.to_s.split('.')
          current = event
          parts.each do |part|
            return nil unless current.is_a?(Hash)
            current = current[part] || current[part.to_sym]
          end
          current
        end

        def resolve_window(group_key)
          corr_rule_id = group_key.split('|').first
          rule = @correlation_rules[corr_rule_id]
          rule ? rule[:window] : @default_window
        end

        def cleanup_due?
          (Time.now - @last_cleanup) >= CLEANUP_INTERVAL
        end
      end

      # Represents a completed correlation match.
      CorrelationMatch = Struct.new(:id, :correlation_rule_id, :correlation_rule_name,
                                     :severity, :group_key, :matched_events,
                                     :matched_at, :mitre_attack,
                                     keyword_init: true)
    end
  end
end
