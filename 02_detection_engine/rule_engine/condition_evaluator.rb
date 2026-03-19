# frozen_string_literal: true

# RubyGuardian Detection Engine - Condition Evaluator
# ====================================================
# Evaluates compiled rule conditions against incoming security events.
# Implements matcher dispatch, scoring logic, threshold tracking, and
# pre-filter fast-path rejection for efficient rule evaluation.

require "concurrent"
require "set"

module RubyGuardian
  module Detection
    module RuleEngine
      class ConditionEvaluator
        # Maximum age (seconds) for threshold tracking buckets before pruning
        THRESHOLD_BUCKET_TTL = 600
        # How often to prune stale threshold buckets (in evaluation cycles)
        PRUNE_INTERVAL = 200

        attr_reader :logger

        def initialize(thresholds:, logger:)
          @thresholds = thresholds || {}
          @logger = logger
          @threshold_buckets = Concurrent::Map.new
          @evaluation_count = Concurrent::AtomicFixnum.new(0)
          @sequence_tracker = Concurrent::Map.new
        end

        # Evaluate an event against a compiled rule and return a numeric score.
        # Returns nil if the event does not match (pre-filter rejection or
        # no matchers fire), otherwise returns the aggregate match score.
        #
        # @param event [Hash] enriched event from EventCollector
        # @param compiled_rule [Hash] compiled rule from RuleCompiler
        # @return [Integer, nil] match score or nil
        def evaluate(event, compiled_rule)
          return nil unless event.is_a?(Hash) && compiled_rule.is_a?(Hash)

          @evaluation_count.increment
          prune_stale_data if (@evaluation_count.value % PRUNE_INTERVAL).zero?

          # Fast-path: pre-filter rejection
          return nil unless passes_pre_filters?(event, compiled_rule[:pre_filters])

          matchers = compiled_rule[:matchers]
          return nil if matchers.nil? || matchers.empty?

          total_score = 0
          matched_count = 0
          total_weight = matchers.sum { |m| m[:weight] || 1 }

          matchers.each do |matcher|
            match_result = evaluate_matcher(event, matcher)
            next unless match_result

            weight = matcher[:weight] || 1
            matched_count += 1
            # Weighted contribution: (base_score * weight_fraction * match_confidence)
            contribution = compiled_rule[:score] * (weight.to_f / total_weight) * match_result
            total_score += contribution.to_i
          end

          return nil if matched_count.zero?

          # Apply threshold check if the rule has threshold configuration
          if compiled_rule[:threshold]
            return nil unless threshold_met?(event, compiled_rule)
          end

          # Ensure score is capped at 100
          [total_score, 100].min
        end

        # Reset all tracked state (useful for testing or reload)
        def reset!
          @threshold_buckets = Concurrent::Map.new
          @sequence_tracker = Concurrent::Map.new
          @evaluation_count = Concurrent::AtomicFixnum.new(0)
        end

        private

        # Check pre-filters for fast event rejection.
        #
        # @param event [Hash]
        # @param pre_filters [Hash, nil]
        # @return [Boolean]
        def passes_pre_filters?(event, pre_filters)
          return true if pre_filters.nil? || pre_filters.empty?

          # Check required event types
          if pre_filters[:required_event_types]
            event_type = event[:type]
            return true if pre_filters[:required_event_types].empty?
            # Allow if any required type partially matches event type
            matches_any = pre_filters[:required_event_types].any? do |req_type|
              event_type.to_s.include?(req_type.to_s)
            end
            return false unless matches_any
          end

          # Check minimum call depth
          if pre_filters[:min_call_depth]
            depth = event.dig(:data, :call_depth) || 0
            return false if depth < pre_filters[:min_call_depth]
          end

          true
        end

        # Dispatch to the appropriate matcher evaluation method.
        #
        # @param event [Hash]
        # @param matcher [Hash] compiled matcher
        # @return [Float, nil] confidence value 0.0-1.0 or nil if no match
        def evaluate_matcher(event, matcher)
          case matcher[:check]
          when :check_method_called
            check_method_called(event, matcher)
          when :check_class_used
            check_class_used(event, matcher)
          when :check_api_pattern
            check_api_pattern(event, matcher)
          when :check_call_sequence
            check_call_sequence(event, matcher)
          when :check_call_chain
            check_call_chain(event, matcher)
          when :check_argument_pattern
            check_argument_pattern(event, matcher)
          when :check_syscall_sequence
            check_syscall_sequence(event, matcher)
          when :check_filesystem_path
            check_filesystem_path(event, matcher)
          when :check_filesystem_extension
            check_filesystem_extension(event, matcher)
          when :check_network_destination
            check_network_destination(event, matcher)
          when :check_network_connection
            check_network_connection(event, matcher)
          when :check_network_dns
            check_network_dns(event, matcher)
          when :check_network_http
            check_network_http(event, matcher)
          when :check_string_patterns
            check_string_patterns(event, matcher)
          else
            @logger.debug("ConditionEvaluator: unknown matcher check #{matcher[:check]}")
            nil
          end
        rescue StandardError => e
          @logger.debug("ConditionEvaluator: matcher error: #{e.message}")
          nil
        end

        # --- Individual matcher implementations ---

        # Check if the event involves a method call matching the rule's method set.
        def check_method_called(event, matcher)
          method_name = event.dig(:data, :method_called) ||
                        event.dig(:data, :method) ||
                        event.dig(:data, :cmdline)
          return nil unless method_name

          method_str = method_name.to_s
          return 1.0 if matcher[:method_set].any? { |m| method_str.include?(m) }

          nil
        end

        # Check if the event involves a class matching the rule's class set.
        def check_class_used(event, matcher)
          class_name = event.dig(:data, :class_name) ||
                       event.dig(:data, :target_class) ||
                       event.dig(:data, :object_class)
          return nil unless class_name

          class_str = class_name.to_s
          return 1.0 if matcher[:class_set].any? { |c| class_str.include?(c) }

          nil
        end

        # Check if event data matches any of the compiled regex patterns.
        def check_api_pattern(event, matcher)
          searchable = build_searchable_string(event)
          return nil if searchable.empty?

          matched = matcher[:patterns].count { |pat| pat.match?(searchable) }
          return nil if matched.zero?

          # Confidence increases with more pattern matches
          [matched.to_f / matcher[:patterns].size, 1.0].min
        end

        # Check if event is part of a tracked call sequence.
        def check_call_sequence(event, matcher)
          pid = event.dig(:data, :pid) || event[:pid] || "unknown"
          sequence_key = "#{pid}:#{matcher[:sequence].hash}"

          tracker = @sequence_tracker.compute_if_absent(sequence_key) do
            { events: [], last_update: Time.now.to_f }
          end

          method_name = event.dig(:data, :method_called) ||
                        event.dig(:data, :method) || ""

          # Check if this event matches the next expected item in sequence
          expected_index = tracker[:events].size
          expected_method = matcher[:sequence][expected_index]

          if expected_method && method_name.to_s.include?(expected_method.to_s)
            tracker[:events] << { method: method_name, time: Time.now.to_f }
            tracker[:last_update] = Time.now.to_f

            # Check if the full sequence is complete
            if tracker[:events].size >= matcher[:sequence].size
              window = matcher[:window_ms] / 1000.0
              time_span = tracker[:events].last[:time] - tracker[:events].first[:time]

              if time_span <= window
                @sequence_tracker.delete(sequence_key)
                return 1.0
              else
                # Sequence too spread out; reset
                tracker[:events].clear
              end
            end
          else
            # Check if this event matches the first item (reset sequence)
            first_method = matcher[:sequence].first
            if first_method && method_name.to_s.include?(first_method.to_s)
              tracker[:events] = [{ method: method_name, time: Time.now.to_f }]
              tracker[:last_update] = Time.now.to_f
            end
          end

          nil
        end

        # Check if the event's call chain matches the pattern.
        def check_call_chain(event, matcher)
          call_chain = event.dig(:data, :call_chain) ||
                       event.dig(:data, :backtrace)
          return nil unless call_chain

          chain_str = Array(call_chain).join(" -> ")
          matcher[:pattern].match?(chain_str) ? 0.8 : nil
        end

        # Check if event arguments match the pattern.
        def check_argument_pattern(event, matcher)
          args = event.dig(:data, :arguments) ||
                 event.dig(:data, :args) ||
                 event.dig(:data, :cmdline) || ""
          args_str = Array(args).join(" ")

          matcher[:pattern].match?(args_str) ? 0.9 : nil
        end

        # Check if the event is part of a syscall sequence.
        def check_syscall_sequence(event, matcher)
          syscall_name = event.dig(:data, :syscall) ||
                         event.dig(:data, :syscall_name)
          return nil unless syscall_name

          return nil unless matcher[:syscall_set].include?(syscall_name.to_s)

          pid = event.dig(:data, :pid) || "unknown"
          seq_key = "syscall:#{pid}:#{matcher[:syscall_set].hash}"

          tracker = @sequence_tracker.compute_if_absent(seq_key) do
            { syscalls: [], last_update: Time.now.to_f }
          end

          tracker[:syscalls] << { name: syscall_name.to_s, time: Time.now.to_f }
          tracker[:last_update] = Time.now.to_f

          # Prune old entries outside the window
          window = matcher[:window_ms] / 1000.0
          cutoff = Time.now.to_f - window
          tracker[:syscalls].reject! { |s| s[:time] < cutoff }

          observed_set = Set.new(tracker[:syscalls].map { |s| s[:name] })

          if matcher[:ordered]
            # Check if observed syscalls appear in the expected order
            observed_list = tracker[:syscalls].map { |s| s[:name] }
            expected = matcher[:expected_sequence]
            idx = 0
            observed_list.each do |s|
              idx += 1 if s == expected[idx]
              if idx >= expected.size
                @sequence_tracker.delete(seq_key)
                return 1.0
              end
            end
          else
            # Unordered: just check all required syscalls have been seen
            if matcher[:syscall_set].subset?(observed_set)
              @sequence_tracker.delete(seq_key)
              return 1.0
            end
          end

          # Partial match - return partial confidence
          coverage = (observed_set & matcher[:syscall_set]).size.to_f / matcher[:syscall_set].size
          coverage >= 0.5 ? coverage * 0.5 : nil
        end

        # Check if event filesystem path matches the pattern.
        def check_filesystem_path(event, matcher)
          path = event.dig(:data, :path) ||
                 event.dig(:data, :file_path) ||
                 event.dig(:data, :target)
          return nil unless path

          return nil if matcher[:operation] && event.dig(:data, :operation)&.to_s != matcher[:operation].to_s

          matcher[:pattern].match?(path.to_s) ? 0.9 : nil
        end

        # Check if event file extension is in the suspicious set.
        def check_filesystem_extension(event, matcher)
          path = event.dig(:data, :path) ||
                 event.dig(:data, :file_path)
          return nil unless path

          ext = File.extname(path.to_s).downcase
          matcher[:extension_set].include?(ext) ? 0.6 : nil
        end

        # Check if network destination matches the pattern.
        def check_network_destination(event, matcher)
          dest = event.dig(:data, :destination) ||
                 event.dig(:data, :remote_addr) ||
                 event.dig(:data, :host)
          return nil unless dest

          matcher[:pattern].match?(dest.to_s) ? 0.9 : nil
        end

        # Check if network connection pattern matches.
        def check_network_connection(event, matcher)
          conn_info = [
            event.dig(:data, :remote_addr),
            event.dig(:data, :remote_port),
            event.dig(:data, :protocol)
          ].compact.join(":")

          return nil if conn_info.empty?

          matcher[:pattern].match?(conn_info) ? 0.8 : nil
        end

        # Check DNS-related network indicators.
        def check_network_dns(event, matcher)
          query = event.dig(:data, :dns_query) ||
                  event.dig(:data, :query_name)
          return nil unless query

          query_str = query.to_s
          # Check for unusually long DNS queries (potential tunneling)
          if matcher[:dns_config].is_a?(Hash)
            max_length = matcher[:dns_config]["max_query_length"] || 50
            return 0.7 if query_str.length > max_length
          end

          # Check for high entropy (encoded data in DNS)
          entropy = calculate_entropy(query_str)
          return 0.8 if entropy > 4.0

          nil
        end

        # Check HTTP-related network indicators.
        def check_network_http(event, matcher)
          url = event.dig(:data, :url) ||
                event.dig(:data, :request_url)
          method = event.dig(:data, :http_method) ||
                   event.dig(:data, :method)
          return nil unless url || method

          searchable = "#{method} #{url}"
          if matcher[:http_config].is_a?(Hash)
            patterns = Array(matcher[:http_config]["suspicious_patterns"])
            patterns.each do |pat|
              regex = Regexp.new(pat, Regexp::IGNORECASE) rescue next
              return 0.8 if regex.match?(searchable)
            end
          end

          nil
        end

        # Check if event data matches any string patterns.
        def check_string_patterns(event, matcher)
          searchable = build_searchable_string(event)
          return nil if searchable.empty?

          matched = matcher[:patterns].count { |pat| pat.match?(searchable) }
          return nil if matched.zero?

          [matched.to_f / matcher[:patterns].size, 1.0].min
        end

        # --- Threshold tracking ---

        # Check if the threshold condition is met for this rule/event combination.
        #
        # @param event [Hash]
        # @param compiled_rule [Hash]
        # @return [Boolean]
        def threshold_met?(event, compiled_rule)
          threshold = compiled_rule[:threshold]
          return true unless threshold

          key_parts = threshold[:bucket_key_fields].map { |f| event[f]&.to_s || "" }
          bucket_key = "#{compiled_rule[:id]}:#{key_parts.join(':')}"

          bucket = @threshold_buckets.compute_if_absent(bucket_key) do
            { hits: [], window: threshold[:window_seconds] }
          end

          now = Time.now.to_f
          bucket[:hits] << now

          # Prune hits outside the window
          cutoff = now - threshold[:window_seconds]
          bucket[:hits].reject! { |t| t < cutoff }

          bucket[:hits].size >= threshold[:count]
        end

        # --- Utility methods ---

        # Build a single searchable string from all interesting event fields.
        def build_searchable_string(event)
          parts = []
          data = event[:data] || {}

          parts << data[:cmdline].to_s if data[:cmdline]
          parts << data[:method_called].to_s if data[:method_called]
          parts << data[:method].to_s if data[:method]
          parts << data[:arguments].to_s if data[:arguments]
          parts << data[:path].to_s if data[:path]
          parts << data[:target].to_s if data[:target]
          parts << data[:destination].to_s if data[:destination]
          parts << data[:class_name].to_s if data[:class_name]

          parts.join(" ")
        end

        # Calculate Shannon entropy of a string (useful for detecting encoded data).
        def calculate_entropy(string)
          return 0.0 if string.nil? || string.empty?

          freq = Hash.new(0)
          string.each_char { |c| freq[c] += 1 }
          len = string.length.to_f

          freq.values.sum do |count|
            p = count / len
            -p * Math.log2(p)
          end
        end

        # Remove stale data from threshold buckets and sequence trackers.
        def prune_stale_data
          now = Time.now.to_f
          cutoff = now - THRESHOLD_BUCKET_TTL

          @threshold_buckets.each_pair do |key, bucket|
            bucket[:hits]&.reject! { |t| t < cutoff }
            @threshold_buckets.delete(key) if bucket[:hits]&.empty?
          end

          @sequence_tracker.each_pair do |key, tracker|
            @sequence_tracker.delete(key) if tracker[:last_update] < cutoff
          end
        end
      end
    end
  end
end
