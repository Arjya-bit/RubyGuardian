# frozen_string_literal: true

# RubyGuardian Detection Engine - Rule Compiler
# ==============================================
# Compiles parsed detection rules into optimized internal representations
# for efficient runtime evaluation. Pre-compiles regex patterns, builds
# lookup tables, and creates fast-path matchers for common indicator types.

require "set"

module RubyGuardian
  module Detection
    module RuleEngine
      class RuleCompiler
        # Compiled rule structure keys
        COMPILED_KEYS = %i[
          id name description severity score mitre_attack tags
          applicable_sources enabled source_file
          matchers threshold pre_filters
        ].freeze

        attr_reader :logger, :stats

        def initialize(logger:)
          @logger = logger
          @stats = { compiled: 0, skipped: 0, errors: 0 }
        end

        # Compile a single parsed rule into an optimized evaluation structure.
        #
        # @param rule [Hash] parsed rule from RuleParser
        # @return [Hash, nil] compiled rule or nil if compilation fails
        def compile(rule)
          return nil unless rule.is_a?(Hash)
          return nil unless rule[:enabled] != false

          compiled = {
            id: rule[:id],
            name: rule[:name],
            description: rule[:description],
            severity: rule[:severity],
            score: rule[:score] || 50,
            mitre_attack: rule[:mitre_attack],
            tags: Array(rule[:tags]),
            source_file: rule[:source_file],
            enabled: true,
            applicable_sources: determine_applicable_sources(rule[:indicators]),
            matchers: compile_matchers(rule[:indicators]),
            threshold: compile_threshold(rule[:threshold]),
            pre_filters: build_pre_filters(rule[:indicators])
          }

          @stats[:compiled] += 1
          @logger.debug("RuleCompiler: compiled rule #{compiled[:id]}")
          compiled
        rescue StandardError => e
          @stats[:errors] += 1
          @logger.error("RuleCompiler: failed to compile rule #{rule[:id]}: #{e.message}")
          nil
        end

        # Compile an array of rules, returning only successfully compiled ones.
        #
        # @param rules [Array<Hash>] parsed rules
        # @return [Array<Hash>] compiled rules
        def compile_all(rules)
          rules.filter_map { |rule| compile(rule) }
        end

        # Return compilation statistics
        def compilation_stats
          @stats.dup
        end

        private

        # Determine which event sources (monitors) a rule applies to
        # based on the indicator types it contains.
        #
        # @param indicators [Hash] indicator section from parsed rule
        # @return [Array<String>] list of applicable source names
        def determine_applicable_sources(indicators)
          return [] unless indicators.is_a?(Hash)

          sources = Set.new

          sources.add("process_monitor") if indicators[:ruby_api]
          sources.add("process_monitor") if indicators[:string_patterns]
          sources.add("syscall_tracer") if indicators[:syscall_sequence]
          sources.add("file_monitor") if indicators[:filesystem]
          sources.add("network_monitor") if indicators[:network]
          sources.add("memory_inspector") if indicators.key?(:memory)
          sources.add("objectspace_scanner") if indicators.key?(:objectspace)

          # If no specific sources identified, apply to all
          sources.to_a
        end

        # Compile indicator matchers into efficient evaluation structures.
        # Each matcher is a hash with :type, :check, and optional :weight.
        #
        # @param indicators [Hash] indicator section from parsed rule
        # @return [Array<Hash>] compiled matchers
        def compile_matchers(indicators)
          return [] unless indicators.is_a?(Hash)

          matchers = []

          matchers.concat(compile_ruby_api_matchers(indicators[:ruby_api])) if indicators[:ruby_api]
          matchers.concat(compile_syscall_matchers(indicators[:syscall_sequence])) if indicators[:syscall_sequence]
          matchers.concat(compile_filesystem_matchers(indicators[:filesystem])) if indicators[:filesystem]
          matchers.concat(compile_network_matchers(indicators[:network])) if indicators[:network]
          matchers.concat(compile_string_pattern_matchers(indicators[:string_patterns])) if indicators[:string_patterns]

          matchers
        end

        # Compile Ruby API indicator matchers with pre-compiled regex patterns.
        #
        # @param api_indicators [Hash] ruby_api section from indicators
        # @return [Array<Hash>] compiled matchers
        def compile_ruby_api_matchers(api_indicators)
          return [] unless api_indicators.is_a?(Hash)

          matchers = []

          # Method call matchers
          if api_indicators[:methods_called]&.any?
            method_set = Set.new(api_indicators[:methods_called].map(&:to_s))
            matchers << {
              type: :ruby_api_method,
              method_set: method_set,
              weight: 30,
              check: :check_method_called
            }
          end

          # Class usage matchers
          if api_indicators[:classes_used]&.any?
            class_set = Set.new(api_indicators[:classes_used].map(&:to_s))
            matchers << {
              type: :ruby_api_class,
              class_set: class_set,
              weight: 25,
              check: :check_class_used
            }
          end

          # Argument pattern matchers (pre-compile regexes)
          if api_indicators[:patterns]&.any?
            compiled_patterns = api_indicators[:patterns].filter_map do |pattern|
              Regexp.new(pattern, Regexp::IGNORECASE)
            rescue RegexpError => e
              @logger.warn("RuleCompiler: invalid regex pattern '#{pattern}': #{e.message}")
              nil
            end

            unless compiled_patterns.empty?
              matchers << {
                type: :ruby_api_pattern,
                patterns: compiled_patterns,
                weight: 35,
                check: :check_api_pattern
              }
            end
          end

          # Call sequence matchers
          if api_indicators[:call_sequence]&.any?
            matchers << {
              type: :ruby_api_sequence,
              sequence: api_indicators[:call_sequence],
              window_ms: api_indicators[:window_ms] || 5000,
              weight: 40,
              check: :check_call_sequence
            }
          end

          # Call chain contains matcher
          if api_indicators[:call_chain_contains]
            chain_pattern = compile_safe_regex(api_indicators[:call_chain_contains])
            if chain_pattern
              matchers << {
                type: :ruby_api_call_chain,
                pattern: chain_pattern,
                weight: 30,
                check: :check_call_chain
              }
            end
          end

          # Argument pattern matchers from raw argument_pattern field
          if api_indicators[:argument_pattern]
            arg_pattern = compile_safe_regex(api_indicators[:argument_pattern])
            if arg_pattern
              matchers << {
                type: :ruby_api_argument,
                pattern: arg_pattern,
                weight: 35,
                check: :check_argument_pattern
              }
            end
          end

          matchers
        end

        # Compile syscall sequence matchers with ordering constraints.
        #
        # @param syscall_indicators [Hash] syscall_sequence section
        # @return [Array<Hash>] compiled matchers
        def compile_syscall_matchers(syscall_indicators)
          return [] unless syscall_indicators.is_a?(Hash)

          syscalls = Array(syscall_indicators[:syscalls])
          return [] if syscalls.empty?

          syscall_set = Set.new(syscalls.map(&:to_s))

          [{
            type: :syscall_sequence,
            syscall_set: syscall_set,
            ordered: syscall_indicators.fetch(:ordered, false),
            expected_sequence: syscalls,
            window_ms: syscall_indicators[:window_ms] || 5000,
            weight: 40,
            check: :check_syscall_sequence
          }]
        end

        # Compile filesystem indicator matchers.
        #
        # @param fs_indicators [Hash] filesystem section
        # @return [Array<Hash>] compiled matchers
        def compile_filesystem_matchers(fs_indicators)
          return [] unless fs_indicators.is_a?(Hash)

          matchers = []

          if fs_indicators[:path_pattern]
            path_regex = compile_safe_regex(fs_indicators[:path_pattern])
            if path_regex
              matchers << {
                type: :filesystem_path,
                pattern: path_regex,
                operation: fs_indicators[:operation],
                weight: 25,
                check: :check_filesystem_path
              }
            end
          end

          if fs_indicators[:suspicious_extensions]&.any?
            ext_set = Set.new(fs_indicators[:suspicious_extensions].map { |e| e.to_s.downcase })
            matchers << {
              type: :filesystem_extension,
              extension_set: ext_set,
              weight: 15,
              check: :check_filesystem_extension
            }
          end

          matchers
        end

        # Compile network indicator matchers.
        #
        # @param net_indicators [Hash] network section
        # @return [Array<Hash>] compiled matchers
        def compile_network_matchers(net_indicators)
          return [] unless net_indicators.is_a?(Hash)

          matchers = []

          if net_indicators[:destination_pattern]
            dest_regex = compile_safe_regex(net_indicators[:destination_pattern])
            if dest_regex
              matchers << {
                type: :network_destination,
                pattern: dest_regex,
                weight: 30,
                check: :check_network_destination
              }
            end
          end

          if net_indicators[:connection_pattern]
            conn_regex = compile_safe_regex(net_indicators[:connection_pattern])
            if conn_regex
              matchers << {
                type: :network_connection,
                pattern: conn_regex,
                weight: 25,
                check: :check_network_connection
              }
            end
          end

          if net_indicators[:dns]
            matchers << {
              type: :network_dns,
              dns_config: net_indicators[:dns],
              weight: 20,
              check: :check_network_dns
            }
          end

          if net_indicators[:http]
            matchers << {
              type: :network_http,
              http_config: net_indicators[:http],
              weight: 20,
              check: :check_network_http
            }
          end

          matchers
        end

        # Compile string pattern matchers with pre-compiled regex.
        #
        # @param patterns [Array<String>] string patterns to match
        # @return [Array<Hash>] compiled matchers
        def compile_string_pattern_matchers(patterns)
          return [] unless patterns.is_a?(Array)

          compiled = patterns.filter_map { |p| compile_safe_regex(p) }
          return [] if compiled.empty?

          [{
            type: :string_pattern,
            patterns: compiled,
            weight: 20,
            check: :check_string_patterns
          }]
        end

        # Compile threshold configuration for rate-based detection.
        #
        # @param threshold [Hash, nil] threshold config
        # @return [Hash, nil] compiled threshold
        def compile_threshold(threshold)
          return nil unless threshold.is_a?(Hash)

          {
            count: [threshold[:count] || 1, 1].max,
            window_seconds: [threshold[:window_seconds] || 60, 1].max,
            bucket_key_fields: threshold[:bucket_key_fields] || [:source, :type]
          }
        end

        # Build pre-filters that can quickly reject events that cannot
        # possibly match this rule, avoiding expensive evaluation.
        #
        # @param indicators [Hash] indicator section
        # @return [Hash] pre-filter configuration
        def build_pre_filters(indicators)
          return {} unless indicators.is_a?(Hash)

          filters = {}

          # Required event types for fast rejection
          required_types = Set.new
          required_types.add(:ruby_api_call) if indicators[:ruby_api]
          required_types.add(:syscall_event) if indicators[:syscall_sequence]
          required_types.add(:filesystem_event) if indicators[:filesystem]
          required_types.add(:network_event) if indicators[:network]
          filters[:required_event_types] = required_types unless required_types.empty?

          # Minimum severity for pre-filtering
          if indicators.dig(:ruby_api, :call_depth)
            filters[:min_call_depth] = indicators[:ruby_api][:call_depth].to_i
          end

          filters
        end

        # Safely compile a regex pattern string, returning nil on error.
        #
        # @param pattern [String] regex pattern
        # @return [Regexp, nil]
        def compile_safe_regex(pattern)
          return nil unless pattern.is_a?(String) && !pattern.empty?

          Regexp.new(pattern, Regexp::IGNORECASE)
        rescue RegexpError => e
          @logger.warn("RuleCompiler: invalid regex '#{pattern}': #{e.message}")
          nil
        end
      end
    end
  end
end
