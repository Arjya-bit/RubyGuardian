# frozen_string_literal: true

# RubyGuardian Detection Engine - Rule Parser
# ============================================
# Parses YAML-based detection rule and signature files into normalized
# internal rule structures. Validates required fields and handles
# multiple signature file formats (YARA-style, threshold, sequence).

require "yaml"

module RubyGuardian
  module Detection
    module RuleEngine
      class RuleParser
        REQUIRED_FIELDS = %w[id name severity indicators].freeze
        VALID_SEVERITIES = %w[info low medium high critical].freeze
        MAX_RULES_PER_FILE = 500

        attr_reader :logger

        def initialize(logger:)
          @logger = logger
          @parsed_count = 0
          @error_count = 0
        end

        # Parse a single YAML file and return an array of normalized rule hashes.
        #
        # @param file_path [String] absolute path to a .yml file
        # @return [Array<Hash>] parsed rule structures
        def parse_file(file_path)
          raw = YAML.safe_load(File.read(file_path), permitted_classes: [Symbol])
          return [] unless raw.is_a?(Hash)

          signatures = raw["signatures"] || raw["rules"] || []
          unless signatures.is_a?(Array)
            logger.warn("RuleParser: no signatures array in #{file_path}")
            return []
          end

          if signatures.size > MAX_RULES_PER_FILE
            logger.warn("RuleParser: #{file_path} contains #{signatures.size} rules " \
                        "(max #{MAX_RULES_PER_FILE}), truncating")
            signatures = signatures.first(MAX_RULES_PER_FILE)
          end

          rules = signatures.filter_map do |sig|
            parse_signature(sig, file_path)
          end

          @parsed_count += rules.size
          logger.debug("RuleParser: parsed #{rules.size} rules from #{File.basename(file_path)}")
          rules
        rescue Psych::SyntaxError => e
          @error_count += 1
          logger.error("RuleParser: YAML syntax error in #{file_path}: #{e.message}")
          []
        rescue Errno::ENOENT => e
          @error_count += 1
          logger.error("RuleParser: file not found: #{file_path}")
          []
        rescue StandardError => e
          @error_count += 1
          logger.error("RuleParser: unexpected error parsing #{file_path}: #{e.class}: #{e.message}")
          []
        end

        # Parse multiple files from a directory
        #
        # @param directory [String] path to a directory containing .yml files
        # @return [Array<Hash>] all parsed rules
        def parse_directory(directory)
          files = Dir.glob(File.join(directory, "**", "*.yml")).sort
          logger.info("RuleParser: scanning #{files.size} files in #{directory}")

          files.flat_map { |f| parse_file(f) }
        end

        # Return parser statistics
        def stats
          { parsed: @parsed_count, errors: @error_count }
        end

        private

        # Parse and validate a single signature entry from a YAML file.
        #
        # @param sig [Hash] raw signature hash from YAML
        # @param source_file [String] path of the file this came from
        # @return [Hash, nil] normalized rule or nil if invalid
        def parse_signature(sig, source_file)
          unless sig.is_a?(Hash)
            logger.warn("RuleParser: non-hash signature entry in #{source_file}, skipping")
            return nil
          end

          missing = REQUIRED_FIELDS.select { |f| sig[f].nil? }
          unless missing.empty?
            logger.warn("RuleParser: rule in #{source_file} missing fields: #{missing.join(', ')}")
            return nil
          end

          severity = normalize_severity(sig["severity"])
          unless severity
            logger.warn("RuleParser: invalid severity '#{sig['severity']}' in rule #{sig['id']}")
            return nil
          end

          {
            id: sig["id"].to_s.strip,
            name: sig["name"].to_s.strip,
            description: (sig["description"] || "").to_s.strip,
            severity: severity,
            score: (sig["score"] || default_score_for_severity(severity)).to_i,
            mitre_attack: parse_mitre_attack(sig["mitre_attack"]),
            tags: Array(sig["tags"]).map(&:to_s),
            indicators: parse_indicators(sig["indicators"]),
            threshold: parse_threshold(sig["threshold"] || sig.dig("indicators", "threshold")),
            source_file: source_file,
            enabled: sig.fetch("enabled", true)
          }
        rescue StandardError => e
          @error_count += 1
          logger.error("RuleParser: error parsing signature #{sig['id']}: #{e.message}")
          nil
        end

        def normalize_severity(raw)
          s = raw.to_s.downcase.strip
          VALID_SEVERITIES.include?(s) ? s.to_sym : nil
        end

        def default_score_for_severity(severity)
          case severity
          when :critical then 90
          when :high     then 75
          when :medium   then 55
          when :low      then 35
          when :info     then 15
          else 50
          end
        end

        def parse_mitre_attack(raw)
          return nil unless raw.is_a?(Hash)

          {
            tactic: raw["tactic"]&.to_s,
            technique: raw["technique"]&.to_s,
            subtechnique: raw["subtechnique"]&.to_s
          }.compact
        end

        # Parse the indicators section which can contain various detection criteria
        def parse_indicators(raw)
          return {} unless raw.is_a?(Hash)

          result = {}

          # Ruby API indicators (method calls, classes, sequences)
          if raw["ruby_api"]
            result[:ruby_api] = parse_ruby_api_indicators(raw["ruby_api"])
          end

          # Syscall sequence indicators
          if raw["syscall_sequence"]
            result[:syscall_sequence] = parse_syscall_indicators(raw["syscall_sequence"])
          end

          # Filesystem indicators
          if raw["filesystem"]
            result[:filesystem] = parse_filesystem_indicators(raw["filesystem"])
          end

          # Network indicators
          if raw["network"]
            result[:network] = parse_network_indicators(raw["network"])
          end

          # String pattern indicators
          if raw["string_patterns"]
            result[:string_patterns] = Array(raw["string_patterns"]).map(&:to_s)
          end

          result
        end

        def parse_ruby_api_indicators(raw)
          return {} unless raw.is_a?(Hash)

          {
            methods_called: Array(raw["methods_called"]),
            classes_used: Array(raw["classes_used"]),
            call_sequence: Array(raw["call_sequence"]),
            call_chain_contains: raw["call_chain_contains"],
            patterns: Array(raw["patterns"]),
            argument_pattern: raw["argument_pattern"],
            call_depth: raw["call_depth"],
            window_ms: raw["window_ms"]&.to_i
          }.compact
        end

        def parse_syscall_indicators(raw)
          return {} unless raw.is_a?(Hash)

          {
            syscalls: Array(raw["syscalls"]),
            ordered: raw.fetch("ordered", false),
            window_ms: raw["window_ms"]&.to_i || 5000
          }
        end

        def parse_filesystem_indicators(raw)
          return {} unless raw.is_a?(Hash)

          {
            path_pattern: raw["path_pattern"],
            operation: raw["operation"],
            suspicious_extensions: Array(raw["suspicious_extensions"])
          }.compact
        end

        def parse_network_indicators(raw)
          return {} unless raw.is_a?(Hash)

          {
            dns: raw["dns"],
            http: raw["http"],
            connection_pattern: raw["connection_pattern"],
            destination_pattern: raw["destination_pattern"]
          }.compact
        end

        def parse_threshold(raw)
          return nil unless raw.is_a?(Hash)

          {
            count: raw["count"]&.to_i || 1,
            window_seconds: raw["window_seconds"]&.to_i || 60
          }
        end
      end
    end
  end
end
