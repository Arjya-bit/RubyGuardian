# frozen_string_literal: true

require 'yaml'
require 'digest'
require 'pathname'

module RubyGuardian
  module DetectionEngine
    module RuleEngine
      # Loads YAML-based detection rules from files or directories, validates
      # them against a required schema, and maintains a cache of compiled rules
      # keyed by content hash to avoid reprocessing unchanged rules.
      class RuleLoader
        REQUIRED_FIELDS = %w[id name severity conditions].freeze
        VALID_SEVERITIES = %w[critical high medium low info].freeze
        VALID_STATUSES = %w[enabled disabled testing].freeze
        MAX_RULE_SIZE = 1_048_576  # 1 MB

        attr_reader :rules, :load_errors, :cache_stats

        def initialize(options = {})
          @rules_dir     = options.fetch(:rules_dir, nil)
          @file_pattern  = options.fetch(:file_pattern, '*.yml')
          @auto_reload   = options.fetch(:auto_reload, false)
          @reload_interval = options.fetch(:reload_interval, 60)
          @rules         = {}
          @rule_cache    = {}
          @file_checksums = {}
          @load_errors   = []
          @mutex         = Mutex.new
          @cache_stats   = { hits: 0, misses: 0, evictions: 0 }
          @last_load_at  = nil
        end

        # Load all rules from the configured directory.
        #
        # @return [Hash] rule_id => rule hash
        def load_all
          raise ConfigError, 'No rules_dir configured' unless @rules_dir

          @mutex.synchronize do
            @load_errors.clear
            rule_files = discover_rule_files
            loaded = {}

            rule_files.each do |path|
              begin
                rules_from_file = load_file(path)
                rules_from_file.each do |rule|
                  if loaded.key?(rule['id'])
                    @load_errors << { file: path, error: "Duplicate rule ID: #{rule['id']}" }
                    next
                  end
                  loaded[rule['id']] = rule
                end
              rescue => e
                @load_errors << { file: path, error: e.message }
              end
            end

            @rules = loaded
            @last_load_at = Time.now
          end

          @rules
        end

        # Load rules from a single YAML file.
        #
        # @param path [String] file path
        # @return [Array<Hash>] parsed and validated rules
        def load_file(path)
          path = File.expand_path(path)
          validate_file!(path)

          content = File.read(path)
          checksum = Digest::SHA256.hexdigest(content)

          # Return cached rules if file unchanged
          if @rule_cache.key?(path) && @file_checksums[path] == checksum
            @cache_stats[:hits] += 1
            return @rule_cache[path]
          end

          @cache_stats[:misses] += 1
          @file_checksums[path] = checksum

          documents = YAML.safe_load_stream(content, permitted_classes: [Date, Time, Regexp])
          rules = documents.flat_map { |doc| normalize_document(doc, path) }

          rules.each { |rule| validate_rule!(rule, path) }
          enrich_rules!(rules, path)

          @rule_cache[path] = rules
          rules
        end

        # Reload rules that have changed on disk.
        #
        # @return [Array<String>] list of rule IDs that changed
        def reload_changed
          return [] unless @rules_dir

          changed_ids = []

          @mutex.synchronize do
            discover_rule_files.each do |path|
              content = File.read(path)
              checksum = Digest::SHA256.hexdigest(content)
              next if @file_checksums[path] == checksum

              begin
                rules_from_file = load_file(path)
                rules_from_file.each do |rule|
                  @rules[rule['id']] = rule
                  changed_ids << rule['id']
                end
              rescue => e
                @load_errors << { file: path, error: e.message }
              end
            end
          end

          changed_ids
        end

        # Check if a reload is needed based on the configured interval.
        #
        # @return [Boolean]
        def reload_due?
          return true if @last_load_at.nil?
          (Time.now - @last_load_at) >= @reload_interval
        end

        # Evict a specific rule from the cache.
        #
        # @param rule_id [String]
        def evict(rule_id)
          @mutex.synchronize do
            @rules.delete(rule_id)
            @cache_stats[:evictions] += 1
          end
        end

        # Clear the entire rule cache.
        def clear_cache
          @mutex.synchronize do
            @rule_cache.clear
            @file_checksums.clear
            @rules.clear
          end
        end

        private

        def discover_rule_files
          pattern = File.join(@rules_dir, '**', @file_pattern)
          Dir.glob(pattern).sort
        end

        def validate_file!(path)
          raise LoadError, "Rule file not found: #{path}" unless File.exist?(path)
          raise LoadError, "Rule file not readable: #{path}" unless File.readable?(path)

          size = File.size(path)
          if size > MAX_RULE_SIZE
            raise LoadError, "Rule file exceeds max size (#{size} > #{MAX_RULE_SIZE}): #{path}"
          end
        end

        def normalize_document(doc, path)
          case doc
          when Hash
            if doc.key?('rules')
              Array(doc['rules'])
            else
              [doc]
            end
          when Array
            doc
          else
            raise ParseError, "Unexpected YAML structure in #{path}: #{doc.class}"
          end
        end

        def validate_rule!(rule, path)
          missing = REQUIRED_FIELDS - rule.keys
          unless missing.empty?
            raise ValidationError, "Rule in #{path} missing fields: #{missing.join(', ')}"
          end

          unless VALID_SEVERITIES.include?(rule['severity'].to_s.downcase)
            raise ValidationError,
                  "Invalid severity '#{rule['severity']}' in rule '#{rule['id']}'. " \
                  "Valid: #{VALID_SEVERITIES.join(', ')}"
          end

          status = rule.fetch('status', 'enabled')
          unless VALID_STATUSES.include?(status)
            raise ValidationError, "Invalid status '#{status}' in rule '#{rule['id']}'"
          end
        end

        def enrich_rules!(rules, path)
          rules.each do |rule|
            rule['_source_file'] = path
            rule['_loaded_at']   = Time.now.utc.iso8601
            rule['status']     ||= 'enabled'
            rule['severity']     = rule['severity'].to_s.downcase
            rule['tags']       ||= []
            rule['mitre_attack'] ||= {}
          end
        end
      end

      class LoadError < StandardError; end
      class ParseError < StandardError; end
      class ValidationError < StandardError; end
      class ConfigError < StandardError; end
    end
  end
end
