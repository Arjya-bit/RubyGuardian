# frozen_string_literal: true

require 'yaml'
require 'erb'

module RubyGuardian
  module Shared
    # YAML configuration loader with environment support
    # Supports ERB templating for dynamic values
    class ConfigLoader
      class ConfigNotFoundError < StandardError; end
      class InvalidConfigError < StandardError; end

      attr_reader :config, :environment

      BASE_PATH = File.expand_path('../../config', __dir__)

      def initialize(environment: nil)
        @environment = environment || ENV.fetch('RUBY_GUARDIAN_ENV', 'development')
        @config = {}
      end

      # Load the master attack configuration
      def load_attack_config
        @config = load_yaml('attack_config.yml')
        merge_environment_config
        @config
      end

      # Load payload registry
      def load_payloads
        load_yaml('payloads.yml')
      end

      # Load target profiles
      def load_target_profiles
        load_yaml('target_profiles.yml')
      end

      # Get a specific config value using dot notation
      # Example: get('c2_server.host') => "127.0.0.1"
      def get(key_path, default: nil)
        keys = key_path.split('.')
        value = keys.reduce(@config) do |hash, key|
          break nil unless hash.is_a?(Hash)
          hash[key] || hash[key.to_sym]
        end
        value.nil? ? default : value
      end

      # Check if running in a safe environment
      def safe_environment?
        %w[development testing demo sandbox].include?(@environment)
      end

      # Validate that all required config keys are present
      def validate!(required_keys)
        missing = required_keys.reject { |key| get(key) }
        return true if missing.empty?

        raise InvalidConfigError,
              "Missing required configuration keys: #{missing.join(', ')}"
      end

      private

      def load_yaml(filename)
        path = File.join(BASE_PATH, filename)
        raise ConfigNotFoundError, "Config file not found: #{path}" unless File.exist?(path)

        content = File.read(path)
        parsed = ERB.new(content).result
        result = YAML.safe_load(parsed, permitted_classes: [Symbol])

        result.is_a?(Hash) ? deep_symbolize_keys(result) : result
      rescue Psych::SyntaxError => e
        raise InvalidConfigError, "Invalid YAML in #{filename}: #{e.message}"
      end

      def merge_environment_config
        env_file = "environments/#{@environment}.yml"
        env_path = File.join(BASE_PATH, env_file)
        return unless File.exist?(env_path)

        env_config = load_yaml(env_file)
        @config = deep_merge(@config, env_config)
      end

      def deep_merge(base, override)
        base.merge(override) do |_key, old_val, new_val|
          if old_val.is_a?(Hash) && new_val.is_a?(Hash)
            deep_merge(old_val, new_val)
          else
            new_val
          end
        end
      end

      def deep_symbolize_keys(hash)
        hash.each_with_object({}) do |(key, value), result|
          sym_key = key.is_a?(String) ? key.to_sym : key
          result[sym_key] = value.is_a?(Hash) ? deep_symbolize_keys(value) : value
        end
      end
    end
  end
end
