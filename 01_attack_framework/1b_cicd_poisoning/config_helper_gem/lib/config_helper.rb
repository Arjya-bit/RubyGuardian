# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Trojanized Gem Specimen: config_helper.rb
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This file demonstrates the "legitimate" portion of a trojanized gem.
#   It provides real, functional configuration management features to appear
#   useful and trustworthy. The malicious payload is in separate files
#   (installer.rb, extconf.rb) and is FULLY COMMENTED OUT.
#
#   In real supply chain attacks, the legitimate functionality is key to
#   the gem being adopted. The attacker needs the gem to be genuinely
#   useful so developers willingly add it to their projects.
#
# MITRE ATT&CK References:
#   - T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain
#   - T1036.005 : Masquerading: Match Legitimate Name or Location
# =============================================================================

require 'yaml'
require 'json'
require 'pathname'

# ConfigHelper - A clean configuration management library for Ruby
#
# This module provides genuine configuration file management functionality.
# In a real trojanized gem, this legitimate code serves as camouflage
# for the malicious payload that activates during installation or in
# CI/CD environments.
#
# @example Basic usage
#   config = ConfigHelper.load('config/settings.yml')
#   config.get('database.host')  #=> "localhost"
#   config.get('database.port', default: 5432)  #=> 5432
#
module ConfigHelper
  VERSION = '1.2.3'

  # Research annotation: This constant would not exist in a real attack.
  # It's here to clearly mark this as a research specimen.
  RESEARCH_SPECIMEN = true

  class ConfigurationError < StandardError; end
  class FileNotFoundError < ConfigurationError; end
  class ParseError < ConfigurationError; end

  # Load a configuration file (YAML or JSON) and return a Config object
  #
  # @param path [String] path to the configuration file
  # @param env [String, nil] optional environment overlay (e.g., 'production')
  # @return [Config] configuration object with dot-notation access
  # @raise [FileNotFoundError] if the file does not exist
  # @raise [ParseError] if the file cannot be parsed
  def self.load(path, env: nil)
    full_path = Pathname.new(path).expand_path
    raise FileNotFoundError, "Config file not found: #{full_path}" unless full_path.exist?

    data = parse_file(full_path)

    # Apply environment overlay if specified
    if env && data.is_a?(Hash) && data.key?(env.to_s)
      base = data.reject { |k, _| %w[development staging production test].include?(k) }
      overlay = data[env.to_s] || {}
      data = deep_merge(base, overlay)
    end

    Config.new(data)

    # -------------------------------------------------------------------------
    # RESEARCH NOTE: Trojanized payload activation point
    # -------------------------------------------------------------------------
    # In a real trojanized gem, this method might also:
    #
    #   1. Check if running inside a CI/CD environment:
    #      # if ENV['CI'] || ENV['GITHUB_ACTIONS'] || ENV['GITLAB_CI']
    #      #   Installer.activate_ci_payload
    #      # end
    #
    #   2. Silently exfiltrate the loaded config (which may contain secrets):
    #      # Thread.new { phone_home(data) }
    #
    #   3. Inject code into the application's runtime:
    #      # inject_runtime_hooks
    #
    # ALL of the above is COMMENTED OUT. This specimen only provides
    # legitimate config loading functionality.
    # -------------------------------------------------------------------------
  end

  # Load multiple configuration files and merge them
  #
  # @param paths [Array<String>] list of config file paths
  # @param env [String, nil] optional environment overlay
  # @return [Config] merged configuration object
  def self.load_multiple(*paths, env: nil)
    configs = paths.map { |p| load(p, env: env) }
    merged_data = configs.reduce({}) { |acc, cfg| deep_merge(acc, cfg.to_h) }
    Config.new(merged_data)
  end

  # Parse a configuration file based on its extension
  #
  # @param path [Pathname] path to the file
  # @return [Hash] parsed configuration data
  def self.parse_file(path)
    content = File.read(path)

    case path.extname.downcase
    when '.yml', '.yaml'
      YAML.safe_load(content, permitted_classes: [Symbol, Date, Time]) || {}
    when '.json'
      JSON.parse(content) || {}
    else
      raise ParseError, "Unsupported config format: #{path.extname}"
    end
  rescue Psych::SyntaxError => e
    raise ParseError, "YAML parse error in #{path}: #{e.message}"
  rescue JSON::ParserError => e
    raise ParseError, "JSON parse error in #{path}: #{e.message}"
  end

  # Deep merge two hashes, with values from `override` taking precedence
  #
  # @param base [Hash] base configuration
  # @param override [Hash] overriding configuration
  # @return [Hash] merged result
  def self.deep_merge(base, override)
    base.merge(override) do |_key, old_val, new_val|
      if old_val.is_a?(Hash) && new_val.is_a?(Hash)
        deep_merge(old_val, new_val)
      else
        new_val
      end
    end
  end

  # Config wraps a hash and provides convenient nested key access
  class Config
    # @param data [Hash] the configuration data
    def initialize(data = {})
      @data = data.is_a?(Hash) ? data : {}
    end

    # Get a configuration value using dot-notation keys
    #
    # @param key_path [String] dot-separated key path (e.g., "database.host")
    # @param default [Object] default value if key is not found
    # @return [Object] the configuration value or default
    #
    # @example
    #   config.get('server.port')           #=> 8080
    #   config.get('missing.key', default: 'fallback') #=> 'fallback'
    def get(key_path, default: nil)
      keys = key_path.to_s.split('.')
      result = keys.reduce(@data) do |current, key|
        break nil unless current.is_a?(Hash)
        current[key] || current[key.to_sym]
      end
      result.nil? ? default : result
    end

    # Check if a key path exists in the configuration
    #
    # @param key_path [String] dot-separated key path
    # @return [Boolean] true if the key exists
    def key?(key_path)
      !get(key_path).nil?
    end

    # Set a configuration value using dot-notation keys
    #
    # @param key_path [String] dot-separated key path
    # @param value [Object] the value to set
    def set(key_path, value)
      keys = key_path.to_s.split('.')
      target = keys[0..-2].reduce(@data) do |current, key|
        current[key] ||= {}
      end
      target[keys.last] = value
    end

    # Return the underlying hash
    #
    # @return [Hash] raw configuration data
    def to_h
      @data.dup
    end

    # Convert to JSON string
    #
    # @return [String] JSON representation
    def to_json(*args)
      @data.to_json(*args)
    end

    # Convert to YAML string
    #
    # @return [String] YAML representation
    def to_yaml
      @data.to_yaml
    end
  end
end
