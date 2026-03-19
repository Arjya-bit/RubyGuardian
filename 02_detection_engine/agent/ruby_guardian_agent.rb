# frozen_string_literal: true

# RubyGuardian Detection Engine - Main Agent Daemon
# ==================================================
# Entry point for the RubyGuardian detection agent. Manages lifecycle,
# signal handling, configuration loading, and monitor orchestration.

require "concurrent"
require "yaml"
require "erb"
require "socket"
require "logger"
require "fileutils"

module RubyGuardian
  module Detection
    class Agent
      VERSION = "2.0.0"

      SIGNALS_HANDLED = %w[INT TERM HUP USR1 USR2 QUIT].freeze
      SHUTDOWN_TIMEOUT_SECONDS = 15

      attr_reader :config, :monitors, :event_collector, :rule_engine,
                  :alert_dispatcher, :heartbeat, :logger, :state

      # Possible states: :initializing, :starting, :running, :reloading,
      #                  :shutting_down, :stopped, :error
      VALID_STATES = %i[initializing starting running reloading
                        shutting_down stopped error].freeze

      def initialize(config_path: nil, daemonize: false)
        @state = :initializing
        @config_path = config_path || default_config_path
        @daemonize = daemonize
        @monitors = {}
        @shutdown_latch = Concurrent::CountDownLatch.new(1)
        @mutex = Mutex.new
        @started_at = nil
        @reload_count = 0
        @error_count = Concurrent::AtomicFixnum.new(0)
      end

      # Main entry point - starts the agent daemon
      def run!
        load_configuration!
        setup_logging
        log_banner
        write_pid_file
        setup_signal_handlers
        daemonize! if @daemonize

        transition_to(:starting)

        initialize_components
        start_monitors
        start_heartbeat

        transition_to(:running)
        @started_at = Time.now
        logger.info("Agent fully started, entering main loop")

        # Block on the shutdown latch until a signal is received
        @shutdown_latch.wait
      rescue StandardError => e
        transition_to(:error)
        logger&.fatal("Agent fatal error: #{e.class}: #{e.message}")
        logger&.fatal(e.backtrace&.first(20)&.join("\n"))
        raise
      ensure
        shutdown!
      end

      # Gracefully shuts down all components
      def shutdown!
        return if @state == :stopped

        transition_to(:shutting_down)
        logger&.info("Initiating graceful shutdown (timeout: #{SHUTDOWN_TIMEOUT_SECONDS}s)")

        shutdown_thread = Thread.new { perform_shutdown }
        unless shutdown_thread.join(SHUTDOWN_TIMEOUT_SECONDS)
          logger&.warn("Shutdown timed out after #{SHUTDOWN_TIMEOUT_SECONDS}s, forcing exit")
          shutdown_thread.kill
        end

        cleanup_pid_file
        transition_to(:stopped)
        logger&.info("Agent stopped cleanly")
      end

      # Reloads configuration and restarts monitors
      def reload!
        transition_to(:reloading)
        logger.info("Reloading configuration from #{@config_path}")

        begin
          old_config = @config.dup
          load_configuration!

          restart_monitors_if_needed(old_config)
          @reload_count += 1

          logger.info("Configuration reloaded successfully (reload ##{@reload_count})")
          transition_to(:running)
        rescue StandardError => e
          logger.error("Reload failed: #{e.message}, keeping previous configuration")
          @config = old_config
          transition_to(:running)
        end
      end

      # Returns agent status information
      def status
        {
          state: @state,
          version: VERSION,
          agent_id: @config&.dig("engine", "agent_id"),
          started_at: @started_at&.iso8601,
          uptime_seconds: @started_at ? (Time.now - @started_at).to_i : 0,
          reload_count: @reload_count,
          error_count: @error_count.value,
          monitors: monitor_statuses,
          event_queue_depth: @event_collector&.queue_depth || 0
        }
      end

      private

      def default_config_path
        File.expand_path("../config/detection_config.yml", __dir__)
      end

      def load_configuration!
        raw_yaml = File.read(@config_path)
        processed_yaml = ERB.new(raw_yaml).result(binding)
        @config = YAML.safe_load(processed_yaml, permitted_classes: [Symbol])

        validate_configuration!
      rescue Errno::ENOENT
        raise ConfigurationError, "Configuration file not found: #{@config_path}"
      rescue Psych::SyntaxError => e
        raise ConfigurationError, "Invalid YAML in #{@config_path}: #{e.message}"
      end

      def validate_configuration!
        required_sections = %w[engine monitoring detection alerting]
        missing = required_sections - @config.keys
        unless missing.empty?
          raise ConfigurationError,
                "Missing required config sections: #{missing.join(', ')}"
        end

        engine = @config["engine"]
        raise ConfigurationError, "engine.agent_id is required" unless engine["agent_id"]
        raise ConfigurationError, "engine.log_level is required" unless engine["log_level"]
      end

      def setup_logging
        engine_cfg = @config["engine"]
        log_file = engine_cfg["log_file"]
        log_dir = File.dirname(log_file)
        FileUtils.mkdir_p(log_dir) unless File.directory?(log_dir)

        @logger = Logger.new(
          log_file,
          engine_cfg.fetch("log_max_files", 10),
          10 * 1024 * 1024 # 10MB per file
        )
        @logger.level = parse_log_level(engine_cfg["log_level"])
        @logger.formatter = proc do |severity, datetime, _progname, msg|
          "[#{datetime.strftime('%Y-%m-%d %H:%M:%S.%L')}] " \
            "[#{severity}] [#{@config['engine']['agent_id']}] #{msg}\n"
        end
      rescue StandardError => e
        # Fall back to STDERR if log file setup fails
        @logger = Logger.new($stderr)
        @logger.warn("Could not open log file #{log_file}: #{e.message}, using STDERR")
      end

      def parse_log_level(level_str)
        case level_str.to_s.downcase
        when "debug" then Logger::DEBUG
        when "info"  then Logger::INFO
        when "warn"  then Logger::WARN
        when "error" then Logger::ERROR
        when "fatal" then Logger::FATAL
        else Logger::INFO
        end
      end

      def log_banner
        logger.info("=" * 60)
        logger.info("RubyGuardian Detection Agent v#{VERSION}")
        logger.info("Agent ID: #{@config['engine']['agent_id']}")
        logger.info("Environment: #{@config['engine']['environment']}")
        logger.info("Config: #{@config_path}")
        logger.info("PID: #{Process.pid}")
        logger.info("Ruby: #{RUBY_VERSION} (#{RUBY_PLATFORM})")
        logger.info("=" * 60)
      end

      def write_pid_file
        pid_path = @config.dig("engine", "pid_file")
        return unless pid_path

        FileUtils.mkdir_p(File.dirname(pid_path))
        File.write(pid_path, Process.pid.to_s)
        logger&.debug("PID file written: #{pid_path}")
      rescue StandardError => e
        logger&.warn("Could not write PID file #{pid_path}: #{e.message}")
      end

      def cleanup_pid_file
        pid_path = @config&.dig("engine", "pid_file")
        return unless pid_path && File.exist?(pid_path)

        File.delete(pid_path)
      rescue StandardError => e
        logger&.warn("Could not remove PID file: #{e.message}")
      end

      def setup_signal_handlers
        Signal.trap("INT")  { signal_shutdown("INT") }
        Signal.trap("TERM") { signal_shutdown("TERM") }
        Signal.trap("QUIT") { signal_shutdown("QUIT") }
        Signal.trap("HUP")  { signal_reload }
        Signal.trap("USR1") { signal_dump_status }
        Signal.trap("USR2") { signal_rotate_logs }
      end

      def signal_shutdown(sig)
        # Signal handlers must be async-signal-safe, so just release the latch
        @logger&.info("Received SIG#{sig}, initiating shutdown")
        @shutdown_latch.count_down
      end

      def signal_reload
        Thread.new { reload! }
      end

      def signal_dump_status
        Thread.new do
          logger.info("Status dump requested via USR1")
          status.each { |k, v| logger.info("  #{k}: #{v}") }
        end
      end

      def signal_rotate_logs
        Thread.new do
          logger.info("Log rotation requested via USR2")
          setup_logging
        end
      end

      def daemonize!
        Process.daemon(true, false)
        write_pid_file # Re-write with new PID after fork
      end

      def initialize_components
        logger.info("Initializing detection engine components")

        @event_collector = EventCollector.new(
          config: @config["engine"],
          logger: logger
        )

        initialize_monitors
        initialize_rule_engine
        initialize_alert_dispatcher

        # Wire up the pipeline: monitors -> event_collector -> rule_engine -> alert_dispatcher
        @event_collector.on_event do |event|
          results = @rule_engine.evaluate(event)
          results.each { |alert| @alert_dispatcher.dispatch(alert) }
        end

        logger.info("All components initialized successfully")
      end

      def initialize_monitors
        mon_config = @config["monitoring"]

        monitor_classes = {
          "process"     => ProcessMonitor,
          "syscall"     => SyscallTracer,
          "memory"      => MemoryInspector,
          "network"     => NetworkMonitor,
          "filesystem"  => FileMonitor,
          "objectspace" => ObjectSpaceScanner
        }

        monitor_classes.each do |name, klass|
          section = mon_config[name]
          if section && section["enabled"]
            logger.info("Initializing #{name} monitor")
            @monitors[name] = klass.new(
              config: section,
              event_collector: @event_collector,
              logger: logger
            )
          else
            logger.info("#{name} monitor is disabled, skipping")
          end
        end
      end

      def initialize_rule_engine
        require_relative "../rule_engine/engine"
        @rule_engine = RubyGuardian::Detection::RuleEngine::Engine.new(
          config: @config["detection"],
          logger: logger
        )
      end

      def initialize_alert_dispatcher
        require_relative "../alerting/alert_dispatcher"
        @alert_dispatcher = RubyGuardian::Detection::Alerting::AlertDispatcher.new(
          config: @config["alerting"],
          logger: logger
        )
      end

      def start_monitors
        logger.info("Starting #{@monitors.size} monitors")
        @monitors.each do |name, monitor|
          logger.info("Starting #{name} monitor")
          monitor.start
        end
      end

      def start_heartbeat
        @heartbeat = Heartbeat.new(
          agent: self,
          interval: @config.dig("engine", "heartbeat_interval") || 30,
          logger: logger
        )
        @heartbeat.start
      end

      def perform_shutdown
        logger.info("Stopping heartbeat")
        @heartbeat&.stop

        logger.info("Stopping monitors")
        @monitors.each do |name, monitor|
          logger.info("Stopping #{name} monitor")
          monitor.stop
        rescue StandardError => e
          logger.error("Error stopping #{name}: #{e.message}")
        end

        logger.info("Draining event collector")
        @event_collector&.drain

        logger.info("Stopping alert dispatcher")
        @alert_dispatcher&.stop

        logger.info("All components stopped")
      end

      def restart_monitors_if_needed(old_config)
        old_mon = old_config["monitoring"]
        new_mon = @config["monitoring"]

        @monitors.each do |name, monitor|
          old_section = old_mon[name]
          new_section = new_mon[name]

          if new_section && !new_section["enabled"]
            logger.info("Disabling #{name} monitor after reload")
            monitor.stop
            @monitors.delete(name)
          elsif old_section != new_section
            logger.info("Restarting #{name} monitor with updated config")
            monitor.stop
            monitor.reconfigure(new_section)
            monitor.start
          end
        end
      end

      def monitor_statuses
        @monitors.transform_values(&:status)
      end

      def transition_to(new_state)
        unless VALID_STATES.include?(new_state)
          raise ArgumentError, "Invalid state: #{new_state}"
        end

        old_state = @state
        @state = new_state
        logger&.debug("State transition: #{old_state} -> #{new_state}")
      end
    end

    class ConfigurationError < StandardError; end

    # CLI entry point
    class AgentCLI
      def self.run(args = ARGV)
        options = parse_options(args)

        agent = Agent.new(
          config_path: options[:config],
          daemonize: options[:daemonize]
        )

        case options[:command]
        when :start
          agent.run!
        when :stop
          stop_agent(options)
        when :status
          show_status(options)
        when :reload
          reload_agent(options)
        else
          puts "Usage: ruby_guardian_agent {start|stop|status|reload} [options]"
          exit 1
        end
      end

      def self.parse_options(args)
        options = { command: :start }

        # Simple argument parsing
        args.each_with_index do |arg, i|
          case arg
          when "start", "stop", "status", "reload"
            options[:command] = arg.to_sym
          when "-c", "--config"
            options[:config] = args[i + 1]
          when "-d", "--daemonize"
            options[:daemonize] = true
          when "-p", "--pid-file"
            options[:pid_file] = args[i + 1]
          when "-v", "--version"
            puts "RubyGuardian Detection Agent v#{Agent::VERSION}"
            exit 0
          when "-h", "--help"
            print_help
            exit 0
          end
        end

        options
      end

      def self.stop_agent(options)
        pid_file = options[:pid_file] || "/var/run/ruby-guardian-agent.pid"
        unless File.exist?(pid_file)
          puts "PID file not found: #{pid_file}"
          exit 1
        end

        pid = File.read(pid_file).strip.to_i
        Process.kill("TERM", pid)
        puts "Sent SIGTERM to agent (PID #{pid})"
      rescue Errno::ESRCH
        puts "Agent process #{pid} not found"
        File.delete(pid_file)
      end

      def self.show_status(options)
        pid_file = options[:pid_file] || "/var/run/ruby-guardian-agent.pid"
        if File.exist?(pid_file)
          pid = File.read(pid_file).strip.to_i
          begin
            Process.kill(0, pid)
            puts "Agent is running (PID #{pid})"
          rescue Errno::ESRCH
            puts "Agent is not running (stale PID file)"
          end
        else
          puts "Agent is not running"
        end
      end

      def self.reload_agent(options)
        pid_file = options[:pid_file] || "/var/run/ruby-guardian-agent.pid"
        pid = File.read(pid_file).strip.to_i
        Process.kill("HUP", pid)
        puts "Sent SIGHUP to agent (PID #{pid})"
      end

      def self.print_help
        puts <<~HELP
          RubyGuardian Detection Agent v#{Agent::VERSION}

          Usage: ruby_guardian_agent <command> [options]

          Commands:
            start    Start the agent
            stop     Stop a running agent
            status   Check agent status
            reload   Reload configuration

          Options:
            -c, --config PATH    Configuration file path
            -d, --daemonize      Run as background daemon
            -p, --pid-file PATH  PID file location
            -v, --version        Show version
            -h, --help           Show this help
        HELP
      end
    end
  end
end
