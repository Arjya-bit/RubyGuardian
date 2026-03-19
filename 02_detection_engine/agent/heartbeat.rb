# frozen_string_literal: true

module RubyGuardian
  module Detection
    # Health monitoring and watchdog for the detection agent
    # Sends periodic heartbeats and monitors component health
    class Heartbeat
      HEARTBEAT_INTERVAL = 30
      STALE_THRESHOLD = 120
      MEMORY_WARN_MB = 512
      CPU_WARN_PERCENT = 80

      attr_reader :config, :logger, :components, :status

      def initialize(config:, logger:)
        @config = config
        @logger = logger
        @components = {}
        @status = :initializing
        @running = false
        @start_time = Time.now
        @heartbeat_count = 0
        @mutex = Mutex.new
      end

      def start
        @running = true
        @status = :running
        @heartbeat_thread = Thread.new { heartbeat_loop }
        logger.info('Heartbeat monitor started')
      end

      def stop
        @running = false
        @status = :stopped
        @heartbeat_thread&.join(5)
        logger.info('Heartbeat monitor stopped')
      end

      def register_component(name, component)
        @mutex.synchronize do
          @components[name] = {
            component: component,
            last_seen: Time.now,
            status: :running,
            errors: 0
          }
        end
      end

      def component_alive(name)
        @mutex.synchronize do
          if @components[name]
            @components[name][:last_seen] = Time.now
            @components[name][:status] = :running
          end
        end
      end

      def component_error(name, error)
        @mutex.synchronize do
          if @components[name]
            @components[name][:errors] += 1
            @components[name][:last_error] = error.message
          end
        end
      end

      def health_report
        {
          status: @status,
          uptime: Time.now - @start_time,
          heartbeat_count: @heartbeat_count,
          memory_mb: current_memory_mb,
          cpu_percent: current_cpu_percent,
          components: component_summary,
          ruby_version: RUBY_VERSION,
          pid: Process.pid,
          timestamp: Time.now.utc.iso8601
        }
      end

      private

      def heartbeat_loop
        while @running
          perform_heartbeat
          sleep(config.fetch(:heartbeat_interval, HEARTBEAT_INTERVAL))
        end
      end

      def perform_heartbeat
        @heartbeat_count += 1
        check_components
        check_resources
        log_status
      end

      def check_components
        @mutex.synchronize do
          @components.each do |name, info|
            age = Time.now - info[:last_seen]
            if age > STALE_THRESHOLD
              info[:status] = :stale
              logger.warn("Component #{name} is stale (#{age.round}s since last heartbeat)")
            end
          end
        end
      end

      def check_resources
        mem = current_memory_mb
        if mem > MEMORY_WARN_MB
          logger.warn("High memory usage: #{mem.round}MB")
        end

        cpu = current_cpu_percent
        if cpu > CPU_WARN_PERCENT
          logger.warn("High CPU usage: #{cpu.round}%")
        end
      end

      def current_memory_mb
        if File.readable?("/proc/#{Process.pid}/status")
          File.readlines("/proc/#{Process.pid}/status").each do |line|
            return line.split[1].to_f / 1024 if line.start_with?('VmRSS:')
          end
        end
        0.0
      end

      def current_cpu_percent
        if File.readable?("/proc/#{Process.pid}/stat")
          fields = File.read("/proc/#{Process.pid}/stat").split
          utime = fields[13].to_f
          stime = fields[14].to_f
          total = utime + stime
          uptime = File.read('/proc/uptime').split[0].to_f
          clk_tck = 100.0
          (total / clk_tck / uptime * 100).round(1)
        else
          0.0
        end
      rescue StandardError
        0.0
      end

      def component_summary
        @components.transform_values do |info|
          {
            status: info[:status],
            last_seen: info[:last_seen].iso8601,
            errors: info[:errors],
            last_error: info[:last_error]
          }
        end
      end

      def log_status
        report = health_report
        logger.debug("Heartbeat ##{@heartbeat_count}: mem=#{report[:memory_mb].round}MB " \
                      "components=#{report[:components].size} uptime=#{report[:uptime].round}s")
      end
    end
  end
end
