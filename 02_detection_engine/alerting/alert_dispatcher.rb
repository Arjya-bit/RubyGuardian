# frozen_string_literal: true

# RubyGuardian Detection Engine -- Alert Dispatcher
#
# Routes detection alerts to configured channels (log, webhook, SIEM,
# email) based on severity and alert rules. Supports batching,
# deduplication, and rate limiting.

require 'json'
require 'net/http'
require 'uri'
require 'concurrent'

module RubyGuardian
  module Detection
    module Alerting
      class AlertDispatcher
        SEVERITY_LEVELS = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }.freeze
        DEFAULT_BATCH_SIZE = 10
        DEFAULT_FLUSH_INTERVAL = 30 # seconds

        attr_reader :config, :logger, :stats

        def initialize(config:, logger:)
          @config = config
          @logger = logger
          @channels = []
          @batch = Concurrent::Array.new
          @stats = Concurrent::Hash.new(0)
          @dedup_cache = Concurrent::Map.new
          @flush_timer = nil
          @running = false

          initialize_channels
        end

        # Dispatch an alert to all configured channels
        def dispatch(alert)
          return unless @running

          alert = normalize_alert(alert)

          # Check minimum severity threshold
          min_severity = @config&.dig('min_severity') || 'low'
          return if severity_below?(alert[:severity], min_severity)

          # Deduplication check
          dedup_key = "#{alert[:rule_id]}:#{alert[:source_pid]}"
          dedup_window = @config&.dig('dedup_window_seconds') || 60
          if @dedup_cache[dedup_key] && (Time.now - @dedup_cache[dedup_key]) < dedup_window
            @stats[:deduplicated] += 1
            return
          end
          @dedup_cache[dedup_key] = Time.now

          @stats[:dispatched] += 1
          @batch << alert

          # Flush immediately for critical alerts
          if alert[:severity] == 'critical'
            flush_batch
          elsif @batch.size >= DEFAULT_BATCH_SIZE
            flush_batch
          end
        end

        # Start the dispatcher (enables alert processing and periodic flushing)
        def start
          @running = true
          @flush_timer = Concurrent::TimerTask.new(
            execution_interval: DEFAULT_FLUSH_INTERVAL
          ) { flush_batch }
          @flush_timer.execute
          @logger.info('AlertDispatcher started')
        end

        # Stop the dispatcher and flush remaining alerts
        def stop
          @running = false
          @flush_timer&.shutdown
          flush_batch unless @batch.empty?
          @logger.info("AlertDispatcher stopped (#{@stats[:dispatched]} alerts dispatched)")
        end

        # Get dispatcher statistics
        def status
          {
            running: @running,
            channels: @channels.map { |c| c.class.name },
            pending_batch: @batch.size,
            stats: @stats.to_h
          }
        end

        private

        def initialize_channels
          channels_config = @config&.dig('channels') || {}

          if channels_config['log']&.dig('enabled')
            @channels << LogChannel.new(config: channels_config['log'], logger: @logger)
          end

          if channels_config['webhook']&.dig('enabled')
            @channels << WebhookChannel.new(config: channels_config['webhook'], logger: @logger)
          end

          if channels_config['siem']&.dig('enabled')
            @channels << SiemChannel.new(config: channels_config['siem'], logger: @logger)
          end

          # Default to log channel if none configured
          if @channels.empty?
            @channels << LogChannel.new(config: {}, logger: @logger)
          end

          @logger.info("Initialized #{@channels.size} alert channels")
        end

        def normalize_alert(alert)
          {
            id: SecureRandom.uuid,
            timestamp: Time.now.utc.iso8601,
            severity: 'medium',
            source: 'ruby_guardian',
            rule_id: nil,
            source_pid: nil,
            description: nil,
            evidence: {},
            mitre_ids: []
          }.merge(alert.is_a?(Hash) ? alert : { description: alert.to_s })
        end

        def severity_below?(alert_severity, threshold)
          (SEVERITY_LEVELS[alert_severity.to_s.to_sym] || 0) <
            (SEVERITY_LEVELS[threshold.to_s.to_sym] || 0)
        end

        def flush_batch
          return if @batch.empty?

          alerts = @batch.dup
          @batch.clear

          @channels.each do |channel|
            channel.send_alerts(alerts)
            @stats[:channel_sends] += 1
          rescue StandardError => e
            @logger.error("Channel #{channel.class.name} failed: #{e.message}")
            @stats[:channel_errors] += 1
          end
        end
      end

      # Log-based alert channel
      class LogChannel
        def initialize(config:, logger:)
          @config = config
          @logger = logger
        end

        def send_alerts(alerts)
          alerts.each do |alert|
            @logger.warn(
              "[ALERT] [#{alert[:severity]&.upcase}] " \
              "#{alert[:rule_id]}: #{alert[:description]} " \
              "(PID: #{alert[:source_pid]}, MITRE: #{alert[:mitre_ids]&.join(', ')})"
            )
          end
        end
      end

      # Webhook-based alert channel
      class WebhookChannel
        def initialize(config:, logger:)
          @url = config['url']
          @headers = config['headers'] || {}
          @logger = logger
        end

        def send_alerts(alerts)
          return unless @url

          uri = URI.parse(@url)
          http = Net::HTTP.new(uri.host, uri.port)
          http.use_ssl = uri.scheme == 'https'
          http.open_timeout = 5
          http.read_timeout = 10

          request = Net::HTTP::Post.new(uri.path)
          request['Content-Type'] = 'application/json'
          @headers.each { |k, v| request[k] = v }
          request.body = JSON.generate({ alerts: alerts })

          response = http.request(request)
          @logger.debug("Webhook response: #{response.code}")
        rescue StandardError => e
          @logger.error("Webhook delivery failed: #{e.message}")
        end
      end

      # SIEM integration channel (sends to Logstash/Elasticsearch)
      class SiemChannel
        def initialize(config:, logger:)
          @host = config['host'] || 'localhost'
          @port = config['port'] || 5044
          @logger = logger
        end

        def send_alerts(alerts)
          require 'socket'
          socket = TCPSocket.new(@host, @port)
          alerts.each do |alert|
            socket.puts(JSON.generate(alert))
          end
          socket.close
        rescue StandardError => e
          @logger.error("SIEM delivery failed: #{e.message}")
        end
      end
    end
  end
end
