# frozen_string_literal: true

module RubyGuardian
  module Detection
    # Central event bus for collecting, buffering, and dispatching security events
    # from all monitors to the rule engine and alert system
    class EventCollector
      MAX_BUFFER_SIZE = 10_000
      FLUSH_INTERVAL = 5

      attr_reader :config, :logger, :stats

      def initialize(config:, logger:)
        @config = config
        @logger = logger
        @buffer = []
        @subscribers = []
        @mutex = Mutex.new
        @running = false
        @stats = { total: 0, dropped: 0, dispatched: 0 }
        @filters = []
      end

      def start
        @running = true
        @flush_thread = Thread.new { flush_loop }
        logger.info('EventCollector started')
      end

      def stop
        @running = false
        flush_buffer
        @flush_thread&.join(5)
        logger.info("EventCollector stopped. Stats: #{@stats}")
      end

      def subscribe(&block)
        @mutex.synchronize { @subscribers << block }
      end

      def add_filter(&block)
        @mutex.synchronize { @filters << block }
      end

      def emit(event)
        enriched = enrich_event(event)
        return if filtered?(enriched)

        @mutex.synchronize do
          @stats[:total] += 1
          if @buffer.length >= MAX_BUFFER_SIZE
            @buffer.shift
            @stats[:dropped] += 1
          end
          @buffer << enriched
        end
      end

      def flush_buffer
        events = @mutex.synchronize do
          batch = @buffer.dup
          @buffer.clear
          batch
        end

        return if events.empty?

        @subscribers.each do |subscriber|
          events.each do |event|
            begin
              subscriber.call(event)
              @mutex.synchronize { @stats[:dispatched] += 1 }
            rescue StandardError => e
              logger.error("Subscriber error: #{e.message}")
            end
          end
        end
      end

      def event_count
        @mutex.synchronize { @buffer.length }
      end

      private

      def flush_loop
        while @running
          sleep(FLUSH_INTERVAL)
          flush_buffer
        end
      end

      def enrich_event(event)
        event.merge(
          id: SecureRandom.uuid,
          timestamp: Time.now.utc.iso8601(3),
          hostname: Socket.gethostname,
          agent_version: RubyGuardian::Detection::VERSION rescue '0.1.0',
          severity_level: severity_to_level(event[:severity])
        )
      end

      def severity_to_level(severity)
        case severity
        when :critical then 4
        when :high then 3
        when :medium then 2
        when :low then 1
        when :info then 0
        else 0
        end
      end

      def filtered?(event)
        @filters.any? { |f| f.call(event) }
      rescue StandardError
        false
      end
    end
  end
end
