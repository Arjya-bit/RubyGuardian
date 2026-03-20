# frozen_string_literal: true

require 'time'

module RubyGuardian
  module DetectionEngine
    module Agent
      # Collects and exposes Prometheus-compatible metrics for the detection engine.
      # Supports counters, gauges, histograms, and summaries. Provides a text-based
      # exposition format compatible with Prometheus scraping.
      class MetricCollector
        METRIC_TYPES = %i[counter gauge histogram summary].freeze

        HISTOGRAM_DEFAULT_BUCKETS = [
          0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0
        ].freeze

        attr_reader :prefix

        def initialize(options = {})
          @prefix   = options.fetch(:prefix, 'rubyguardian')
          @metrics  = {}
          @mutex    = Mutex.new
          @start_time = Time.now

          register_default_metrics
        end

        # Register a new counter metric.
        #
        # @param name [Symbol] metric name
        # @param help [String] metric description
        # @param labels [Array<Symbol>] label names
        def register_counter(name, help:, labels: [])
          register_metric(name, :counter, help: help, labels: labels, value: 0)
        end

        # Register a new gauge metric.
        #
        # @param name [Symbol] metric name
        # @param help [String] metric description
        # @param labels [Array<Symbol>] label names
        def register_gauge(name, help:, labels: [])
          register_metric(name, :gauge, help: help, labels: labels, value: 0)
        end

        # Register a new histogram metric.
        #
        # @param name [Symbol] metric name
        # @param help [String] metric description
        # @param labels [Array<Symbol>] label names
        # @param buckets [Array<Float>] histogram bucket boundaries
        def register_histogram(name, help:, labels: [], buckets: HISTOGRAM_DEFAULT_BUCKETS)
          register_metric(name, :histogram, help: help, labels: labels,
                          buckets: buckets.sort, sum: 0.0, count: 0, observations: {})
        end

        # Increment a counter.
        #
        # @param name [Symbol] metric name
        # @param by [Numeric] increment value (default 1)
        # @param labels [Hash] label values
        def increment(name, by: 1, labels: {})
          @mutex.synchronize do
            metric = fetch_metric!(name, :counter)
            key = label_key(labels)
            metric[:values][key] ||= 0
            metric[:values][key] += by
          end
        end

        # Set a gauge value.
        #
        # @param name [Symbol] metric name
        # @param value [Numeric] gauge value
        # @param labels [Hash] label values
        def set(name, value, labels: {})
          @mutex.synchronize do
            metric = fetch_metric!(name, :gauge)
            key = label_key(labels)
            metric[:values][key] = value
          end
        end

        # Increment a gauge.
        def gauge_increment(name, by: 1, labels: {})
          @mutex.synchronize do
            metric = fetch_metric!(name, :gauge)
            key = label_key(labels)
            metric[:values][key] ||= 0
            metric[:values][key] += by
          end
        end

        # Decrement a gauge.
        def gauge_decrement(name, by: 1, labels: {})
          gauge_increment(name, by: -by, labels: labels)
        end

        # Observe a value for a histogram.
        #
        # @param name [Symbol] metric name
        # @param value [Float] observed value
        # @param labels [Hash] label values
        def observe(name, value, labels: {})
          @mutex.synchronize do
            metric = fetch_metric!(name, :histogram)
            key = label_key(labels)
            metric[:observations][key] ||= { sum: 0.0, count: 0, buckets: {} }
            obs = metric[:observations][key]
            obs[:sum] += value
            obs[:count] += 1

            metric[:buckets].each do |bound|
              obs[:buckets][bound] ||= 0
              obs[:buckets][bound] += 1 if value <= bound
            end
          end
        end

        # Measure the duration of a block and observe it in a histogram.
        #
        # @param name [Symbol] histogram metric name
        # @param labels [Hash] label values
        def time(name, labels: {})
          start = Process.clock_gettime(Process::CLOCK_MONOTONIC)
          result = yield
          duration = Process.clock_gettime(Process::CLOCK_MONOTONIC) - start
          observe(name, duration, labels: labels)
          result
        end

        # Get the current value of a metric.
        #
        # @param name [Symbol] metric name
        # @param labels [Hash] label values
        # @return [Numeric, nil]
        def get(name, labels: {})
          @mutex.synchronize do
            metric = @metrics[name]
            return nil unless metric

            key = label_key(labels)
            case metric[:type]
            when :counter, :gauge
              metric[:values][key]
            when :histogram
              metric[:observations].dig(key, :count)
            end
          end
        end

        # Generate Prometheus text exposition format output.
        #
        # @return [String] Prometheus-compatible metrics text
        def to_prometheus
          @mutex.synchronize do
            lines = []

            @metrics.each do |name, metric|
              fqn = "#{@prefix}_#{name}"
              lines << "# HELP #{fqn} #{metric[:help]}"
              lines << "# TYPE #{fqn} #{metric[:type]}"

              case metric[:type]
              when :counter, :gauge
                render_simple_metric(lines, fqn, metric)
              when :histogram
                render_histogram(lines, fqn, metric)
              end

              lines << ''
            end

            lines.join("\n")
          end
        end

        # Reset all metrics to their initial values.
        def reset!
          @mutex.synchronize do
            @metrics.each_value do |metric|
              case metric[:type]
              when :counter, :gauge
                metric[:values].clear
              when :histogram
                metric[:observations].clear
              end
            end
          end
        end

        private

        def register_metric(name, type, **opts)
          @mutex.synchronize do
            @metrics[name] = {
              type:   type,
              help:   opts[:help],
              labels: opts.fetch(:labels, []),
              values: {},
              buckets: opts[:buckets],
              observations: opts[:observations] || {}
            }
          end
        end

        def register_default_metrics
          register_counter :events_received_total,
                           help: 'Total number of events received by the pipeline'
          register_counter :events_processed_total,
                           help: 'Total number of events successfully processed',
                           labels: [:stage]
          register_counter :alerts_generated_total,
                           help: 'Total number of alerts generated',
                           labels: [:severity]
          register_counter :errors_total,
                           help: 'Total number of processing errors',
                           labels: [:stage]
          register_gauge   :pipeline_queue_size,
                           help: 'Current number of events in the processing queue'
          register_gauge   :active_rules_count,
                           help: 'Number of currently loaded detection rules'
          register_histogram :event_processing_duration_seconds,
                             help: 'Time spent processing each event',
                             labels: [:stage]
          register_histogram :alert_dispatch_duration_seconds,
                             help: 'Time spent dispatching each alert',
                             labels: [:channel]
        end

        def fetch_metric!(name, expected_type)
          metric = @metrics[name]
          raise MetricError, "Unknown metric: #{name}" unless metric
          unless metric[:type] == expected_type
            raise MetricError, "Metric #{name} is #{metric[:type]}, not #{expected_type}"
          end
          metric
        end

        def label_key(labels)
          labels.sort.map { |k, v| "#{k}=#{v}" }.join(',')
        end

        def render_simple_metric(lines, fqn, metric)
          if metric[:values].empty?
            lines << "#{fqn} 0"
          else
            metric[:values].each do |key, value|
              if key.empty?
                lines << "#{fqn} #{value}"
              else
                lines << "#{fqn}{#{key}} #{value}"
              end
            end
          end
        end

        def render_histogram(lines, fqn, metric)
          metric[:observations].each do |key, obs|
            label_prefix = key.empty? ? '' : "#{key},"

            metric[:buckets].each do |bound|
              count = obs[:buckets].fetch(bound, 0)
              lines << "#{fqn}_bucket{#{label_prefix}le=\"#{bound}\"} #{count}"
            end
            lines << "#{fqn}_bucket{#{label_prefix}le=\"+Inf\"} #{obs[:count]}"
            lines << "#{fqn}_sum{#{key}} #{obs[:sum]}"
            lines << "#{fqn}_count{#{key}} #{obs[:count]}"
          end
        end
      end

      class MetricError < StandardError; end
    end
  end
end
