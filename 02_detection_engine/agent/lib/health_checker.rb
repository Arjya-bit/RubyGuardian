# frozen_string_literal: true

require 'json'
require 'time'

module RubyGuardian
  module DetectionEngine
    module Agent
      # Health check endpoint and internal component status monitoring.
      # Aggregates health from all subsystems (rule engine, alert channels,
      # event pipeline, correlation engine) and exposes a JSON health report.
      class HealthChecker
        HEALTH_OK       = 'healthy'
        HEALTH_DEGRADED = 'degraded'
        HEALTH_CRITICAL = 'critical'
        HEALTH_UNKNOWN  = 'unknown'

        CHECK_TIMEOUT = 5  # seconds per individual check

        attr_reader :components, :check_results

        def initialize(options = {})
          @components     = {}
          @check_results  = {}
          @check_interval = options.fetch(:check_interval, 30)
          @stale_after    = options.fetch(:stale_after, 90)
          @history_size   = options.fetch(:history_size, 100)
          @check_history  = []
          @mutex          = Mutex.new
          @start_time     = Time.now
          @last_check_at  = nil
          @callbacks       = { on_degraded: [], on_critical: [], on_recovered: [] }
        end

        # Register a component for health monitoring.
        #
        # @param name [Symbol] component identifier
        # @param check [Proc, #call] health check callable returning a ComponentHealth
        # @param critical [Boolean] whether this component is critical to overall health
        def register(name, check:, critical: false)
          @mutex.synchronize do
            @components[name] = {
              check:     check,
              critical:  critical,
              last_status: HEALTH_UNKNOWN,
              registered_at: Time.now
            }
          end
        end

        # Register an event callback.
        #
        # @param event [Symbol] one of :on_degraded, :on_critical, :on_recovered
        # @param callback [Proc]
        def on(event, &callback)
          raise ArgumentError, "Unknown event: #{event}" unless @callbacks.key?(event)
          @callbacks[event] << callback
        end

        # Run all registered health checks.
        #
        # @return [HealthReport] aggregated health report
        def check_all
          results = {}

          @mutex.synchronize do
            @components.each do |name, component|
              results[name] = run_check(name, component)
            end

            @check_results = results
            @last_check_at = Time.now
          end

          report = build_report(results)
          record_history(report)
          fire_callbacks(report)
          report
        end

        # Check a single component.
        #
        # @param name [Symbol] component name
        # @return [ComponentHealth]
        def check(name)
          component = @components[name]
          raise ArgumentError, "Unknown component: #{name}" unless component

          run_check(name, component)
        end

        # Generate the full health report as JSON.
        #
        # @return [String] JSON health report
        def to_json
          report = @check_results.empty? ? check_all : build_report(@check_results)
          JSON.pretty_generate(report_to_hash(report))
        end

        # Quick liveness check (is the process alive and able to respond).
        #
        # @return [Hash] liveness status
        def liveness
          {
            status: 'ok',
            timestamp: Time.now.utc.iso8601,
            uptime_seconds: (Time.now - @start_time).to_i,
            pid: Process.pid
          }
        end

        # Readiness check (are all critical components healthy).
        #
        # @return [Hash] readiness status
        def readiness
          report = check_all
          ready = report.status != HEALTH_CRITICAL
          {
            status: ready ? 'ready' : 'not_ready',
            overall_health: report.status,
            components: report.component_statuses,
            timestamp: Time.now.utc.iso8601
          }
        end

        # Return check history for trend analysis.
        #
        # @param limit [Integer] max history entries to return
        # @return [Array<Hash>]
        def history(limit: 20)
          @check_history.last([limit, @check_history.size].min)
        end

        # Check if health data is stale.
        #
        # @return [Boolean]
        def stale?
          return true if @last_check_at.nil?
          (Time.now - @last_check_at) > @stale_after
        end

        private

        def run_check(name, component)
          start_time = Time.now
          begin
            result = Timeout.timeout(CHECK_TIMEOUT) { component[:check].call }
            duration = Time.now - start_time

            health = if result.is_a?(ComponentHealth)
                        result
                      elsif result.is_a?(Hash)
                        ComponentHealth.new(**result)
                      else
                        ComponentHealth.new(status: result ? HEALTH_OK : HEALTH_CRITICAL)
                      end

            health.duration_ms = (duration * 1000).round(2)
            health.checked_at = Time.now

            previous = component[:last_status]
            component[:last_status] = health.status

            health.recovered = (previous != HEALTH_OK && health.status == HEALTH_OK)
            health
          rescue Timeout::Error
            ComponentHealth.new(
              status: HEALTH_CRITICAL,
              message: "Health check timed out after #{CHECK_TIMEOUT}s",
              checked_at: Time.now,
              duration_ms: (CHECK_TIMEOUT * 1000)
            )
          rescue => e
            ComponentHealth.new(
              status: HEALTH_CRITICAL,
              message: "Health check error: #{e.message}",
              checked_at: Time.now,
              duration_ms: ((Time.now - start_time) * 1000).round(2)
            )
          end
        end

        def build_report(results)
          component_statuses = {}
          overall = HEALTH_OK

          results.each do |name, health|
            component_statuses[name] = {
              status:      health.status,
              message:     health.message,
              duration_ms: health.duration_ms,
              critical:    @components[name][:critical]
            }

            if health.status == HEALTH_CRITICAL && @components[name][:critical]
              overall = HEALTH_CRITICAL
            elsif health.status != HEALTH_OK && overall != HEALTH_CRITICAL
              overall = HEALTH_DEGRADED
            end
          end

          HealthReport.new(
            status:             overall,
            component_statuses: component_statuses,
            uptime_seconds:     (Time.now - @start_time).to_i,
            checked_at:         Time.now,
            stale:              false
          )
        end

        def report_to_hash(report)
          {
            status:     report.status,
            uptime_seconds: report.uptime_seconds,
            checked_at: report.checked_at&.utc&.iso8601,
            pid:        Process.pid,
            components: report.component_statuses
          }
        end

        def record_history(report)
          @check_history << {
            status:     report.status,
            checked_at: report.checked_at,
            component_count: report.component_statuses.size
          }
          @check_history.shift while @check_history.size > @history_size
        end

        def fire_callbacks(report)
          case report.status
          when HEALTH_DEGRADED
            @callbacks[:on_degraded].each { |cb| cb.call(report) }
          when HEALTH_CRITICAL
            @callbacks[:on_critical].each { |cb| cb.call(report) }
          end

          @check_results.each_value do |health|
            if health.respond_to?(:recovered) && health.recovered
              @callbacks[:on_recovered].each { |cb| cb.call(health) }
            end
          end
        end
      end

      # Health status for a single component.
      ComponentHealth = Struct.new(:status, :message, :details, :duration_ms,
                                    :checked_at, :recovered, keyword_init: true)

      # Aggregated health report for all components.
      HealthReport = Struct.new(:status, :component_statuses, :uptime_seconds,
                                 :checked_at, :stale, keyword_init: true)
    end
  end
end
