# frozen_string_literal: true

require 'time'
require 'securerandom'

module RubyGuardian
  module DetectionEngine
    module Agent
      # Event processing pipeline that executes stages in order:
      # normalize -> enrich -> evaluate -> alert. Supports middleware-style
      # stage injection, error handling per stage, and backpressure signaling.
      class EventPipeline
        STAGES = %i[normalize enrich evaluate alert].freeze

        attr_reader :stats, :stage_config

        def initialize(options = {})
          @normalizers   = []
          @enrichers     = []
          @evaluator     = options.fetch(:evaluator, nil)
          @alerter       = options.fetch(:alerter, nil)
          @correlation   = options.fetch(:correlation_engine, nil)
          @error_handler = options.fetch(:error_handler, method(:default_error_handler))
          @filters       = options.fetch(:filters, [])
          @batch_size    = options.fetch(:batch_size, 100)
          @middleware     = { normalize: [], enrich: [], evaluate: [], alert: [] }
          @stats = {
            received: 0, normalized: 0, enriched: 0, evaluated: 0,
            alerted: 0, filtered: 0, errors: 0, dropped: 0
          }
          @mutex = Mutex.new
          @running = false
        end

        # Register a normalizer that transforms raw events into a standard format.
        #
        # @param normalizer [#call] object responding to #call(event) -> event
        def add_normalizer(normalizer)
          @normalizers << normalizer
        end

        # Register an enrichment source that adds context to events.
        #
        # @param enricher [#call] object responding to #call(event) -> event
        def add_enricher(enricher)
          @enrichers << enricher
        end

        # Register middleware for a specific pipeline stage.
        #
        # @param stage [Symbol] one of STAGES
        # @param middleware [#call]
        def use(stage, middleware)
          unless STAGES.include?(stage)
            raise ArgumentError, "Unknown stage: #{stage}. Valid: #{STAGES.join(', ')}"
          end
          @middleware[stage] << middleware
        end

        # Process a single event through the full pipeline.
        #
        # @param raw_event [Hash] the raw event data
        # @return [PipelineResult] processing result
        def process(raw_event)
          @stats[:received] += 1
          result = PipelineResult.new(event_id: SecureRandom.uuid, stages: {})

          begin
            # Stage 1: Normalize
            event = run_stage(:normalize, raw_event, result) do |evt|
              normalize_event(evt)
            end
            return result.finalize(:filtered) if event.nil?

            # Pre-evaluation filtering
            if filtered?(event)
              @stats[:filtered] += 1
              return result.finalize(:filtered)
            end

            # Stage 2: Enrich
            event = run_stage(:enrich, event, result) do |evt|
              enrich_event(evt)
            end
            return result.finalize(:enrichment_failed) if event.nil?

            # Stage 3: Evaluate
            eval_results = run_stage(:evaluate, event, result) do |evt|
              evaluate_event(evt)
            end

            # Stage 4: Alert on matches
            if eval_results && !eval_results.empty?
              run_stage(:alert, [event, eval_results], result) do |payload|
                dispatch_alerts(payload[0], payload[1])
              end
            end

            # Correlation check
            if @correlation && eval_results
              check_correlations(eval_results, event)
            end

            result.finalize(:completed)
          rescue => e
            @stats[:errors] += 1
            @error_handler.call(e, raw_event)
            result.finalize(:error, error: e.message)
          end

          result
        end

        # Process a batch of events.
        #
        # @param events [Array<Hash>] raw events
        # @return [Array<PipelineResult>] results
        def process_batch(events)
          events.map { |e| process(e) }
        end

        # Start the pipeline (for continuous processing mode).
        def start
          @running = true
        end

        # Stop the pipeline gracefully.
        def stop
          @running = false
        end

        # Check if pipeline is running.
        def running?
          @running
        end

        private

        def run_stage(stage_name, input, result)
          start_time = Time.now

          # Run pre-middleware
          current = input
          @middleware[stage_name].each do |mw|
            current = mw.call(current, stage_name)
          end

          output = yield(current)
          @stats[stage_stat_key(stage_name)] += 1

          result.stages[stage_name] = {
            status: :ok,
            duration_ms: ((Time.now - start_time) * 1000).round(2)
          }

          output
        rescue => e
          result.stages[stage_name] = {
            status: :error,
            error: e.message,
            duration_ms: ((Time.now - start_time) * 1000).round(2)
          }
          @error_handler.call(e, input)
          nil
        end

        def normalize_event(event)
          normalized = event.dup
          normalized[:_pipeline_id] = SecureRandom.uuid
          normalized[:_received_at] = Time.now.utc

          @normalizers.each do |normalizer|
            normalized = normalizer.call(normalized)
            break if normalized.nil?
          end

          # Ensure standard fields exist
          if normalized
            normalized[:timestamp] ||= Time.now.utc
            normalized[:event_type] ||= 'unknown'
            normalized[:source_ip] ||= 'unknown'
          end

          normalized
        end

        def enrich_event(event)
          enriched = event.dup

          @enrichers.each do |enricher|
            begin
              enriched = enricher.call(enriched)
            rescue => e
              enriched[:_enrichment_errors] ||= []
              enriched[:_enrichment_errors] << e.message
            end
          end

          enriched
        end

        def evaluate_event(event)
          return [] unless @evaluator

          if @evaluator.respond_to?(:evaluate_all)
            @evaluator.evaluate_all(event)
          else
            result = @evaluator.evaluate(event)
            result.matched ? [result] : []
          end
        end

        def dispatch_alerts(event, eval_results)
          return unless @alerter

          eval_results.each do |result|
            alert_data = build_alert(event, result)
            @alerter.dispatch(alert_data)
            @stats[:alerted] += 1
          end
        end

        def check_correlations(eval_results, event)
          eval_results.each do |result|
            matches = @correlation.process(result, event)
            matches.each do |match|
              alert_data = build_correlation_alert(match)
              @alerter&.dispatch(alert_data)
            end
          end
        end

        def build_alert(event, eval_result)
          {
            alert_id:     SecureRandom.uuid,
            rule_id:      eval_result.rule_id,
            rule_name:    eval_result.rule_name,
            severity:     eval_result.severity,
            timestamp:    Time.now.utc,
            event_type:   event[:event_type],
            source_ip:    event[:source_ip],
            dest_ip:      event[:dest_ip],
            source_user:  event[:source_user],
            process_name: event[:process_name],
            command_line: event[:command_line],
            raw_event:    event
          }
        end

        def build_correlation_alert(match)
          {
            alert_id:     match.id,
            rule_id:      match.correlation_rule_id,
            rule_name:    match.correlation_rule_name,
            severity:     match.severity,
            timestamp:    match.matched_at,
            event_type:   'correlation',
            correlated_events: match.matched_events.size,
            mitre_attack: match.mitre_attack
          }
        end

        def filtered?(event)
          @filters.any? { |f| f.call(event) }
        end

        def stage_stat_key(stage)
          { normalize: :normalized, enrich: :enriched,
            evaluate: :evaluated, alert: :alerted }[stage] || stage
        end

        def default_error_handler(error, _context)
          $stderr.puts "[EventPipeline] Error: #{error.message}"
        end
      end

      # Result from processing an event through the pipeline.
      class PipelineResult
        attr_accessor :event_id, :stages, :status, :error

        def initialize(event_id:, stages: {})
          @event_id = event_id
          @stages = stages
          @status = :pending
          @error = nil
        end

        def finalize(status, error: nil)
          @status = status
          @error = error
          self
        end

        def success?
          @status == :completed
        end
      end
    end
  end
end
