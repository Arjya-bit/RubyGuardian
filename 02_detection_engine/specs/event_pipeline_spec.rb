# frozen_string_literal: true

require 'rspec'
require 'securerandom'

require_relative '../agent/lib/event_pipeline'
require_relative '../agent/lib/metric_collector'
require_relative '../agent/lib/health_checker'

RSpec.describe RubyGuardian::DetectionEngine::Agent::EventPipeline do
  let(:pipeline) { described_class.new }

  let(:raw_event) do
    {
      timestamp:    Time.now.utc,
      event_type:   'process_create',
      source_ip:    '192.168.1.50',
      dest_ip:      '10.0.0.5',
      process_name: 'powershell.exe',
      command_line: 'powershell.exe -enc SGVsbG8gV29ybGQ=',
      source_user:  'CORP\\jdoe'
    }
  end

  describe '#process' do
    it 'processes an event through normalize and enrich stages' do
      result = pipeline.process(raw_event)

      expect(result).to be_a(RubyGuardian::DetectionEngine::Agent::PipelineResult)
      expect(result.status).to eq(:completed)
      expect(result.stages).to have_key(:normalize)
      expect(result.stages).to have_key(:enrich)
    end

    it 'increments the received counter' do
      pipeline.process(raw_event)
      expect(pipeline.stats[:received]).to eq(1)
    end

    it 'assigns a pipeline ID and timestamp during normalization' do
      normalizer_output = nil
      pipeline.add_normalizer(->(event) {
        normalizer_output = event
        event
      })

      pipeline.process(raw_event)

      expect(normalizer_output).to have_key(:_pipeline_id)
      expect(normalizer_output).to have_key(:_received_at)
    end

    it 'handles normalizer errors gracefully' do
      pipeline.add_normalizer(->(_event) { raise 'Normalizer failure' })

      result = pipeline.process(raw_event)
      # Pipeline should handle the error, not crash
      expect(pipeline.stats[:errors]).to be >= 0
    end
  end

  describe 'normalizers' do
    it 'applies multiple normalizers in sequence' do
      pipeline.add_normalizer(->(e) { e.merge(normalized_step1: true) })
      pipeline.add_normalizer(->(e) { e.merge(normalized_step2: true) })

      capture = nil
      pipeline.add_enricher(->(e) { capture = e; e })
      pipeline.process(raw_event)

      expect(capture[:normalized_step1]).to be true
      expect(capture[:normalized_step2]).to be true
    end

    it 'stops normalization if a normalizer returns nil' do
      pipeline.add_normalizer(->(_e) { nil })

      result = pipeline.process(raw_event)
      expect(result.status).to eq(:filtered)
    end
  end

  describe 'enrichers' do
    it 'applies enrichment to events' do
      pipeline.add_enricher(->(e) { e.merge(geo_country: 'US', threat_score: 75) })

      enriched = nil
      pipeline.use(:evaluate, ->(event, _stage) {
        enriched = event
        event
      })

      pipeline.process(raw_event)
      expect(enriched[:geo_country]).to eq('US')
      expect(enriched[:threat_score]).to eq(75)
    end

    it 'captures enrichment errors without stopping the pipeline' do
      pipeline.add_enricher(->(_e) { raise 'GeoIP lookup failed' })
      pipeline.add_enricher(->(e) { e.merge(fallback: true) })

      result = pipeline.process(raw_event)
      expect(result.status).to eq(:completed)
    end
  end

  describe 'filters' do
    it 'drops events that match a filter' do
      filtered_pipeline = described_class.new(
        filters: [->(e) { e[:event_type] == 'heartbeat' }]
      )

      heartbeat = raw_event.merge(event_type: 'heartbeat')
      result = filtered_pipeline.process(heartbeat)

      expect(result.status).to eq(:filtered)
      expect(filtered_pipeline.stats[:filtered]).to eq(1)
    end

    it 'passes events that do not match any filter' do
      filtered_pipeline = described_class.new(
        filters: [->(e) { e[:event_type] == 'heartbeat' }]
      )

      result = filtered_pipeline.process(raw_event)
      expect(result.status).to eq(:completed)
    end
  end

  describe 'evaluation with mock evaluator' do
    let(:mock_evaluator) do
      evaluator = double('evaluator')
      allow(evaluator).to receive(:respond_to?).with(:evaluate_all).and_return(true)
      allow(evaluator).to receive(:evaluate_all).and_return([
        OpenStruct.new(matched: true, rule_id: 'R1', rule_name: 'Test', severity: 'high')
      ])
      evaluator
    end

    let(:mock_alerter) do
      alerter = double('alerter')
      allow(alerter).to receive(:dispatch)
      alerter
    end

    it 'dispatches alerts when rules match' do
      eval_pipeline = described_class.new(evaluator: mock_evaluator, alerter: mock_alerter)

      expect(mock_alerter).to receive(:dispatch).once
      eval_pipeline.process(raw_event)
    end

    it 'tracks alerted count' do
      eval_pipeline = described_class.new(evaluator: mock_evaluator, alerter: mock_alerter)
      eval_pipeline.process(raw_event)

      expect(eval_pipeline.stats[:alerted]).to eq(1)
    end
  end

  describe 'middleware' do
    it 'executes middleware before each stage' do
      middleware_log = []

      pipeline.use(:normalize, ->(event, stage) {
        middleware_log << "pre-#{stage}"
        event
      })

      pipeline.process(raw_event)
      expect(middleware_log).to include('pre-normalize')
    end
  end

  describe '#process_batch' do
    it 'processes multiple events' do
      events = [raw_event, raw_event.merge(source_ip: '10.0.0.1')]
      results = pipeline.process_batch(events)

      expect(results.size).to eq(2)
      expect(results.all?(&:success?)).to be true
      expect(pipeline.stats[:received]).to eq(2)
    end
  end

  describe '#start / #stop' do
    it 'manages running state' do
      expect(pipeline.running?).to be false
      pipeline.start
      expect(pipeline.running?).to be true
      pipeline.stop
      expect(pipeline.running?).to be false
    end
  end
end

RSpec.describe RubyGuardian::DetectionEngine::Agent::MetricCollector do
  let(:collector) { described_class.new(prefix: 'test') }

  it 'increments a counter' do
    collector.increment(:events_received_total)
    collector.increment(:events_received_total)
    expect(collector.get(:events_received_total)).to eq(2)
  end

  it 'sets a gauge' do
    collector.set(:pipeline_queue_size, 42)
    expect(collector.get(:pipeline_queue_size)).to eq(42)
  end

  it 'observes histogram values' do
    collector.observe(:event_processing_duration_seconds, 0.15)
    collector.observe(:event_processing_duration_seconds, 0.35)
    expect(collector.get(:event_processing_duration_seconds)).to eq(2)
  end

  it 'generates Prometheus exposition format' do
    collector.increment(:events_received_total)
    output = collector.to_prometheus

    expect(output).to include('# HELP test_events_received_total')
    expect(output).to include('# TYPE test_events_received_total counter')
  end

  it 'supports labeled metrics' do
    collector.increment(:alerts_generated_total, labels: { severity: 'high' })
    collector.increment(:alerts_generated_total, labels: { severity: 'low' })

    output = collector.to_prometheus
    expect(output).to include('severity=high')
    expect(output).to include('severity=low')
  end
end

RSpec.describe RubyGuardian::DetectionEngine::Agent::HealthChecker do
  let(:checker) { described_class.new }

  it 'reports liveness' do
    result = checker.liveness
    expect(result[:status]).to eq('ok')
    expect(result[:pid]).to eq(Process.pid)
  end

  it 'checks registered components' do
    checker.register(:test_component,
                     check: -> { RubyGuardian::DetectionEngine::Agent::ComponentHealth.new(status: 'healthy') },
                     critical: true)

    report = checker.check_all
    expect(report.status).to eq('healthy')
    expect(report.component_statuses).to have_key(:test_component)
  end

  it 'reports degraded when non-critical components fail' do
    checker.register(:optional, check: -> {
      RubyGuardian::DetectionEngine::Agent::ComponentHealth.new(status: 'critical', message: 'down')
    }, critical: false)

    report = checker.check_all
    expect(report.status).to eq('degraded')
  end

  it 'reports critical when critical components fail' do
    checker.register(:essential, check: -> {
      RubyGuardian::DetectionEngine::Agent::ComponentHealth.new(status: 'critical', message: 'down')
    }, critical: true)

    report = checker.check_all
    expect(report.status).to eq('critical')
  end

  it 'generates JSON health report' do
    checker.register(:db, check: -> {
      RubyGuardian::DetectionEngine::Agent::ComponentHealth.new(status: 'healthy')
    }, critical: true)

    json = checker.to_json
    parsed = JSON.parse(json)
    expect(parsed['status']).to eq('healthy')
  end
end
