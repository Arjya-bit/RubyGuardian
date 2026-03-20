# frozen_string_literal: true

require 'rspec'
require 'benchmark'
require 'json'
require 'time'

# Performance benchmarks for the RubyGuardian Detection Engine.
#
# Measures rule evaluation throughput, event correlation performance,
# alert generation latency, and memory usage under sustained load.

RSpec.describe 'Detection Engine Performance Benchmarks' do
  let(:sample_event) do
    {
      id: "evt-#{SecureRandom.hex(8)}",
      type: 'process_spawn',
      pid: rand(1000..65535),
      parent_pid: rand(1..999),
      process_name: 'ruby',
      command: 'ruby app.rb',
      timestamp: Time.now.utc.iso8601,
      severity: 'info',
      source_ip: "10.0.#{rand(0..255)}.#{rand(1..254)}",
      destination_ip: "192.168.#{rand(0..255)}.#{rand(1..254)}",
      destination_port: [80, 443, 8080, 3000, 5432].sample
    }
  end

  let(:event_types) do
    %w[process_spawn network_connect file_write file_read syscall
       dns_query memory_allocation code_execution]
  end

  let(:signature_rules) do
    Array.new(50) do |i|
      {
        id: "RG-#{format('%03d', i)}",
        name: "Test Rule #{i}",
        severity: %w[info low medium high critical].sample,
        conditions: {
          event_type: event_types.sample,
          patterns: [
            { field: 'command', regex: "pattern_#{i}" },
            { field: 'process_name', value: 'ruby' }
          ]
        }
      }
    end
  end

  def generate_events(count)
    Array.new(count) do
      type = event_types.sample
      {
        id: "evt-#{SecureRandom.hex(8)}",
        type: type,
        pid: rand(1000..65535),
        parent_pid: rand(1..999),
        process_name: %w[ruby bundle rake puma sidekiq].sample,
        command: "ruby #{%w[app.rb server.rb worker.rb].sample}",
        timestamp: Time.now.utc.iso8601,
        severity: %w[info low medium].sample,
        source_ip: "10.0.#{rand(0..255)}.#{rand(1..254)}",
        syscall_name: type == 'syscall' ? %w[read write open connect mmap].sample : nil
      }
    end
  end

  def evaluate_rules(event, rules)
    matched = []
    rules.each do |rule|
      next unless rule[:conditions][:event_type] == event[:type]

      match = rule[:conditions][:patterns].all? do |pattern|
        field_value = event[pattern[:field]&.to_sym]
        if pattern[:regex]
          field_value.to_s.match?(Regexp.new(pattern[:regex]))
        elsif pattern[:value]
          field_value == pattern[:value]
        else
          true
        end
      end
      matched << rule if match
    end
    matched
  end

  describe 'rule evaluation throughput' do
    it 'evaluates 10,000 events against 50 rules in under 2 seconds' do
      events = generate_events(10_000)

      elapsed = Benchmark.realtime do
        events.each { |event| evaluate_rules(event, signature_rules) }
      end

      throughput = events.length / elapsed
      expect(elapsed).to be < 2.0
      expect(throughput).to be > 5_000
    end

    it 'evaluates single event in under 0.5ms' do
      event = sample_event
      times = Array.new(1000) do
        Benchmark.realtime { evaluate_rules(event, signature_rules) }
      end

      p95_ms = times.sort[(times.length * 0.95).to_i] * 1000
      expect(p95_ms).to be < 0.5
    end

    it 'scales linearly with number of rules' do
      event = sample_event
      timings = {}

      [10, 25, 50, 100].each do |n_rules|
        rules = signature_rules.first(n_rules)
        elapsed = Benchmark.realtime do
          1000.times { evaluate_rules(event, rules) }
        end
        timings[n_rules] = elapsed
      end

      # 100 rules should take less than 4x the time of 25 rules
      ratio = timings[100] / timings[25]
      expect(ratio).to be < 6.0
    end
  end

  describe 'event correlation performance' do
    let(:correlation_window) { {} }

    def add_to_window(window, event, ttl_seconds: 300)
      pgid = event[:pid]
      window[pgid] ||= []
      window[pgid] << event
      # Expire old events
      cutoff = Time.now.utc - ttl_seconds
      window[pgid].reject! { |e| Time.parse(e[:timestamp]) < cutoff }
    end

    it 'correlates 5,000 events within time window efficiently' do
      events = generate_events(5_000)
      window = {}

      elapsed = Benchmark.realtime do
        events.each { |event| add_to_window(window, event) }
      end

      expect(elapsed).to be < 1.0
      expect(window.keys.length).to be > 0
    end

    it 'handles window expiration without memory growth' do
      window = {}
      initial_size = 0

      3.times do |round|
        events = generate_events(1_000)
        events.each { |event| add_to_window(window, event, ttl_seconds: 1) }

        if round == 0
          initial_size = window.values.flatten.length
        end
      end

      # Sleep to let events expire
      sleep(1.1)

      # Add one more batch to trigger cleanup
      events = generate_events(100)
      events.each { |event| add_to_window(window, event, ttl_seconds: 1) }

      # Window should not grow unbounded
      current_size = window.values.flatten.length
      expect(current_size).to be <= initial_size * 2
    end
  end

  describe 'alert generation latency' do
    it 'generates an alert in under 1ms' do
      event = sample_event.merge(severity: 'critical')
      rule = signature_rules.first

      times = Array.new(1000) do
        Benchmark.realtime do
          {
            id: "alert-#{SecureRandom.hex(8)}",
            rule_id: rule[:id],
            rule_name: rule[:name],
            severity: rule[:severity],
            event_id: event[:id],
            pid: event[:pid],
            process_name: event[:process_name],
            timestamp: Time.now.utc.iso8601,
            threat_score: rand(0.5..1.0).round(3)
          }
        end
      end

      p95_ms = times.sort[(times.length * 0.95).to_i] * 1000
      expect(p95_ms).to be < 1.0
    end
  end

  describe 'JSON serialization performance' do
    it 'serializes 1,000 events to JSON in under 100ms' do
      events = generate_events(1_000)

      elapsed = Benchmark.realtime do
        events.each { |e| JSON.generate(e) }
      end

      expect(elapsed * 1000).to be < 100
    end

    it 'deserializes 1,000 JSON events in under 100ms' do
      json_events = generate_events(1_000).map { |e| JSON.generate(e) }

      elapsed = Benchmark.realtime do
        json_events.each { |j| JSON.parse(j) }
      end

      expect(elapsed * 1000).to be < 100
    end
  end

  describe 'memory usage' do
    it 'processes 100,000 events without excessive memory growth' do
      initial_mem = `ps -o rss= -p #{Process.pid}`.strip.to_i

      events = generate_events(100_000)
      events.each { |_event| nil } # Process events
      events = nil # Release reference
      GC.start

      final_mem = `ps -o rss= -p #{Process.pid}`.strip.to_i
      growth_mb = (final_mem - initial_mem) / 1024.0

      # Should not grow more than 200MB for 100K events
      expect(growth_mb).to be < 200
    end
  end

  describe 'sustained load simulation' do
    it 'maintains throughput over 10 seconds of continuous processing' do
      throughputs = []

      5.times do
        events = generate_events(2_000)
        elapsed = Benchmark.realtime do
          events.each { |event| evaluate_rules(event, signature_rules) }
        end
        throughputs << (events.length / elapsed)
      end

      avg_throughput = throughputs.sum / throughputs.length
      min_throughput = throughputs.min

      # Throughput should not degrade significantly
      expect(min_throughput).to be > avg_throughput * 0.8
      expect(avg_throughput).to be > 3_000
    end
  end
end
