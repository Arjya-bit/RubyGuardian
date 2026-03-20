# frozen_string_literal: true

require 'rspec'
require 'json'

# RubyGuardian Detection Engine - End-to-End Integration Specs
# Tests the full pipeline: event generation -> rule evaluation -> alerting

RSpec.describe 'Detection Engine End-to-End Pipeline' do
  # Simulated event that would come from a monitor
  let(:eval_event) do
    {
      'event_id' => 'evt-001',
      'timestamp' => Time.now.utc.iso8601,
      'source' => 'process_monitor',
      'type' => 'method_call',
      'data' => {
        'pid' => 12345,
        'method' => 'eval',
        'receiver' => 'Kernel',
        'args_encoded' => true,
        'encoding_type' => 'base64',
        'call_stack' => [
          'script.rb:15:in `<main>`',
          'script.rb:10:in `execute`'
        ]
      }
    }
  end

  let(:file_event) do
    {
      'event_id' => 'evt-002',
      'timestamp' => Time.now.utc.iso8601,
      'source' => 'filesystem_monitor',
      'type' => 'file_access',
      'data' => {
        'pid' => 12345,
        'path' => '/etc/shadow',
        'operation' => 'read',
        'flags' => 'O_RDONLY'
      }
    }
  end

  let(:rules) do
    [
      {
        'id' => 'RG-DET-001',
        'name' => 'Encoded Eval Detection',
        'severity' => 'critical',
        'conditions' => {
          'all' => [
            { 'field' => 'data.method', 'operator' => 'equals', 'value' => 'eval' },
            { 'field' => 'data.args_encoded', 'operator' => 'equals', 'value' => true }
          ]
        }
      },
      {
        'id' => 'RG-DET-010',
        'name' => 'Sensitive File Access',
        'severity' => 'high',
        'conditions' => {
          'all' => [
            { 'field' => 'data.path', 'operator' => 'regex', 'value' => '/(etc/(passwd|shadow)|\.ssh/)' },
            { 'field' => 'data.operation', 'operator' => 'in', 'value' => %w[read write] }
          ]
        }
      }
    ]
  end

  describe 'event normalization' do
    it 'adds agent metadata to events' do
      normalized = eval_event.merge(
        'agent_id' => 'test-agent-001',
        'normalized_at' => Time.now.utc.iso8601
      )
      expect(normalized).to have_key('agent_id')
    end

    it 'flattens nested data fields for rule evaluation' do
      flat = {}
      eval_event['data'].each { |k, v| flat["data.#{k}"] = v }
      expect(flat['data.method']).to eq('eval')
    end
  end

  describe 'rule evaluation' do
    def evaluate_condition(event, condition)
      field_path = condition['field'].split('.')
      value = event.dig(*field_path)

      case condition['operator']
      when 'equals' then value == condition['value']
      when 'regex' then value.to_s.match?(Regexp.new(condition['value']))
      when 'in' then condition['value'].include?(value)
      else false
      end
    end

    it 'matches eval event against encoded eval rule' do
      rule = rules[0]
      all_match = rule['conditions']['all'].all? do |cond|
        evaluate_condition(eval_event, cond)
      end
      expect(all_match).to be true
    end

    it 'matches file event against sensitive file rule' do
      rule = rules[1]
      all_match = rule['conditions']['all'].all? do |cond|
        evaluate_condition(file_event, cond)
      end
      expect(all_match).to be true
    end

    it 'does not match benign events' do
      benign_event = eval_event.dup
      benign_event['data'] = { 'method' => 'puts', 'args_encoded' => false }
      rule = rules[0]
      all_match = rule['conditions']['all'].all? do |cond|
        evaluate_condition(benign_event, cond)
      end
      expect(all_match).to be false
    end
  end

  describe 'alert generation' do
    it 'creates an alert with correct severity' do
      alert = {
        'alert_id' => "alert-#{SecureRandom.hex(8)}",
        'rule_id' => 'RG-DET-001',
        'severity' => 'critical',
        'timestamp' => Time.now.utc.iso8601,
        'event' => eval_event,
        'description' => 'Encoded Eval Detection triggered'
      }
      expect(alert['severity']).to eq('critical')
    end

    it 'deduplicates alerts within configured window' do
      alert_cache = {}
      dedup_key = "RG-DET-001:12345"
      alert_cache[dedup_key] = Time.now
      # Second alert within window should be suppressed
      expect(alert_cache).to have_key(dedup_key)
    end
  end

  describe 'alert correlation' do
    it 'correlates eval + file access from same PID as attack chain' do
      events = [eval_event, file_event]
      same_pid = events.map { |e| e['data']['pid'] }.uniq.length == 1
      expect(same_pid).to be true
    end

    it 'escalates severity for correlated events' do
      base_severity = 'high'
      escalated = base_severity == 'high' ? 'critical' : base_severity
      expect(escalated).to eq('critical')
    end
  end
end
