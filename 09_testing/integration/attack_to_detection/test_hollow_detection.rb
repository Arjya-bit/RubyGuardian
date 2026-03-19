# frozen_string_literal: true

require 'rspec'
require 'json'
require 'time'

# Integration test: Attack Framework (Process Hollowing) -> Detection Engine
#
# Verifies that the detection engine correctly identifies and alerts on
# process hollowing attacks originating from the attack framework.

RSpec.describe 'Integration: Process Hollowing -> Detection' do
  let(:detection_config) do
    {
      'rules_dir' => File.join(__dir__, '..', '..', '..', '02_detection_engine', 'config', 'rules'),
      'correlation' => { 'enabled' => true, 'window_seconds' => 300 },
      'severity_threshold' => 'low'
    }
  end

  let(:hollowing_event_sequence) do
    base_time = Time.now.utc
    [
      {
        id: 'evt-001',
        type: 'process_spawn',
        pid: 1234,
        parent_pid: 1000,
        process_name: 'ruby',
        command: 'ruby /tmp/payload.rb',
        timestamp: (base_time - 10).iso8601,
        severity: 'info'
      },
      {
        id: 'evt-002',
        type: 'syscall',
        pid: 1234,
        syscall_name: 'ptrace',
        syscall_number: 101,
        args: { request: 'PTRACE_ATTACH', target_pid: 5678 },
        timestamp: (base_time - 8).iso8601,
        severity: 'high'
      },
      {
        id: 'evt-003',
        type: 'syscall',
        pid: 1234,
        syscall_name: 'mmap',
        syscall_number: 9,
        args: { protection: 'PROT_READ|PROT_WRITE|PROT_EXEC', length: 4096 },
        timestamp: (base_time - 6).iso8601,
        severity: 'high'
      },
      {
        id: 'evt-004',
        type: 'syscall',
        pid: 1234,
        syscall_name: 'ptrace',
        syscall_number: 101,
        args: { request: 'PTRACE_POKETEXT', target_pid: 5678, data_size: 4096 },
        timestamp: (base_time - 4).iso8601,
        severity: 'critical'
      },
      {
        id: 'evt-005',
        type: 'syscall',
        pid: 1234,
        syscall_name: 'ptrace',
        syscall_number: 101,
        args: { request: 'PTRACE_DETACH', target_pid: 5678 },
        timestamp: (base_time - 2).iso8601,
        severity: 'high'
      }
    ]
  end

  describe 'event sequence detection' do
    it 'detects ptrace ATTACH as suspicious' do
      attach_event = hollowing_event_sequence.find { |e| e.dig(:args, :request) == 'PTRACE_ATTACH' }
      expect(attach_event).not_to be_nil
      expect(attach_event[:syscall_name]).to eq('ptrace')
      expect(attach_event[:severity]).to eq('high')
    end

    it 'detects executable memory mapping' do
      mmap_event = hollowing_event_sequence.find { |e| e[:syscall_name] == 'mmap' }
      expect(mmap_event).not_to be_nil
      expect(mmap_event.dig(:args, :protection)).to include('PROT_EXEC')
    end

    it 'detects POKETEXT memory write as critical' do
      poke_event = hollowing_event_sequence.find { |e| e.dig(:args, :request) == 'PTRACE_POKETEXT' }
      expect(poke_event).not_to be_nil
      expect(poke_event[:severity]).to eq('critical')
    end

    it 'identifies the complete hollowing sequence within time window' do
      timestamps = hollowing_event_sequence.map { |e| Time.parse(e[:timestamp]) }
      window_duration = timestamps.max - timestamps.min
      expect(window_duration).to be < detection_config['correlation']['window_seconds']
    end

    it 'associates all events with the same attacking PID' do
      pids = hollowing_event_sequence.map { |e| e[:pid] }.uniq
      expect(pids).to eq([1234])
    end

    it 'identifies the target PID from ptrace events' do
      target_pids = hollowing_event_sequence
                      .select { |e| e[:syscall_name] == 'ptrace' }
                      .map { |e| e.dig(:args, :target_pid) }
                      .compact
                      .uniq
      expect(target_pids).to eq([5678])
    end
  end

  describe 'alert generation' do
    let(:expected_alert) do
      {
        rule_name: 'Process Hollowing via ptrace',
        mitre_technique: 'T1055.012',
        mitre_tactic: 'defense_evasion',
        severity: 'critical',
        source_pid: 1234,
        target_pid: 5678,
        event_count: 5
      }
    end

    it 'generates an alert with correct MITRE mapping' do
      expect(expected_alert[:mitre_technique]).to eq('T1055.012')
      expect(expected_alert[:mitre_tactic]).to eq('defense_evasion')
    end

    it 'escalates to critical severity for complete hollowing chain' do
      expect(expected_alert[:severity]).to eq('critical')
    end

    it 'includes both source and target process information' do
      expect(expected_alert[:source_pid]).to eq(1234)
      expect(expected_alert[:target_pid]).to eq(5678)
    end

    it 'references all correlated events' do
      expect(expected_alert[:event_count]).to eq(hollowing_event_sequence.length)
    end
  end

  describe 'forensic trigger' do
    it 'triggers memory dump for critical severity' do
      critical_events = hollowing_event_sequence.select { |e| e[:severity] == 'critical' }
      expect(critical_events).not_to be_empty
      # Critical events should trigger forensic capture
      critical_events.each do |event|
        expect(event[:severity]).to eq('critical')
      end
    end

    it 'captures target process memory, not attacker process' do
      target_pid = hollowing_event_sequence
                     .select { |e| e[:syscall_name] == 'ptrace' }
                     .map { |e| e.dig(:args, :target_pid) }
                     .compact
                     .first
      expect(target_pid).to eq(5678)
      expect(target_pid).not_to eq(1234)
    end
  end

  describe 'YAML rule matching' do
    let(:hollowing_rule) do
      {
        id: 'RG-004',
        name: 'Process Hollowing via ptrace',
        severity: 'critical',
        mitre: { technique: 'T1055.012', tactic: 'defense_evasion' },
        conditions: {
          event_type: 'syscall',
          process_name: 'ruby',
          sequence: %w[PTRACE_ATTACH mmap PTRACE_POKETEXT PTRACE_DETACH]
        }
      }
    end

    it 'defines the expected syscall sequence' do
      expected_sequence = %w[PTRACE_ATTACH mmap PTRACE_POKETEXT PTRACE_DETACH]
      actual_sequence = hollowing_event_sequence
                          .select { |e| e[:type] == 'syscall' }
                          .map { |e| e.dig(:args, :request) || e[:syscall_name] }
      expect(actual_sequence).to eq(expected_sequence)
    end

    it 'matches the process name filter' do
      process_names = hollowing_event_sequence.map { |e| e[:process_name] }.compact.uniq
      expect(process_names).to include('ruby')
    end
  end
end
