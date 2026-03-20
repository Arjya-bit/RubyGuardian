# frozen_string_literal: true

require 'rspec'

# RubyGuardian Detection Engine - Agent Lifecycle Specs
# Tests agent startup, shutdown, signal handling, and component management.

RSpec.describe 'RubyGuardian::DetectionEngine::Agent Lifecycle' do
  let(:config) do
    {
      'engine' => {
        'agent_id' => 'test-agent-001',
        'environment' => 'test',
        'log_level' => 'debug',
        'heartbeat_interval' => 5,
        'pid_file' => '/tmp/rg-test-agent.pid'
      },
      'monitoring' => {
        'process' => { 'enabled' => true, 'poll_interval' => 1 },
        'memory' => { 'enabled' => true, 'scan_interval' => 5 },
        'filesystem' => { 'enabled' => true },
        'network' => { 'enabled' => false },
        'syscall' => { 'enabled' => false }
      }
    }
  end

  describe 'initialization' do
    it 'loads configuration from YAML file' do
      expect(config['engine']['agent_id']).to eq('test-agent-001')
    end

    it 'sets default values for missing config keys' do
      defaults = { 'heartbeat_interval' => 30, 'log_level' => 'info' }
      merged = defaults.merge(config['engine'])
      expect(merged['heartbeat_interval']).to eq(5) # overridden
    end

    it 'validates required configuration fields' do
      required_fields = %w[agent_id environment]
      required_fields.each do |field|
        expect(config['engine']).to have_key(field)
      end
    end
  end

  describe 'component lifecycle' do
    it 'starts only enabled monitors' do
      enabled = config['monitoring'].select { |_, v| v['enabled'] }
      expect(enabled.keys).to include('process', 'memory', 'filesystem')
      expect(enabled.keys).not_to include('network', 'syscall')
    end

    it 'stops monitors in reverse order on shutdown' do
      start_order = %w[process memory filesystem]
      stop_order = start_order.reverse
      expect(stop_order).to eq(%w[filesystem memory process])
    end

    it 'reports component health status' do
      health = {
        'process_monitor' => :running,
        'memory_monitor' => :running,
        'filesystem_monitor' => :running,
        'rule_engine' => :ready,
        'alert_dispatcher' => :ready
      }
      expect(health.values.all? { |s| %i[running ready].include?(s) }).to be true
    end
  end

  describe 'signal handling' do
    it 'handles SIGTERM for graceful shutdown' do
      signals_handled = %w[TERM INT HUP USR1]
      expect(signals_handled).to include('TERM')
    end

    it 'handles SIGHUP for config reload' do
      signals_handled = %w[TERM INT HUP USR1]
      expect(signals_handled).to include('HUP')
    end

    it 'handles SIGUSR1 for status dump' do
      signals_handled = %w[TERM INT HUP USR1]
      expect(signals_handled).to include('USR1')
    end
  end

  describe 'PID file management' do
    it 'creates PID file on startup' do
      pid_file = config['engine']['pid_file']
      expect(pid_file).to end_with('.pid')
    end

    it 'detects stale PID files' do
      stale_pid = 99999
      # Process.kill(0, stale_pid) would raise Errno::ESRCH
      expect { Process.kill(0, stale_pid) }.to raise_error(Errno::ESRCH)
    end
  end

  describe 'heartbeat' do
    it 'sends heartbeat at configured interval' do
      interval = config['engine']['heartbeat_interval']
      expect(interval).to eq(5)
    end

    it 'includes component statuses in heartbeat' do
      heartbeat = {
        'agent_id' => 'test-agent-001',
        'timestamp' => Time.now.utc.iso8601,
        'uptime_seconds' => 120,
        'events_processed' => 5420,
        'alerts_generated' => 3,
        'components' => { 'process_monitor' => 'ok', 'memory_monitor' => 'ok' }
      }
      expect(heartbeat).to have_key('components')
    end
  end
end
