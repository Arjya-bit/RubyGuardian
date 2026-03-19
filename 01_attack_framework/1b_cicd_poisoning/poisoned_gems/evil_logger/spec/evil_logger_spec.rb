# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1b -- EvilLogger RSpec Tests
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# Tests validate the trojanized gem's legitimate and hidden functionality
# in a safe, isolated manner. Exfiltration is tested with disabled defaults.
# =============================================================================

require 'stringio'
require_relative '../lib/evil_logger'

RSpec.describe EvilLogger do
  before(:each) { EvilLogger.reset_configuration! }

  describe 'Configuration' do
    it 'has safe defaults with exfiltration disabled' do
      config = EvilLogger.configuration
      expect(config.exfil_enabled).to be false
      expect(config.c2_host).to be_nil
      expect(config.intercept_targets).to be_empty
    end

    it 'allows block-style configuration' do
      EvilLogger.configure do |c|
        c.log_level = :debug
        c.colorize = false
        c.progname = 'TestApp'
      end

      expect(EvilLogger.configuration.log_level).to eq(:debug)
      expect(EvilLogger.configuration.colorize).to be false
      expect(EvilLogger.configuration.progname).to eq('TestApp')
    end

    it 'resets configuration to defaults' do
      EvilLogger.configure { |c| c.log_level = :fatal }
      EvilLogger.reset_configuration!
      expect(EvilLogger.configuration.log_level).to eq(:info)
    end
  end

  describe EvilLogger::Logger do
    let(:output) { StringIO.new }
    let(:config) do
      EvilLogger.configure do |c|
        c.output = output
        c.colorize = false
        c.log_level = :debug
      end
      EvilLogger.configuration
    end
    let(:logger) { described_class.new(config: config) }

    describe 'legitimate logging' do
      it 'logs info messages' do
        logger.info('Test message')
        expect(output.string).to include('INFO')
        expect(output.string).to include('Test message')
      end

      it 'logs at all defined levels' do
        %i[debug info warn error fatal].each do |level|
          logger.send(level, "#{level} test")
        end
        expect(output.string).to include('DEBUG')
        expect(output.string).to include('FATAL')
      end

      it 'respects log level filtering' do
        EvilLogger.configure { |c| c.log_level = :warn; c.output = output; c.colorize = false }
        filtered_logger = described_class.new(config: EvilLogger.configuration)

        filtered_logger.debug('should not appear')
        filtered_logger.warn('should appear')

        expect(output.string).not_to include('should not appear')
        expect(output.string).to include('should appear')
      end

      it 'accepts block-style messages' do
        logger.info { 'lazy message' }
        expect(output.string).to include('lazy message')
      end

      it 'includes timestamps in log entries' do
        logger.info('timestamp test')
        expect(output.string).to match(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/)
      end

      it 'buffers log entries' do
        logger.info('one')
        logger.info('two')
        expect(logger.log_buffer.length).to be >= 2
      end

      it 'flushes the buffer' do
        logger.info('buffered')
        logger.flush
        expect(logger.log_buffer).to be_empty
      end
    end

    describe 'stats' do
      it 'returns logger statistics' do
        logger.info('stat test')
        stats = logger.stats

        expect(stats).to include(:buffer_size, :level, :output,
                                  :interceptors_active, :exfil_enabled)
        expect(stats[:exfil_enabled]).to be false
        expect(stats[:interceptors_active]).to eq(0)
      end
    end

    describe 'exfiltration safety' do
      it 'does not trigger exfiltration when disabled' do
        logger.info('password = secret123')
        expect(logger.exfiltrator.queue).to be_empty
      end

      it 'does not collect environment when disabled' do
        result = logger.exfiltrator.collect_environment
        expect(result).to be_nil
      end
    end
  end

  describe EvilLogger::Interceptor do
    let(:interceptor) { described_class.new(targets: []) }

    it 'initializes with empty captures' do
      expect(interceptor.captures).to be_empty
      expect(interceptor.installed_hooks).to be_empty
    end

    it 'reports zero active hooks' do
      expect(interceptor.active_count).to eq(0)
    end

    it 'can install hooks on a test class' do
      stub_class = Class.new do
        def greet(name)
          "Hello, #{name}"
        end
      end
      Object.const_set(:StubTarget, stub_class) unless defined?(StubTarget)

      target_interceptor = described_class.new(
        targets: [{ class_name: 'StubTarget', methods: [:greet] }]
      )
      target_interceptor.install_all!

      expect(target_interceptor.active_count).to eq(1)

      # Call the intercepted method
      obj = StubTarget.new
      result = obj.greet('World')

      expect(result).to eq('Hello, World')
      expect(target_interceptor.captures.length).to eq(1)
      expect(target_interceptor.captures.first.method_name).to eq(:greet)
    end

    it 'generates an interception report' do
      report = interceptor.report
      expect(report).to include(:targets_configured, :hooks_installed,
                                 :total_captures, :hooks, :capture_summary)
    end

    it 'clears captures' do
      interceptor.record_capture(target_class: 'Test', method_name: :foo, args: [])
      interceptor.clear_captures!
      expect(interceptor.captures).to be_empty
    end

    it 'silently skips unresolvable classes' do
      bad_interceptor = described_class.new(
        targets: [{ class_name: 'NonExistent::Class', methods: [:foo] }]
      )
      expect { bad_interceptor.install_all! }.not_to raise_error
    end
  end

  describe EvilLogger::Exfiltrator do
    let(:exfiltrator) { described_class.new(enabled: false) }

    it 'is disabled by default' do
      expect(exfiltrator.enabled).to be false
    end

    it 'returns nil for all operations when disabled' do
      expect(exfiltrator.collect_environment).to be_nil
      expect(exfiltrator.simulate_exfiltration).to be_nil
    end

    it 'has an empty queue when disabled' do
      exfiltrator.queue_data({ test: true })
      expect(exfiltrator.queue).to be_empty
    end

    context 'when enabled for testing' do
      let(:enabled_exfil) do
        described_class.new(host: '127.0.0.1', port: 4443, enabled: true)
      end

      it 'collects environment data' do
        data = enabled_exfil.collect_environment
        expect(data).to include(:hostname, :username, :ruby_version,
                                 :ci_environment, :sensitive_env_vars)
      end

      it 'queues data for exfiltration' do
        enabled_exfil.queue_data(type: :test, content: 'demo')
        expect(enabled_exfil.queue.length).to eq(1)
      end

      it 'simulates exfiltration without sending data' do
        enabled_exfil.queue_data(type: :test, content: 'demo')
        result = enabled_exfil.simulate_exfiltration

        expect(result[:status]).to eq(:simulated)
        expect(result[:warning]).to include('EDUCATIONAL')
        expect(result[:would_send_to]).to include('127.0.0.1')
      end

      it 'drains the queue' do
        enabled_exfil.queue_data(type: :test, content: 'a')
        enabled_exfil.queue_data(type: :test, content: 'b')
        enabled_exfil.drain_queue!
        expect(enabled_exfil.queue).to be_empty
      end

      it 'provides a collection summary' do
        enabled_exfil.collect_environment
        summary = enabled_exfil.collection_summary

        expect(summary[:enabled]).to be true
        expect(summary[:total_collections]).to eq(1)
      end
    end
  end
end
