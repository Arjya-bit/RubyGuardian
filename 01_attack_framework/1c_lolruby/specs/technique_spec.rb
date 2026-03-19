# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1c -- LoLRuby Technique Module Specs
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# These tests validate individual LoLRuby technique modules to ensure they
# correctly describe attack primitives, produce proper metadata, and operate
# safely in sandbox mode. Understanding technique structure aids defenders
# in building comprehensive detection coverage.
# =============================================================================

require 'rspec'
require_relative '../techniques/execution/eval_executor'
require_relative '../techniques/reconnaissance/network_scan'
require_relative '../techniques/reconnaissance/service_enum'
require_relative '../techniques/reconnaissance/user_enum'
require_relative '../techniques/defense_evasion/string_obfuscator'
require_relative '../techniques/persistence/load_path_hijack'
require_relative '../techniques/credential_access/env_harvester'
require_relative '../techniques/exfiltration/dns_exfiltrator'

RSpec.describe 'LoLRuby Technique Modules' do
  # ─────────────────────────────────────────────────────────────
  # EvalExecutor Tests
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::LoLRuby::Execution::EvalExecutor do
    subject(:executor) { described_class.new(sandbox: true) }

    describe '#initialize' do
      it 'starts with an empty execution log' do
        expect(executor.execution_log).to be_empty
      end

      it 'defaults to sandbox mode' do
        exec = described_class.new
        expect(exec.summary[:sandbox_mode]).to be true
      end
    end

    describe '#demonstrate_eval_chain' do
      it 'logs the execution attempt' do
        executor.demonstrate_eval_chain('puts "test"')
        expect(executor.execution_log.size).to eq(1)
        expect(executor.execution_log.first[:method]).to eq(:kernel_eval)
      end

      it 'does not execute in sandbox mode' do
        result = executor.demonstrate_eval_chain('dangerous_code')
        expect(result[:sandbox]).to be true
        expect(result[:executed]).to be false
      end

      it 'provides a code preview in sandbox results' do
        result = executor.demonstrate_eval_chain('some_code_here')
        expect(result[:code_preview]).to be_a(String)
      end
    end

    describe '#demonstrate_instance_eval' do
      it 'returns technique metadata' do
        result = executor.demonstrate_instance_eval('String')
        expect(result[:technique]).to eq('instance_eval_injection')
        expect(result[:ruby_api]).to include('instance_eval')
      end

      it 'logs the instance_eval demonstration' do
        executor.demonstrate_instance_eval('Hash')
        expect(executor.execution_log.last[:method]).to eq(:instance_eval)
      end
    end

    describe '#demonstrate_dynamic_dispatch' do
      it 'returns dispatch technique details' do
        result = executor.demonstrate_dynamic_dispatch('obj', 'method_name')
        expect(result[:technique]).to eq('dynamic_dispatch')
        expect(result[:ruby_api]).to include('send')
      end
    end

    describe '#summary' do
      it 'reports on all demonstrated techniques' do
        executor.demonstrate_eval_chain('test1')
        executor.demonstrate_instance_eval('String')
        summary = executor.summary
        expect(summary[:techniques_demonstrated]).to eq(2)
        expect(summary[:sandbox_mode]).to be true
      end
    end

    describe '#describe' do
      it 'provides educational description' do
        desc = executor.describe
        expect(desc).to include('T1059.007')
        expect(desc).to include('Kernel.eval')
        expect(desc).to include('Detection')
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # NetworkScan Tests
  # ─────────────────────────────────────────────────────────────
  describe RubyGuardian::LoLRuby::Reconnaissance::NetworkScan do
    subject(:scanner) { described_class.new(timeout: 1, log_output: StringIO.new) }

    describe '#initialize' do
      it 'starts with empty results' do
        expect(scanner.results).to be_empty
      end

      it 'creates a logger' do
        expect(scanner.logger).to be_a(Logger)
      end
    end

    describe 'COMMON_PORTS' do
      it 'maps port numbers to service names' do
        expect(described_class::COMMON_PORTS[22]).to eq('SSH')
        expect(described_class::COMMON_PORTS[80]).to eq('HTTP')
        expect(described_class::COMMON_PORTS[3306]).to eq('MySQL')
      end

      it 'is frozen to prevent modification' do
        expect(described_class::COMMON_PORTS).to be_frozen
      end
    end

    describe '#describe' do
      it 'outputs educational information' do
        expect { scanner.describe }.to output(/T1046/).to_stdout
        expect { scanner.describe }.to output(/TCPSocket/).to_stdout
      end
    end

    describe '#report' do
      it 'generates a text report' do
        report = scanner.report(format: :text)
        expect(report).to include('LoLRuby Network Scan Report')
      end

      it 'generates a JSON report' do
        report = scanner.report(format: :json)
        parsed = JSON.parse(report)
        expect(parsed).to have_key('scan_time')
        expect(parsed).to have_key('total_results')
      end

      it 'raises on unknown format' do
        expect { scanner.report(format: :xml) }.to raise_error(ArgumentError)
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Shared Technique Interface
  # ─────────────────────────────────────────────────────────────
  describe 'Technique interface compliance' do
    # All technique classes should provide a describe method for education
    let(:technique_classes) do
      [
        RubyGuardian::LoLRuby::Execution::EvalExecutor
      ]
    end

    it 'each technique provides a describe method' do
      technique_classes.each do |klass|
        instance = klass.new
        expect(instance).to respond_to(:describe)
        desc = instance.describe
        expect(desc).to be_a(String)
        expect(desc.length).to be > 20
      end
    end

    it 'each technique provides a summary method' do
      technique_classes.each do |klass|
        instance = klass.new
        expect(instance).to respond_to(:summary)
        summary = instance.summary
        expect(summary).to be_a(Hash)
      end
    end
  end

  # ─────────────────────────────────────────────────────────────
  # Cross-technique consistency
  # ─────────────────────────────────────────────────────────────
  describe 'Technique metadata consistency' do
    let(:eval_exec) { RubyGuardian::LoLRuby::Execution::EvalExecutor.new(sandbox: true) }

    it 'execution log entries have required keys' do
      eval_exec.demonstrate_eval_chain('test')
      entry = eval_exec.execution_log.first
      expect(entry).to have_key(:method)
      expect(entry).to have_key(:details)
      expect(entry).to have_key(:timestamp)
      expect(entry).to have_key(:sandbox)
    end

    it 'timestamps are in ISO 8601 format' do
      eval_exec.demonstrate_eval_chain('test')
      ts = eval_exec.execution_log.first[:timestamp]
      expect { Time.iso8601(ts) }.not_to raise_error
    end
  end
end
