# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- ProcessHollower RSpec Tests
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# These tests validate the ProcessHollower orchestrator in dry_run mode,
# ensuring all phases execute correctly without performing real injection.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
# =============================================================================

require 'stringio'

# Stub shared modules so specs can run standalone
module RubyGuardian
  module Shared
    class AttackLogger
      attr_reader :messages
      def initialize(name, output: $stdout, level: :info)
        @name = name
        @messages = []
      end

      def info(msg);          @messages << [:info, msg]; end
      def debug(msg);         @messages << [:debug, msg]; end
      def warn(msg);          @messages << [:warn, msg]; end
      def error(msg);         @messages << [:error, msg]; end
      def technique(name, **opts); @messages << [:technique, name, opts]; end
      def safety_check(name, passed:); @messages << [:safety, name, passed]; end
    end

    module PlatformDetector
      def self.linux?;   true; end
      def self.windows?; false; end
    end

    module SandboxDetector
      def self.require_sandbox!; true; end
    end
  end
end

require_relative '../lib/process_hollower'

RSpec.describe RubyGuardian::ProcessHollowing::ProcessHollower do
  subject(:hollower) { described_class.new(config) }

  let(:config) do
    {
      target_binary: '/bin/sleep',
      dry_run: true,
      require_sandbox: false,
      log_level: :debug,
      log_output: StringIO.new
    }
  end

  describe '#initialize' do
    it 'sets status to INITIALIZED' do
      expect(hollower.status).to eq(:initialized)
    end

    it 'detects the current platform' do
      expect(hollower.platform).to eq(:linux)
    end

    it 'starts with an empty operation log' do
      expect(hollower.operation_log).to be_an(Array)
      expect(hollower.operation_log.length).to eq(1) # init log entry
    end

    it 'has no target PID before execution' do
      expect(hollower.target_pid).to be_nil
    end
  end

  describe '#execute (dry_run mode)' do
    let(:result) { hollower.execute }

    it 'returns a success result hash' do
      expect(result[:outcome]).to eq(:success)
    end

    it 'marks dry_run in the result' do
      expect(result[:dry_run]).to be true
    end

    it 'uses a simulated PID of -1' do
      result
      expect(hollower.target_pid).to eq(-1)
    end

    it 'progresses through all status phases' do
      result
      expect(hollower.status).to eq(:resumed)
    end

    it 'logs operations for each phase' do
      result
      phases = hollower.operation_log.map { |e| e[:phase] }
      expect(phases).to include(:initialize, :safety_checks, :create_target,
                                 :analyze, :hollow, :inject, :hijack, :resume)
    end

    it 'records the correct number of operations' do
      expect(result[:operations]).to be >= 8
    end

    it 'simulates memory layout during analysis' do
      result
      layout = hollower.target_info[:memory_layout]
      expect(layout).to be_an(Array)
      expect(layout.first).to include(:start_addr, :end_addr, :permissions)
    end
  end

  describe '#execute with payload_data' do
    it 'accepts inline payload bytes in dry_run' do
      payload = "\x90" * 64 # NOP sled
      result = hollower.execute(payload_data: payload)
      expect(result[:outcome]).to eq(:success)
      inject_log = hollower.operation_log.find { |e| e[:phase] == :inject }
      expect(inject_log[:message]).to include('64 bytes')
    end
  end

  describe '#cleanup' do
    it 'sets status to CLEANED_UP' do
      hollower.execute
      hollower.cleanup
      expect(hollower.status).to eq(:cleaned_up)
    end

    it 'logs the cleanup operation' do
      hollower.execute
      hollower.cleanup
      phases = hollower.operation_log.map { |e| e[:phase] }
      expect(phases).to include(:cleanup)
    end
  end

  describe '#describe' do
    it 'returns educational description text' do
      desc = hollower.describe
      expect(desc).to include('Process Hollowing')
      expect(desc).to include('T1055.012')
      expect(desc).to include('Detection Opportunities')
    end
  end

  describe '#operation_summary' do
    it 'returns a summary hash with all expected keys' do
      hollower.execute
      summary = hollower.operation_summary
      expect(summary).to include(:status, :platform, :target_pid,
                                  :target_binary, :operations, :log)
    end

    it 'reflects the correct target binary' do
      hollower.execute
      expect(hollower.operation_summary[:target_binary]).to eq('/bin/sleep')
    end
  end

  describe 'error handling' do
    it 'returns failure when safety checks fail on unsupported platform' do
      allow(RubyGuardian::Shared::PlatformDetector).to receive(:linux?).and_return(false)
      allow(RubyGuardian::Shared::PlatformDetector).to receive(:windows?).and_return(false)

      bad_hollower = described_class.new(config.merge(dry_run: false, require_sandbox: false))
      result = bad_hollower.execute
      expect(result[:outcome]).to eq(:failure)
      expect(bad_hollower.status).to eq(:failed)
    end
  end
end
