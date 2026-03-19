# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Full Hollowing Integration Test
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# Integration test that exercises the complete process hollowing pipeline
# in dry_run mode: target creation -> analysis -> hollowing -> injection ->
# thread hijack -> resume. Validates component interaction and data flow.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
# =============================================================================

require 'stringio'
require 'json'

# Stub shared infrastructure for standalone integration testing
module RubyGuardian
  module Shared
    class AttackLogger
      attr_reader :messages
      def initialize(name, output: $stdout, level: :info)
        @name = name
        @messages = []
      end
      def info(msg);    @messages << [:info, msg]; end
      def debug(msg);   @messages << [:debug, msg]; end
      def warn(msg);    @messages << [:warn, msg]; end
      def error(msg);   @messages << [:error, msg]; end
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

require_relative '../../lib/process_hollower'

RSpec.describe 'Full Process Hollowing Integration', type: :integration do
  let(:log_output) { StringIO.new }
  let(:base_config) do
    {
      target_binary: '/bin/sleep',
      dry_run: true,
      require_sandbox: false,
      log_level: :debug,
      log_output: log_output,
      cleanup_on_failure: true,
      timeout: 10
    }
  end

  describe 'complete hollowing lifecycle in dry_run mode' do
    subject(:hollower) do
      RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
    end

    it 'executes the full pipeline and returns success' do
      result = hollower.execute
      expect(result[:outcome]).to eq(:success)
      expect(result[:status]).to eq(:resumed)
      expect(result[:dry_run]).to be true
    end

    it 'transitions through all status phases in order' do
      hollower.execute
      phases = hollower.operation_log.map { |e| e[:phase] }

      expected_order = %i[initialize safety_checks create_target analyze hollow inject hijack resume]
      # Verify ordering is preserved (allow extra entries)
      ordered_phases = phases & expected_order
      expect(ordered_phases).to eq(expected_order)
    end

    it 'populates target_info with simulated memory layout' do
      hollower.execute
      info = hollower.target_info

      expect(info[:binary]).to eq('/bin/sleep')
      expect(info[:simulated]).to be true
      expect(info[:memory_layout]).to be_an(Array)
      expect(info[:memory_layout].length).to eq(2)

      region = info[:memory_layout].first
      expect(region[:start_addr]).to eq(0x400000)
      expect(region[:end_addr]).to eq(0x401000)
      expect(region[:permissions]).to eq('r-xp')
    end

    it 'logs every operation with a timestamp' do
      hollower.execute
      hollower.operation_log.each do |entry|
        expect(entry).to include(:timestamp, :phase, :message)
        expect { Time.iso8601(entry[:timestamp]) }.not_to raise_error
      end
    end
  end

  describe 'pipeline with custom payload data' do
    it 'injects benign shellcode payload' do
      # Minimal x86_64 write+exit shellcode (benign demo)
      payload = [
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, # mov rax, 1 (sys_write)
        0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, # mov rdi, 1 (stdout)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00, # mov rax, 60 (sys_exit)
        0x48, 0x31, 0xFF,                           # xor rdi, rdi
        0x0F, 0x05                                  # syscall
      ].pack('C*')

      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
      result = hollower.execute(payload_data: payload)

      expect(result[:outcome]).to eq(:success)
      inject_entry = hollower.operation_log.find { |e| e[:phase] == :inject }
      expect(inject_entry[:message]).to include("#{payload.bytesize} bytes")
    end

    it 'handles large payload (16KB NOP sled + shellcode)' do
      nop_sled = "\x90" * 16_384
      shellcode = [0x48, 0x31, 0xFF, 0x48, 0xC7, 0xC0, 0x3C, 0x00,
                   0x00, 0x00, 0x0F, 0x05].pack('C*')
      payload = nop_sled + shellcode

      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
      result = hollower.execute(payload_data: payload)
      expect(result[:outcome]).to eq(:success)
    end
  end

  describe 'cleanup after execution' do
    it 'transitions to CLEANED_UP state' do
      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
      hollower.execute
      hollower.cleanup

      expect(hollower.status).to eq(:cleaned_up)
    end

    it 'can be called multiple times without error' do
      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
      hollower.execute
      expect { hollower.cleanup }.not_to raise_error
      expect { hollower.cleanup }.not_to raise_error
    end
  end

  describe 'operation_summary after full pipeline' do
    it 'provides a complete summary of the operation' do
      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
      hollower.execute
      summary = hollower.operation_summary

      expect(summary[:status]).to eq(:resumed)
      expect(summary[:platform]).to eq(:linux)
      expect(summary[:target_pid]).to eq(-1)
      expect(summary[:target_binary]).to eq('/bin/sleep')
      expect(summary[:operations]).to be >= 8
      expect(summary[:log]).to be_an(Array)
    end
  end

  describe 'educational description' do
    it 'covers key concepts of process hollowing' do
      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
      desc = hollower.describe

      # Verify educational content covers critical concepts
      expect(desc).to include('Process Hollowing')
      expect(desc).to include('T1055.012')
      expect(desc).to include('fork()')
      expect(desc).to include('ptrace')
      expect(desc).to include('/proc/<pid>/maps')
      expect(desc).to include('RIP')
      expect(desc).to include('Detection Opportunities')
    end
  end

  describe 'error recovery' do
    it 'returns failure result on unsupported platform' do
      allow(RubyGuardian::Shared::PlatformDetector).to receive(:linux?).and_return(false)
      allow(RubyGuardian::Shared::PlatformDetector).to receive(:windows?).and_return(false)

      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(
        base_config.merge(dry_run: false, require_sandbox: false)
      )
      result = hollower.execute

      expect(result[:outcome]).to eq(:failure)
      expect(result[:error]).to include('Unsupported platform')
    end

    it 'sets FAILED status and runs cleanup on error' do
      allow(RubyGuardian::Shared::PlatformDetector).to receive(:linux?).and_return(false)
      allow(RubyGuardian::Shared::PlatformDetector).to receive(:windows?).and_return(false)

      hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(
        base_config.merge(dry_run: false, require_sandbox: false)
      )
      hollower.execute

      expect(hollower.status).to eq(:cleaned_up)
    end
  end

  describe 'multiple sequential executions' do
    it 'supports creating multiple hollower instances' do
      results = 3.times.map do |i|
        h = RubyGuardian::ProcessHollowing::ProcessHollower.new(base_config)
        h.execute
      end

      results.each do |r|
        expect(r[:outcome]).to eq(:success)
      end
    end
  end
end
