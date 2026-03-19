# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- MemoryMapper RSpec Tests
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# Tests the memory mapping, allocation, and hollowing logic used during
# process hollowing. Validates address alignment, region tracking, and
# the operations report generation.
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
# =============================================================================

require 'stringio'

# Stub shared modules for standalone spec execution
module RubyGuardian
  module Shared
    class AttackLogger
      def initialize(name, output: $stdout, level: :info); end
      def info(msg); end
      def debug(msg); end
      def warn(msg); end
      def error(msg); end
    end
  end
end

# Stub FFI bindings constants
module RubyGuardian
  module ProcessHollowing
    module FFIBindings
      ARCH = :x86_64

      module LinuxConstants
        PROT_READ  = 0x1
        PROT_WRITE = 0x2
        PROT_EXEC  = 0x4
        MAP_PRIVATE   = 0x02
        MAP_ANONYMOUS = 0x20
        MAP_FIXED     = 0x10
      end

      module LinuxAPI
        def self.read_proc_maps(pid)
          [
            { start_addr: 0x400000, end_addr: 0x401000, permissions: 'r-xp',
              pathname: '/bin/sleep', executable: true },
            { start_addr: 0x600000, end_addr: 0x601000, permissions: 'rw-p',
              pathname: '/bin/sleep', executable: false },
            { start_addr: 0x7f0000000000, end_addr: 0x7f0000200000, permissions: 'r-xp',
              pathname: '/lib/x86_64-linux-gnu/libc.so.6', executable: true }
          ]
        end

        def self.write_process_memory(pid, addr, data); data.bytesize; end
        def self.read_process_memory(pid, addr, size); "\x00" * size; end
        def self.ptrace_getregs(pid); { rip: 0x400000, rsp: 0x7fffffffe000 }; end
        def self.ptrace_setregs(pid, regs); true; end
      end

      module TypeUtils
        def self.protection_to_string(prot); "0x#{prot.to_s(16)}"; end
      end
    end
  end
end

require_relative '../lib/memory_mapper'

RSpec.describe RubyGuardian::ProcessHollowing::MemoryMapper do
  let(:logger) { RubyGuardian::Shared::AttackLogger.new('test') }
  subject(:mapper) { described_class.new(logger: logger) }

  describe '#initialize' do
    it 'sets the default page size to 4096' do
      report = mapper.operations_report
      expect(report[:page_size]).to eq(4096)
    end

    it 'accepts a custom page size' do
      custom = described_class.new(logger: logger, page_size: 65536)
      expect(custom.operations_report[:page_size]).to eq(65536)
    end

    it 'starts with empty region tracking lists' do
      expect(mapper.mapped_regions).to be_empty
      expect(mapper.unmapped_regions).to be_empty
    end
  end

  describe '#hollow' do
    let(:target_info) do
      {
        binary: '/bin/sleep',
        memory_layout: RubyGuardian::ProcessHollowing::FFIBindings::LinuxAPI.read_proc_maps(1234)
      }
    end

    it 'unmaps executable image regions on Linux' do
      result = mapper.hollow(1234, target_info, platform: :linux)
      expect(result[:success]).to be true
      expect(result[:regions_unmapped]).to be >= 1
    end

    it 'tracks unmapped regions' do
      mapper.hollow(1234, target_info, platform: :linux)
      expect(mapper.unmapped_regions).not_to be_empty
      expect(mapper.unmapped_regions.first).to include(:address, :size, :permissions)
    end

    it 'raises on unsupported platform' do
      expect {
        mapper.hollow(1234, target_info, platform: :freebsd)
      }.to raise_error(RuntimeError, /Unsupported platform/)
    end

    it 'falls back to executable regions when binary not in maps' do
      info = { binary: '/nonexistent/binary', memory_layout: target_info[:memory_layout] }
      result = mapper.hollow(1234, info, platform: :linux)
      expect(result[:success]).to be true
    end
  end

  describe '#allocate' do
    it 'returns an allocation result with address and size' do
      result = mapper.allocate(1234, 8192, platform: :linux)
      expect(result).to include(:address, :size, :protection, :method)
    end

    it 'page-aligns the allocation size upward' do
      result = mapper.allocate(1234, 100, platform: :linux)
      expect(result[:size]).to eq(4096) # aligned up from 100
    end

    it 'tracks mapped regions after allocation' do
      mapper.allocate(1234, 4096, platform: :linux)
      expect(mapper.mapped_regions.length).to eq(1)
    end

    it 'supports specifying a desired address' do
      result = mapper.allocate(1234, 4096, address: 0x600000, platform: :linux)
      expect(result[:address]).to eq(0x600000)
    end

    it 'includes MAP_FIXED flag when address is specified' do
      result = mapper.allocate(1234, 4096, address: 0x600000, platform: :linux)
      map_fixed = RubyGuardian::ProcessHollowing::FFIBindings::LinuxConstants::MAP_FIXED
      expect(result[:flags] & map_fixed).not_to eq(0)
    end
  end

  describe '#query_memory_layout' do
    it 'returns memory regions for Linux targets' do
      regions = mapper.query_memory_layout(1234, platform: :linux)
      expect(regions).to be_an(Array)
      expect(regions.first).to include(:start_addr, :end_addr)
    end
  end

  describe '#find_image_base' do
    it 'finds the base address of the target binary' do
      base = mapper.find_image_base(1234, '/bin/sleep', platform: :linux)
      expect(base).to eq(0x400000)
    end

    it 'raises when binary is not found in maps' do
      expect {
        mapper.find_image_base(1234, '/nonexistent/binary', platform: :linux)
      }.to raise_error(RuntimeError, /Could not find image base/)
    end
  end

  describe '#compute_image_size' do
    it 'computes the total memory span of the image' do
      size = mapper.compute_image_size(1234, 0x400000, '/bin/sleep', platform: :linux)
      # Two regions: 0x400000-0x401000 and 0x600000-0x601000 => span = 0x201000
      expect(size).to eq(0x601000 - 0x400000)
    end
  end

  describe '#operations_report' do
    it 'includes all tracking counters' do
      report = mapper.operations_report
      expect(report).to include(:page_size, :regions_mapped, :regions_unmapped,
                                 :total_allocated, :total_unmapped)
    end

    it 'reflects operations after hollow + allocate' do
      target_info = {
        binary: '/bin/sleep',
        memory_layout: RubyGuardian::ProcessHollowing::FFIBindings::LinuxAPI.read_proc_maps(1)
      }
      mapper.hollow(1, target_info, platform: :linux)
      mapper.allocate(1, 8192, platform: :linux)

      report = mapper.operations_report
      expect(report[:regions_mapped]).to eq(1)
      expect(report[:regions_unmapped]).to be >= 1
      expect(report[:total_allocated]).to eq(8192)
    end
  end

  describe 'page alignment helpers (via allocate)' do
    it 'aligns 1 byte to one full page' do
      result = mapper.allocate(1, 1, platform: :linux)
      expect(result[:size]).to eq(4096)
    end

    it 'aligns exact page size to itself' do
      result = mapper.allocate(1, 4096, platform: :linux)
      expect(result[:size]).to eq(4096)
    end

    it 'aligns page_size+1 to two pages' do
      result = mapper.allocate(1, 4097, platform: :linux)
      expect(result[:size]).to eq(8192)
    end
  end
end
