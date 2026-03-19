# frozen_string_literal: true

require "rspec"
require "fileutils"
require "tmpdir"
require "json"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))
require "memory_dumper"

RSpec.describe RubyGuardian::MemoryForensics::MemoryDumper do
  let(:test_pid) { Process.pid }
  let(:config) { { "acquisition" => { "hash_algorithms" => %w[sha256 md5] } } }
  let(:logger) do
    l = Logger.new(File::NULL)
    l.level = Logger::DEBUG
    l
  end

  describe "#initialize" do
    it "creates a dumper with valid PID" do
      dumper = described_class.new(pid: test_pid, config: config, logger: logger)
      expect(dumper.pid).to eq(test_pid)
    end

    it "raises ArgumentError for zero PID" do
      expect {
        described_class.new(pid: 0, config: config, logger: logger)
      }.to raise_error(ArgumentError, /Invalid PID/)
    end

    it "raises ArgumentError for negative PID" do
      expect {
        described_class.new(pid: -1, config: config, logger: logger)
      }.to raise_error(ArgumentError, /Invalid PID/)
    end

    it "raises ProcessNotFoundError for nonexistent PID" do
      expect {
        described_class.new(pid: 9_999_999, config: config, logger: logger)
      }.to raise_error(RubyGuardian::MemoryForensics::MemoryDumper::ProcessNotFoundError)
    end

    it "accepts a string PID and converts to integer" do
      dumper = described_class.new(pid: test_pid.to_s, config: config, logger: logger)
      expect(dumper.pid).to eq(test_pid)
    end

    it "loads default config when none provided" do
      dumper = described_class.new(pid: test_pid, logger: logger)
      expect(dumper.config).to be_a(Hash)
    end
  end

  describe "#parse_memory_maps" do
    subject(:dumper) { described_class.new(pid: test_pid, config: config, logger: logger) }

    it "returns an array of memory regions" do
      regions = dumper.parse_memory_maps
      expect(regions).to be_an(Array)
      expect(regions).not_to be_empty
    end

    it "parses memory regions with expected attributes" do
      regions = dumper.parse_memory_maps
      region = regions.first

      expect(region.start_addr).to be_a(Integer)
      expect(region.end_addr).to be_a(Integer)
      expect(region.permissions).to be_a(String)
      expect(region.size).to be > 0
      expect(region.end_addr).to be > region.start_addr
    end

    it "identifies readable regions" do
      regions = dumper.parse_memory_maps
      readable = regions.select { |r| r.permissions.include?("r") }
      expect(readable).not_to be_empty
    end

    it "includes heap and stack regions" do
      regions = dumper.parse_memory_maps
      pathnames = regions.map(&:pathname).compact
      has_heap = pathnames.any? { |p| p.include?("[heap]") }
      has_stack = pathnames.any? { |p| p.include?("[stack]") }
      expect(has_heap || has_stack).to be true
    end
  end

  describe "#process_info" do
    subject(:dumper) { described_class.new(pid: test_pid, config: config, logger: logger) }

    it "returns process information hash" do
      info = dumper.process_info
      expect(info).to be_a(Hash)
      expect(info[:pid]).to eq(test_pid)
    end

    it "includes command line" do
      info = dumper.process_info
      expect(info[:cmdline]).to be_a(String)
      expect(info[:cmdline]).not_to be_empty
    end

    it "includes memory maps count" do
      info = dumper.process_info
      expect(info[:memory_maps_count]).to be_a(Integer)
      expect(info[:memory_maps_count]).to be > 0
    end
  end

  describe ".verify_integrity" do
    it "returns not verified when no metadata file exists" do
      result = described_class.verify_integrity("/nonexistent/file.dump")
      expect(result[:verified]).to be false
      expect(result[:error]).to match(/metadata/)
    end

    context "with a mock dump and metadata file" do
      let(:tmp_dir) { Dir.mktmpdir("rg_test_") }
      let(:dump_path) { File.join(tmp_dir, "test.dump") }

      before do
        # Create a test dump file
        File.write(dump_path, "test dump content for verification")

        # Create matching metadata
        sha256 = Digest::SHA256.file(dump_path).hexdigest
        md5 = Digest::MD5.file(dump_path).hexdigest
        metadata = {
          "hashes" => {
            "sha256" => sha256,
            "md5" => md5
          }
        }
        File.write("#{dump_path}.meta.json", JSON.generate(metadata))
      end

      after do
        FileUtils.rm_rf(tmp_dir)
      end

      it "verifies integrity with matching hashes" do
        result = described_class.verify_integrity(dump_path)
        expect(result[:verified]).to be true
      end

      it "returns hash comparison details" do
        result = described_class.verify_integrity(dump_path)
        expect(result[:hashes]).to be_a(Hash)
        expect(result[:hashes]["sha256"][:match]).to be true
        expect(result[:hashes]["md5"][:match]).to be true
      end

      it "detects tampered files" do
        # Modify the dump after metadata was written
        File.write(dump_path, "tampered content")
        result = described_class.verify_integrity(dump_path)
        expect(result[:verified]).to be false
      end
    end
  end

  describe "DumpMetadata" do
    it "creates a metadata struct with all fields" do
      metadata = RubyGuardian::MemoryForensics::MemoryDumper::DumpMetadata.new(
        pid: 1234,
        timestamp: Time.now.utc.iso8601,
        method: "proc_mem",
        output_path: "/tmp/test.dump",
        size: 1024,
        hashes: { "sha256" => "abc123" },
        memory_regions: [],
        ruby_version: "ruby 3.2.2",
        duration: 1.5,
        compressed: true,
        acquisition_host: "test-host"
      )

      expect(metadata.pid).to eq(1234)
      expect(metadata.method).to eq("proc_mem")
      expect(metadata.compressed).to be true
      expect(metadata.hashes).to include("sha256")
    end
  end

  describe "MemoryRegion" do
    it "creates a region struct with address range" do
      region = RubyGuardian::MemoryForensics::MemoryDumper::MemoryRegion.new(
        start_addr: 0x7f0000000000,
        end_addr: 0x7f0000001000,
        permissions: "rw-p",
        offset: "00000000",
        device: "00:00",
        inode: 0,
        pathname: "[heap]",
        size: 0x1000
      )

      expect(region.start_addr).to eq(0x7f0000000000)
      expect(region.size).to eq(0x1000)
      expect(region.permissions).to eq("rw-p")
      expect(region.pathname).to eq("[heap]")
    end
  end

  describe "acquisition methods" do
    it "defines known acquisition methods" do
      expect(described_class::ACQUISITION_METHODS).to include(:proc_mem)
      expect(described_class::ACQUISITION_METHODS).to include(:gcore)
      expect(described_class::ACQUISITION_METHODS).to include(:ptrace)
    end

    it "defines default hash algorithms" do
      expect(described_class::DEFAULT_HASH_ALGORITHMS).to include("sha256")
      expect(described_class::DEFAULT_HASH_ALGORITHMS).to include("md5")
    end

    it "defines reasonable dump size limit" do
      expect(described_class::MAX_DUMP_SIZE).to be > 0
      expect(described_class::MAX_DUMP_SIZE).to eq(10 * 1024 * 1024 * 1024)
    end
  end

  describe "error classes" do
    it "defines AcquisitionError as base" do
      expect(described_class::AcquisitionError).to be < StandardError
    end

    it "defines ProcessNotFoundError" do
      expect(described_class::ProcessNotFoundError).to be < described_class::AcquisitionError
    end

    it "defines PermissionError" do
      expect(described_class::PermissionError).to be < described_class::AcquisitionError
    end

    it "defines DumpSizeExceededError" do
      expect(described_class::DumpSizeExceededError).to be < described_class::AcquisitionError
    end

    it "defines TimeoutError" do
      expect(described_class::TimeoutError).to be < described_class::AcquisitionError
    end
  end
end
