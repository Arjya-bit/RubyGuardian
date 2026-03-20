# frozen_string_literal: true
#
# RubyGuardian - Dump Parser Module Specs
# Tests for parsing and interpreting raw memory dump files.

require 'rspec'
require 'fileutils'
require 'tmpdir'
require 'json'

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'dump_parser'

RSpec.describe RubyGuardian::MemoryForensics::DumpParser do
  let(:tmp_dir) { Dir.mktmpdir('rg_parser_test_') }
  let(:logger) do
    l = Logger.new(File::NULL)
    l.level = Logger::DEBUG
    l
  end

  after(:each) do
    FileUtils.rm_rf(tmp_dir)
  end

  describe '#initialize' do
    it 'accepts a dump file path' do
      dump_path = File.join(tmp_dir, 'test.dump')
      File.write(dump_path, "\x00" * 256)
      parser = described_class.new(dump_path, logger: logger)
      expect(parser.dump_path).to eq(dump_path)
    end

    it 'raises FileNotFoundError for missing dump file' do
      expect {
        described_class.new('/nonexistent/path.dump', logger: logger)
      }.to raise_error(described_class::FileNotFoundError)
    end

    it 'detects dump format from file header' do
      dump_path = File.join(tmp_dir, 'test.dump')
      File.write(dump_path, "RGDUMP\x01\x00" + "\x00" * 248)
      parser = described_class.new(dump_path, logger: logger)
      expect(parser.format).to eq(:rubyguardian_v1)
    end

    it 'handles ELF core dump format' do
      dump_path = File.join(tmp_dir, 'core.dump')
      File.write(dump_path, "\x7FELF" + "\x00" * 252)
      parser = described_class.new(dump_path, logger: logger)
      expect(parser.format).to eq(:elf_core)
    end

    it 'falls back to raw format for unknown headers' do
      dump_path = File.join(tmp_dir, 'raw.dump')
      File.write(dump_path, "random binary data " * 20)
      parser = described_class.new(dump_path, logger: logger)
      expect(parser.format).to eq(:raw)
    end
  end

  describe '#parse_header' do
    let(:dump_path) { File.join(tmp_dir, 'header_test.dump') }

    before do
      header = "RGDUMP\x01\x00"
      header += [Process.pid].pack('Q<')    # PID as 64-bit LE
      header += [Time.now.to_i].pack('Q<')  # Timestamp
      header += [4096].pack('Q<')           # Region count placeholder
      header += "\x00" * (256 - header.size)
      header += "A" * 4096                   # Mock data
      File.binwrite(dump_path, header)
    end

    it 'extracts PID from dump header' do
      parser = described_class.new(dump_path, logger: logger)
      header = parser.parse_header
      expect(header[:pid]).to eq(Process.pid)
    end

    it 'extracts timestamp from dump header' do
      parser = described_class.new(dump_path, logger: logger)
      header = parser.parse_header
      expect(header[:timestamp]).to be_a(Integer)
      expect(header[:timestamp]).to be > 0
    end

    it 'extracts format version' do
      parser = described_class.new(dump_path, logger: logger)
      header = parser.parse_header
      expect(header[:version]).to eq(1)
    end
  end

  describe '#extract_strings' do
    let(:dump_path) { File.join(tmp_dir, 'strings_test.dump') }

    before do
      content = "\x00\x00hello world\x00\x00\x00"
      content += "\x00password=s3cret123\x00"
      content += "\x00" * 50
      content += "another string here\x00"
      content += "\x01\x02\x03\x04" * 20
      content += "final_token=abc123xyz\x00"
      File.binwrite(dump_path, content)
    end

    it 'extracts printable ASCII strings from binary data' do
      parser = described_class.new(dump_path, logger: logger)
      strings = parser.extract_strings(min_length: 5)
      expect(strings).to include('hello world')
      expect(strings).to include('another string here')
    end

    it 'respects minimum length parameter' do
      parser = described_class.new(dump_path, logger: logger)
      short_strings = parser.extract_strings(min_length: 15)
      expect(short_strings).not_to include('hello world')
      expect(short_strings).to include('another string here')
    end

    it 'supports regex filtering of extracted strings' do
      parser = described_class.new(dump_path, logger: logger)
      secrets = parser.extract_strings(min_length: 4, pattern: /password|token|secret/i)
      expect(secrets).to include('password=s3cret123')
      expect(secrets).to include('final_token=abc123xyz')
      expect(secrets).not_to include('hello world')
    end

    it 'returns string offsets when requested' do
      parser = described_class.new(dump_path, logger: logger)
      results = parser.extract_strings(min_length: 5, include_offsets: true)
      expect(results.first).to be_a(Hash)
      expect(results.first).to have_key(:string)
      expect(results.first).to have_key(:offset)
    end
  end

  describe '#extract_ruby_objects' do
    let(:dump_path) { File.join(tmp_dir, 'objects_test.dump') }

    before do
      # Simulate a heap dump with JSON-like object entries
      objects = [
        { type: 'STRING', class: 'String', value: 'test_value', length: 10 },
        { type: 'ARRAY', class: 'Array', length: 5 },
        { type: 'HASH', class: 'Hash', size: 3 },
        { type: 'OBJECT', class: 'User', ivars: { name: 'admin' } }
      ]
      File.write(dump_path, objects.map(&:to_json).join("\n"))
    end

    it 'parses Ruby object entries from heap dump' do
      parser = described_class.new(dump_path, logger: logger)
      objects = parser.extract_ruby_objects
      expect(objects).to be_an(Array)
      expect(objects.length).to eq(4)
    end

    it 'categorizes objects by type' do
      parser = described_class.new(dump_path, logger: logger)
      objects = parser.extract_ruby_objects
      types = objects.map { |o| o[:type] }
      expect(types).to include('STRING', 'ARRAY', 'HASH', 'OBJECT')
    end

    it 'filters objects by class name' do
      parser = described_class.new(dump_path, logger: logger)
      users = parser.extract_ruby_objects(class_filter: 'User')
      expect(users.length).to eq(1)
      expect(users.first[:class]).to eq('User')
    end
  end

  describe '#compute_statistics' do
    let(:dump_path) { File.join(tmp_dir, 'stats_test.dump') }

    before do
      File.write(dump_path, "A" * 1024)
    end

    it 'returns file size information' do
      parser = described_class.new(dump_path, logger: logger)
      stats = parser.compute_statistics
      expect(stats[:file_size]).to eq(1024)
    end

    it 'calculates entropy of the dump' do
      parser = described_class.new(dump_path, logger: logger)
      stats = parser.compute_statistics
      # A file of all 'A' bytes has zero entropy
      expect(stats[:entropy]).to be_a(Float)
      expect(stats[:entropy]).to be >= 0.0
      expect(stats[:entropy]).to be <= 8.0
    end

    it 'counts null byte regions' do
      dump_path2 = File.join(tmp_dir, 'null_test.dump')
      File.binwrite(dump_path2, "\x00" * 512 + "data" + "\x00" * 512)
      parser = described_class.new(dump_path2, logger: logger)
      stats = parser.compute_statistics
      expect(stats[:null_regions]).to be >= 1
    end
  end

  describe 'error classes' do
    it 'defines FileNotFoundError' do
      expect(described_class::FileNotFoundError).to be < StandardError
    end

    it 'defines ParseError' do
      expect(described_class::ParseError).to be < StandardError
    end

    it 'defines CorruptedDumpError' do
      expect(described_class::CorruptedDumpError).to be < described_class::ParseError
    end

    it 'defines UnsupportedFormatError' do
      expect(described_class::UnsupportedFormatError).to be < described_class::ParseError
    end
  end
end
