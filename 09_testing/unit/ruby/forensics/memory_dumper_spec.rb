# frozen_string_literal: true

require 'rspec'
require 'digest'
require 'tempfile'

# Unit tests for the RubyGuardian Memory Dumper module.
#
# Tests memory region parsing, selective dumping, entropy analysis,
# string extraction, and evidence integrity hashing.

RSpec.describe 'RubyGuardian::Forensics::MemoryDumper' do
  let(:target_pid) { 12345 }

  let(:sample_proc_maps) do
    <<~MAPS
      00400000-00450000 r-xp 00000000 08:01 1234567 /usr/bin/ruby
      00650000-00660000 rw-p 00050000 08:01 1234567 /usr/bin/ruby
      01000000-01200000 rw-p 00000000 00:00 0        [heap]
      7f0000000000-7f0000010000 rwxp 00000000 00:00 0
      7f0000100000-7f0000300000 r-xp 00000000 08:01 2345678 /lib/x86_64-linux-gnu/libc.so.6
      7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0        [stack]
      7ffd00021000-7ffd00023000 r--p 00000000 00:00 0        [vvar]
      7ffd00023000-7ffd00025000 r-xp 00000000 00:00 0        [vdso]
    MAPS
  end

  describe 'memory map parsing' do
    def parse_proc_maps(maps_content)
      maps_content.strip.split("\n").map do |line|
        parts = line.strip.split(/\s+/, 6)
        addr_range = parts[0].split('-')
        {
          start_addr: addr_range[0].to_i(16),
          end_addr: addr_range[1].to_i(16),
          permissions: parts[1],
          offset: parts[2].to_i(16),
          device: parts[3],
          inode: parts[4].to_i,
          path: parts[5] || ''
        }
      end
    end

    it 'parses all memory regions from /proc/pid/maps format' do
      regions = parse_proc_maps(sample_proc_maps)
      expect(regions.length).to eq(8)
    end

    it 'correctly extracts address ranges' do
      regions = parse_proc_maps(sample_proc_maps)
      ruby_text = regions.find { |r| r[:path].include?('/usr/bin/ruby') && r[:permissions].include?('x') }
      expect(ruby_text[:start_addr]).to eq(0x00400000)
      expect(ruby_text[:end_addr]).to eq(0x00450000)
    end

    it 'identifies executable regions' do
      regions = parse_proc_maps(sample_proc_maps)
      executable = regions.select { |r| r[:permissions].include?('x') }
      expect(executable.length).to be >= 3
    end

    it 'identifies anonymous executable regions as suspicious' do
      regions = parse_proc_maps(sample_proc_maps)
      suspicious = regions.select do |r|
        r[:permissions].include?('x') &&
          r[:permissions].include?('w') &&
          (r[:path].empty? || r[:path].strip.empty?)
      end
      expect(suspicious.length).to eq(1)
      expect(suspicious.first[:permissions]).to eq('rwxp')
    end

    it 'identifies heap and stack regions' do
      regions = parse_proc_maps(sample_proc_maps)
      heap = regions.find { |r| r[:path].include?('[heap]') }
      stack = regions.find { |r| r[:path].include?('[stack]') }
      expect(heap).not_to be_nil
      expect(stack).not_to be_nil
    end

    it 'calculates region sizes correctly' do
      regions = parse_proc_maps(sample_proc_maps)
      heap = regions.find { |r| r[:path].include?('[heap]') }
      size = heap[:end_addr] - heap[:start_addr]
      expect(size).to eq(0x200000) # 2 MB
    end
  end

  describe 'entropy analysis' do
    def compute_shannon_entropy(data)
      return 0.0 if data.nil? || data.empty?
      freq = Hash.new(0)
      data.each_byte { |b| freq[b] += 1 }
      total = data.bytesize.to_f
      -freq.values.sum { |count| p_x = count / total; p_x * Math.log2(p_x) }
    end

    it 'computes zero entropy for uniform data' do
      data = "\x00" * 1024
      entropy = compute_shannon_entropy(data)
      expect(entropy).to be_within(0.01).of(0.0)
    end

    it 'computes maximum entropy for fully random data' do
      data = (0..255).to_a.pack('C*') * 4
      entropy = compute_shannon_entropy(data)
      expect(entropy).to be_within(0.01).of(8.0)
    end

    it 'computes moderate entropy for typical code' do
      # ASCII text has moderate entropy (~4.5-5.5)
      data = "def hello; puts 'Hello, World!'; end\n" * 30
      entropy = compute_shannon_entropy(data)
      expect(entropy).to be_between(3.0, 6.0)
    end

    it 'flags high-entropy regions (>6.0) as potentially encrypted' do
      # Simulated encrypted/packed data
      rng = Random.new(42)
      data = Array.new(1024) { rng.rand(256) }.pack('C*')
      entropy = compute_shannon_entropy(data)
      expect(entropy).to be > 6.0
    end

    it 'handles empty data without error' do
      entropy = compute_shannon_entropy('')
      expect(entropy).to eq(0.0)
    end

    it 'detects NOP sled pattern (low entropy)' do
      nop_sled = "\x90" * 512
      entropy = compute_shannon_entropy(nop_sled)
      expect(entropy).to be_within(0.01).of(0.0)
    end
  end

  describe 'string extraction' do
    def extract_strings(data, min_length: 4)
      strings = []
      current_string = ''
      current_offset = 0

      data.each_byte.with_index do |byte, offset|
        if byte >= 0x20 && byte <= 0x7e
          current_string = '' if current_string.empty?
          current_offset = offset if current_string.empty?
          current_string << byte.chr
        else
          if current_string.length >= min_length
            strings << { offset: current_offset, value: current_string }
          end
          current_string = ''
        end
      end

      if current_string.length >= min_length
        strings << { offset: current_offset, value: current_string }
      end

      strings
    end

    it 'extracts ASCII strings from binary data' do
      data = "\x00\x00http://evil.example.com\x00\x00\x00/tmp/payload.rb\x00"
      strings = extract_strings(data, min_length: 4)
      values = strings.map { |s| s[:value] }
      expect(values).to include('http://evil.example.com')
      expect(values).to include('/tmp/payload.rb')
    end

    it 'respects minimum string length' do
      data = "AB\x00ABCD\x00AB\x00ABCDEF\x00"
      strings = extract_strings(data, min_length: 4)
      values = strings.map { |s| s[:value] }
      expect(values).to include('ABCD')
      expect(values).to include('ABCDEF')
      expect(values).not_to include('AB')
    end

    it 'records correct offsets' do
      data = "\x00\x00\x00test_string\x00\x00"
      strings = extract_strings(data, min_length: 4)
      expect(strings.first[:offset]).to eq(3)
      expect(strings.first[:value]).to eq('test_string')
    end

    it 'handles data with no printable strings' do
      data = "\x00\x01\x02\x03\x04\x05"
      strings = extract_strings(data)
      expect(strings).to be_empty
    end

    it 'extracts URLs from memory content' do
      data = "\x00" * 10 + "https://c2.attacker.com/beacon" + "\x00" * 10
      strings = extract_strings(data, min_length: 4)
      urls = strings.select { |s| s[:value].match?(%r{https?://}) }
      expect(urls.length).to eq(1)
    end
  end

  describe 'evidence integrity' do
    it 'generates consistent SHA-256 hashes for identical data' do
      data = "memory dump content for testing"
      hash1 = Digest::SHA256.hexdigest(data)
      hash2 = Digest::SHA256.hexdigest(data)
      expect(hash1).to eq(hash2)
      expect(hash1).to match(/^[a-f0-9]{64}$/)
    end

    it 'produces different hashes for different data' do
      hash1 = Digest::SHA256.hexdigest("dump version 1")
      hash2 = Digest::SHA256.hexdigest("dump version 2")
      expect(hash1).not_to eq(hash2)
    end

    it 'writes dump to file with correct permissions' do
      Tempfile.create(['memdump', '.bin']) do |f|
        f.write("\x00" * 4096)
        f.close
        File.chmod(0o600, f.path)
        mode = File.stat(f.path).mode & 0o777
        expect(mode).to eq(0o600)
      end
    end

    it 'records metadata alongside dump' do
      metadata = {
        pid: target_pid,
        process_name: 'ruby',
        timestamp: Time.now.utc.iso8601,
        regions_captured: 5,
        total_size: 2_097_152,
        hash_algorithm: 'SHA-256',
        evidence_hash: Digest::SHA256.hexdigest('test'),
        triggering_alert: 'alert-001'
      }

      expect(metadata[:pid]).to eq(target_pid)
      expect(metadata[:hash_algorithm]).to eq('SHA-256')
      expect(metadata[:evidence_hash]).to match(/^[a-f0-9]{64}$/)
    end
  end

  describe 'dump region selection' do
    def should_dump?(region, config)
      include_types = config[:include_regions] || %w[heap stack executable]
      max_size = config[:max_region_size] || 50 * 1024 * 1024

      region_size = region[:end_addr] - region[:start_addr]
      return false if region_size > max_size
      return false if region[:path]&.include?('[vvar]')
      return false if region[:path]&.include?('[vdso]')

      is_executable = region[:permissions].include?('x')
      is_heap = region[:path]&.include?('[heap]')
      is_stack = region[:path]&.include?('[stack]')
      is_anon_exec = is_executable && (region[:path].nil? || region[:path].strip.empty?)

      (include_types.include?('heap') && is_heap) ||
        (include_types.include?('stack') && is_stack) ||
        (include_types.include?('executable') && is_executable) ||
        is_anon_exec
    end

    let(:config) { { include_regions: %w[heap stack executable], max_region_size: 50 * 1024 * 1024 } }

    it 'includes heap regions' do
      region = { start_addr: 0x01000000, end_addr: 0x01200000, permissions: 'rw-p', path: '[heap]' }
      expect(should_dump?(region, config)).to be true
    end

    it 'includes stack regions' do
      region = { start_addr: 0x7ffd0000, end_addr: 0x7ffd2100, permissions: 'rw-p', path: '[stack]' }
      expect(should_dump?(region, config)).to be true
    end

    it 'includes anonymous executable regions (suspicious)' do
      region = { start_addr: 0x7f000000, end_addr: 0x7f010000, permissions: 'rwxp', path: '' }
      expect(should_dump?(region, config)).to be true
    end

    it 'excludes vvar and vdso regions' do
      vvar = { start_addr: 0x7ffd2100, end_addr: 0x7ffd2300, permissions: 'r--p', path: '[vvar]' }
      vdso = { start_addr: 0x7ffd2300, end_addr: 0x7ffd2500, permissions: 'r-xp', path: '[vdso]' }
      expect(should_dump?(vvar, config)).to be false
      expect(should_dump?(vdso, config)).to be false
    end

    it 'excludes oversized regions' do
      huge = { start_addr: 0x00000000, end_addr: 0x10000000, permissions: 'rw-p', path: '[heap]' }
      expect(should_dump?(huge, config)).to be false
    end
  end
end
