# frozen_string_literal: true

require 'rspec'
require_relative '../lib/logger'
require_relative '../lib/config_loader'
require_relative '../lib/encoding_utils'
require_relative '../lib/platform_detector'
require_relative '../lib/network_utils'
require_relative '../lib/sandbox_detector'
require_relative '../lib/cleanup_utils'

RSpec.describe RubyGuardian::Shared do
  describe RubyGuardian::Shared::AttackLogger do
    let(:output) { StringIO.new }
    let(:logger) { described_class.new('test_module', output: output, level: :debug) }

    it 'logs messages with module name' do
      logger.info('Test message')
      output.rewind
      expect(output.string).to include('test_module')
    end

    it 'logs technique executions' do
      logger.technique('Process Hollowing', mitre_id: 'T1055.012', status: 'started')
      output.rewind
      expect(output.string).to include('TECHNIQUE')
      expect(output.string).to include('T1055.012')
    end

    it 'logs safety checks' do
      logger.safety_check('sandbox_detected', passed: true)
      output.rewind
      expect(output.string).to include('SAFETY')
      expect(output.string).to include('PASSED')
    end
  end

  describe RubyGuardian::Shared::EncodingUtils do
    describe '.xor_encode / .xor_decode' do
      it 'encodes and decodes symmetrically' do
        data = 'Hello, World!'
        key = 'secret'
        encoded = described_class.xor_encode(data, key: key)
        decoded = described_class.xor_decode(encoded, key: key)
        expect(decoded).to eq(data)
      end

      it 'produces different output than input' do
        data = 'Hello, World!'
        encoded = described_class.xor_encode(data, key: 'key')
        expect(encoded).not_to eq(data)
      end
    end

    describe '.aes_encrypt / .aes_decrypt' do
      it 'encrypts and decrypts data' do
        data = 'Sensitive payload data'
        key = 'encryption-key-for-testing'
        encrypted = described_class.aes_encrypt(data, key: key)
        decrypted = described_class.aes_decrypt(encrypted[:data], key: key, iv: encrypted[:iv])
        expect(decrypted).to eq(data)
      end
    end

    describe '.shannon_entropy' do
      it 'returns 0 for empty data' do
        expect(described_class.shannon_entropy('')).to eq(0.0)
      end

      it 'returns low entropy for repetitive data' do
        entropy = described_class.shannon_entropy('aaaaaaaaaa')
        expect(entropy).to eq(0.0)
      end

      it 'returns higher entropy for random data' do
        random = SecureRandom.random_bytes(1000)
        entropy = described_class.shannon_entropy(random)
        expect(entropy).to be > 7.0
      end
    end

    describe '.multi_encode / .multi_decode' do
      it 'performs multi-layer encoding round-trip' do
        data = 'Multi-layer encoded payload'
        key = 'test-key'
        encoded = described_class.multi_encode(data, key: key)
        decoded = described_class.multi_decode(encoded, key: key)
        expect(decoded).to eq(data)
      end
    end
  end

  describe RubyGuardian::Shared::PlatformDetector do
    describe '.detect' do
      it 'returns a PlatformInfo struct' do
        info = described_class.detect
        expect(info).to be_a(described_class::PlatformInfo)
        expect(info.ruby_version).to eq(RUBY_VERSION)
        expect(info.pid).to eq(Process.pid)
      end

      it 'detects the operating system' do
        info = described_class.detect
        expect(%i[linux macos windows freebsd unknown]).to include(info.os)
      end
    end
  end

  describe RubyGuardian::Shared::NetworkUtils do
    describe '.validate_host!' do
      it 'allows localhost' do
        expect { described_class.validate_host!('127.0.0.1') }.not_to raise_error
      end

      it 'rejects external hosts' do
        expect { described_class.validate_host!('evil.com') }.to raise_error(SecurityError)
      end
    end

    describe '.encode_for_dns' do
      it 'splits data into DNS-safe chunks' do
        data = 'A' * 200
        chunks = described_class.encode_for_dns(data)
        expect(chunks).to all(satisfy { |c| c.length <= 63 })
      end
    end
  end

  describe RubyGuardian::Shared::CleanupUtils do
    describe '.cleanup_temp_files' do
      it 'removes temporary files' do
        path = File.join(Dir.tmpdir, "rg_test_#{Process.pid}")
        File.write(path, 'test')
        described_class.cleanup_temp_files([path])
        expect(File.exist?(path)).to be false
      end

      it 'ignores non-temp paths for safety' do
        described_class.cleanup_temp_files(['/etc/passwd'])
        expect(File.exist?('/etc/passwd')).to be true
      end
    end
  end
end
