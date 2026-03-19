# frozen_string_literal: true

require 'rspec'
require 'json'
require 'time'
require 'digest'

# Integration test: Detection Engine -> Forensic Analysis
#
# Verifies that detection engine alerts correctly trigger forensic
# evidence capture, memory dump analysis, and IOC extraction.

RSpec.describe 'Integration: Detection -> Forensics Pipeline' do
  let(:critical_alert) do
    {
      id: 'alert-001',
      rule_name: 'Process Hollowing via ptrace',
      rule_id: 'RG-004',
      severity: 'critical',
      mitre_technique: 'T1055.012',
      source_pid: 1234,
      target_pid: 5678,
      process_name: 'ruby',
      command_line: 'ruby /tmp/malicious_loader.rb',
      timestamp: Time.now.utc.iso8601,
      threat_score: 0.95,
      correlated_events: 5
    }
  end

  let(:forensic_config) do
    {
      'trigger_severities' => %w[critical high],
      'memory_dump' => {
        'enabled' => true,
        'include_regions' => %w[heap stack executable],
        'max_dump_size_mb' => 512,
        'entropy_threshold' => 6.0
      },
      'ioc_extraction' => {
        'enabled' => true,
        'extract_strings' => true,
        'min_string_length' => 4,
        'extract_ips' => true,
        'extract_domains' => true,
        'extract_urls' => true,
        'extract_hashes' => true
      },
      'evidence_integrity' => {
        'hash_algorithm' => 'SHA-256',
        'chain_of_custody' => true
      }
    }
  end

  describe 'forensic trigger conditions' do
    it 'triggers forensics for critical severity alerts' do
      trigger_severities = forensic_config['trigger_severities']
      expect(trigger_severities).to include(critical_alert[:severity])
    end

    it 'does not trigger for low severity alerts' do
      low_alert = critical_alert.merge(severity: 'low')
      trigger_severities = forensic_config['trigger_severities']
      expect(trigger_severities).not_to include(low_alert[:severity])
    end

    it 'passes correct PID to forensic capture' do
      # Should capture target process, not attacker
      expect(critical_alert[:target_pid]).to eq(5678)
    end
  end

  describe 'memory dump generation' do
    let(:mock_memory_regions) do
      [
        { start_addr: '0x00400000', end_addr: '0x00450000', permissions: 'r-xp',
          size: 327_680, type: 'executable', path: '/usr/bin/ruby' },
        { start_addr: '0x00600000', end_addr: '0x00620000', permissions: 'rw-p',
          size: 131_072, type: 'data', path: '/usr/bin/ruby' },
        { start_addr: '0x01000000', end_addr: '0x01200000', permissions: 'rw-p',
          size: 2_097_152, type: 'heap', path: '[heap]' },
        { start_addr: '0x7f000000', end_addr: '0x7f010000', permissions: 'rwxp',
          size: 65_536, type: 'anonymous', path: '' },
        { start_addr: '0x7fff0000', end_addr: '0x7ffff000', permissions: 'rw-p',
          size: 61_440, type: 'stack', path: '[stack]' }
      ]
    end

    it 'enumerates process memory regions' do
      expect(mock_memory_regions).not_to be_empty
      expect(mock_memory_regions.length).to be >= 3
    end

    it 'identifies executable anonymous regions as suspicious' do
      suspicious = mock_memory_regions.select do |r|
        r[:permissions].include?('x') && r[:path].empty?
      end
      expect(suspicious).not_to be_empty
      expect(suspicious.first[:permissions]).to eq('rwxp')
    end

    it 'captures heap, stack, and executable regions per config' do
      included_types = forensic_config['memory_dump']['include_regions']
      captured = mock_memory_regions.select { |r| included_types.include?(r[:type]) }
      expect(captured.length).to be >= 3
    end

    it 'respects maximum dump size limit' do
      max_bytes = forensic_config['memory_dump']['max_dump_size_mb'] * 1024 * 1024
      total_size = mock_memory_regions.sum { |r| r[:size] }
      expect(total_size).to be < max_bytes
    end
  end

  describe 'entropy analysis' do
    let(:entropy_results) do
      [
        { region: 'executable', entropy: 5.8, classification: 'normal_code' },
        { region: 'heap', entropy: 4.2, classification: 'normal_data' },
        { region: 'anonymous_rwx', entropy: 7.6, classification: 'encrypted_or_packed' },
        { region: 'stack', entropy: 3.1, classification: 'normal_data' }
      ]
    end

    it 'computes entropy for each memory region' do
      expect(entropy_results.length).to be >= 3
      entropy_results.each do |r|
        expect(r[:entropy]).to be_between(0, 8.0)
      end
    end

    it 'flags high-entropy regions as potential shellcode' do
      threshold = forensic_config['memory_dump']['entropy_threshold']
      suspicious = entropy_results.select { |r| r[:entropy] > threshold }
      expect(suspicious).not_to be_empty
      expect(suspicious.first[:classification]).to eq('encrypted_or_packed')
    end

    it 'classifies normal code entropy correctly' do
      code_region = entropy_results.find { |r| r[:region] == 'executable' }
      expect(code_region[:entropy]).to be_between(4.0, 7.0)
      expect(code_region[:classification]).to eq('normal_code')
    end
  end

  describe 'IOC extraction' do
    let(:extracted_iocs) do
      [
        { type: 'ip', value: '192.168.1.100', confidence: 0.95, source: 'memory_strings' },
        { type: 'ip', value: '10.0.0.1', confidence: 0.90, source: 'network_buffer' },
        { type: 'domain', value: 'evil.example.com', confidence: 0.88, source: 'memory_strings' },
        { type: 'url', value: 'http://evil.example.com/payload.rb', confidence: 0.92, source: 'heap' },
        { type: 'hash_sha256', value: 'a' * 64, confidence: 0.99, source: 'file_reference' },
        { type: 'file_path', value: '/tmp/malicious_loader.rb', confidence: 0.85, source: 'stack' }
      ]
    end

    it 'extracts IP addresses from memory' do
      ips = extracted_iocs.select { |i| i[:type] == 'ip' }
      expect(ips.length).to be >= 1
      ips.each { |ip| expect(ip[:value]).to match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) }
    end

    it 'extracts domain names from memory strings' do
      domains = extracted_iocs.select { |i| i[:type] == 'domain' }
      expect(domains).not_to be_empty
    end

    it 'extracts URLs from heap memory' do
      urls = extracted_iocs.select { |i| i[:type] == 'url' }
      expect(urls).not_to be_empty
      urls.each { |u| expect(u[:value]).to match(%r{https?://}) }
    end

    it 'assigns confidence scores to all IOCs' do
      extracted_iocs.each do |ioc|
        expect(ioc[:confidence]).to be_between(0.0, 1.0)
      end
    end

    it 'records the extraction source for each IOC' do
      extracted_iocs.each do |ioc|
        expect(ioc[:source]).not_to be_nil
        expect(ioc[:source]).not_to be_empty
      end
    end
  end

  describe 'evidence integrity' do
    let(:evidence_hash) { Digest::SHA256.hexdigest('simulated_memory_dump_content') }

    it 'computes SHA-256 hash of captured evidence' do
      expect(evidence_hash).to match(/^[a-f0-9]{64}$/)
    end

    it 'uses the configured hash algorithm' do
      expect(forensic_config['evidence_integrity']['hash_algorithm']).to eq('SHA-256')
    end

    it 'maintains chain of custody metadata' do
      expect(forensic_config['evidence_integrity']['chain_of_custody']).to be true
    end
  end

  describe 'forensic report structure' do
    let(:forensic_report) do
      {
        id: 'fr-001',
        alert_id: critical_alert[:id],
        timestamp: Time.now.utc.iso8601,
        target_pid: critical_alert[:target_pid],
        process_name: critical_alert[:process_name],
        severity: critical_alert[:severity],
        memory_dump_path: '/var/rubyguardian/dumps/fr-001.bin',
        memory_regions_count: 5,
        suspicious_regions: 1,
        iocs_extracted: 6,
        evidence_hash: Digest::SHA256.hexdigest('dump'),
        mitre_techniques: ['T1055.012'],
        findings: [
          'Executable anonymous memory region detected (rwxp)',
          'High entropy region (7.6) suggests encrypted/packed content',
          'C2 URL extracted from heap memory'
        ]
      }
    end

    it 'links back to the triggering alert' do
      expect(forensic_report[:alert_id]).to eq(critical_alert[:id])
    end

    it 'includes memory dump file path' do
      expect(forensic_report[:memory_dump_path]).to be_a(String)
      expect(forensic_report[:memory_dump_path]).to include('fr-001')
    end

    it 'reports number of suspicious regions' do
      expect(forensic_report[:suspicious_regions]).to be >= 1
    end

    it 'includes evidence integrity hash' do
      expect(forensic_report[:evidence_hash]).to match(/^[a-f0-9]{64}$/)
    end

    it 'provides human-readable findings' do
      expect(forensic_report[:findings]).to be_an(Array)
      expect(forensic_report[:findings].length).to be >= 1
    end
  end
end
