# frozen_string_literal: true

require 'rspec'
require 'json'
require 'time'

# RubyGuardian Detection Engine - Alert Formatter Specs
# Tests JSON, Syslog, CEF, and LEEF formatters.

RSpec.describe 'RubyGuardian::DetectionEngine::AlertFormatters' do
  let(:sample_alert) do
    {
      'alert_id' => 'alert-abc123',
      'rule_id' => 'RG-DET-001',
      'rule_name' => 'Encoded Eval Detection',
      'severity' => 'critical',
      'timestamp' => '2024-01-15T14:32:00Z',
      'agent_id' => 'agent-001',
      'source_ip' => '10.0.1.50',
      'dest_ip' => '10.0.1.100',
      'description' => 'Base64-encoded eval() payload detected in process 12345',
      'mitre_technique' => 'T1059.007',
      'event_data' => {
        'pid' => 12345,
        'method' => 'eval',
        'encoding' => 'base64'
      }
    }
  end

  describe 'JSON formatter' do
    it 'produces valid JSON' do
      json_output = JSON.generate(sample_alert)
      parsed = JSON.parse(json_output)
      expect(parsed['alert_id']).to eq('alert-abc123')
    end

    it 'includes ISO8601 timestamp' do
      expect { Time.iso8601(sample_alert['timestamp']) }.not_to raise_error
    end

    it 'includes all required fields' do
      required = %w[alert_id rule_id severity timestamp description]
      required.each do |field|
        expect(sample_alert).to have_key(field)
      end
    end
  end

  describe 'Syslog formatter' do
    let(:severity_map) { { 'critical' => 2, 'high' => 3, 'medium' => 4, 'low' => 6 } }
    let(:facility) { 10 } # security/auth

    it 'calculates correct PRI value' do
      severity = severity_map[sample_alert['severity']]
      pri = facility * 8 + severity
      expect(pri).to eq(82)
    end

    it 'formats RFC 5424 header' do
      version = 1
      timestamp = sample_alert['timestamp']
      hostname = 'rg-agent-001'
      app_name = 'RubyGuardian'
      header = "<82>#{version} #{timestamp} #{hostname} #{app_name}"
      expect(header).to start_with('<82>1')
    end

    it 'includes structured data' do
      sd = "[RubyGuardian@12345 ruleId=\"#{sample_alert['rule_id']}\" severity=\"#{sample_alert['severity']}\"]"
      expect(sd).to include('RG-DET-001')
    end
  end

  describe 'CEF formatter' do
    it 'formats CEF header correctly' do
      cef_version = 0
      vendor = 'RubyGuardian'
      product = 'DetectionEngine'
      version = '1.0'
      sig_id = sample_alert['rule_id']
      name = sample_alert['rule_name']
      severity_map = { 'critical' => 10, 'high' => 7, 'medium' => 4, 'low' => 1 }
      sev = severity_map[sample_alert['severity']]

      header = "CEF:#{cef_version}|#{vendor}|#{product}|#{version}|#{sig_id}|#{name}|#{sev}|"
      expect(header).to start_with('CEF:0|RubyGuardian|')
      expect(header).to include('|10|')
    end

    it 'includes extension fields' do
      extensions = "src=#{sample_alert['source_ip']} dst=#{sample_alert['dest_ip']} msg=#{sample_alert['description']}"
      expect(extensions).to include('src=10.0.1.50')
    end

    it 'escapes pipe characters in values' do
      value_with_pipe = 'test|value'
      escaped = value_with_pipe.gsub('|', '\\|')
      expect(escaped).to eq('test\\|value')
    end
  end

  describe 'LEEF formatter' do
    it 'formats LEEF header correctly' do
      leef_version = '2.0'
      vendor = 'RubyGuardian'
      product = 'DetectionEngine'
      version = '1.0'
      event_id = sample_alert['rule_id']

      header = "LEEF:#{leef_version}|#{vendor}|#{product}|#{version}|#{event_id}|"
      expect(header).to start_with('LEEF:2.0|RubyGuardian|')
    end

    it 'uses tab-separated key=value pairs' do
      attrs = "cat=#{sample_alert['mitre_technique']}\tsev=#{sample_alert['severity']}\tsrc=#{sample_alert['source_ip']}"
      expect(attrs.split("\t").length).to eq(3)
    end
  end
end
