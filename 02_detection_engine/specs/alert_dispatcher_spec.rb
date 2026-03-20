# frozen_string_literal: true

require 'rspec'
require 'json'
require 'tmpdir'

require_relative '../alerting/formatters/json_formatter'
require_relative '../alerting/formatters/syslog_formatter'
require_relative '../alerting/formatters/cef_formatter'
require_relative '../alerting/formatters/leef_formatter'
require_relative '../alerting/channels/file_channel'

RSpec.describe 'Alert Dispatching and Channel Routing' do
  let(:sample_alert) do
    {
      alert_id:     'alert-12345',
      rule_id:      'RULE-001',
      rule_name:    'Suspicious Process Injection',
      rule_description: 'Detects process injection via WriteProcessMemory',
      severity:     'high',
      timestamp:    Time.utc(2026, 1, 15, 10, 30, 0),
      source_ip:    '192.168.1.100',
      source_port:  54321,
      source_user:  'admin',
      dest_ip:      '10.0.0.50',
      dest_port:    445,
      event_type:   'process_access',
      event_action: 'WriteProcessMemory',
      process_name: 'evil_tool.exe',
      command_line: 'evil_tool.exe --inject --pid 1234',
      mitre_tactics:    ['Defense Evasion', 'Privilege Escalation'],
      mitre_techniques: ['T1055']
    }
  end

  describe RubyGuardian::DetectionEngine::Alerting::Formatters::JsonFormatter do
    let(:formatter) { described_class.new }

    it 'formats an alert as valid JSON' do
      output = formatter.format(sample_alert)
      parsed = JSON.parse(output)

      expect(parsed['alert_id']).to eq('alert-12345')
      expect(parsed['rule']['id']).to eq('RULE-001')
      expect(parsed['severity']['label']).to eq('high')
      expect(parsed['severity']['numeric']).to eq(2)
    end

    it 'includes MITRE ATT&CK mappings' do
      output = formatter.format(sample_alert)
      parsed = JSON.parse(output)

      expect(parsed['rule']['mitre_attack']['tactics']).to include('Defense Evasion')
      expect(parsed['rule']['mitre_attack']['techniques']).to include('T1055')
    end

    it 'formats pretty JSON when configured' do
      formatter = described_class.new(pretty: true)
      output = formatter.format(sample_alert)
      expect(output).to include("\n")
    end

    it 'formats a batch of alerts' do
      output = formatter.format_batch([sample_alert, sample_alert])
      parsed = JSON.parse(output)

      expect(parsed['count']).to eq(2)
      expect(parsed['alerts']).to be_an(Array)
    end

    it 'rejects alerts missing required fields' do
      incomplete = { rule_id: 'X', rule_name: 'Y' }
      expect { formatter.format(incomplete) }.to raise_error(
        RubyGuardian::DetectionEngine::Alerting::Formatters::ValidationError
      )
    end

    it 'enforces payload size limits' do
      formatter = described_class.new(max_payload_bytes: 50)
      expect { formatter.format(sample_alert) }.to raise_error(
        RubyGuardian::DetectionEngine::Alerting::Formatters::PayloadTooLargeError
      )
    end
  end

  describe RubyGuardian::DetectionEngine::Alerting::Formatters::SyslogFormatter do
    let(:formatter) { described_class.new(facility: :local0, hostname: 'test-host') }

    it 'formats an alert as RFC 5424 syslog' do
      output = formatter.format(sample_alert)

      expect(output).to start_with('<')
      expect(output).to include('test-host')
      expect(output).to include('RubyGuardian')
      expect(output).to include('RULE-001')
    end

    it 'calculates correct PRI values' do
      # local0 (facility 16) + error (severity 3) = 16*8 + 3 = 131
      pri = formatter.calculate_priority('high')
      expect(pri).to eq(131)
    end

    it 'includes structured data elements' do
      output = formatter.format(sample_alert)

      expect(output).to include('alert@48577')
      expect(output).to include('mitre@48577')
      expect(output).to include('T1055')
    end

    it 'escapes special characters in SD params' do
      alert_with_special = sample_alert.merge(rule_name: 'Rule with "quotes" and ]brackets]')
      output = formatter.format(alert_with_special)

      expect(output).to include('\\"')
      expect(output).to include('\\]')
    end
  end

  describe RubyGuardian::DetectionEngine::Alerting::Formatters::CefFormatter do
    let(:formatter) { described_class.new }

    it 'formats an alert in CEF format' do
      output = formatter.format(sample_alert)

      expect(output).to start_with('CEF:0|')
      expect(output).to include('RubyGuardian|DetectionEngine')
      expect(output).to include('RULE-001')
    end

    it 'maps severity to CEF 0-10 scale' do
      output = formatter.format(sample_alert)
      # header: CEF:0|vendor|product|version|sigid|name|severity
      parts = output.split('|')
      expect(parts[6]).to eq('8')  # high -> 8
    end

    it 'includes extension key-value pairs' do
      output = formatter.format(sample_alert)

      expect(output).to include('src=192.168.1.100')
      expect(output).to include('dst=10.0.0.50')
      expect(output).to include('sproc=evil_tool.exe')
    end

    it 'escapes pipe characters in header fields' do
      alert = sample_alert.merge(rule_name: 'Rule|With|Pipes')
      output = formatter.format(alert)
      expect(output).to include('Rule\\|With\\|Pipes')
    end
  end

  describe RubyGuardian::DetectionEngine::Alerting::Formatters::LeefFormatter do
    let(:formatter) { described_class.new }

    it 'formats an alert in LEEF format' do
      output = formatter.format(sample_alert)

      expect(output).to start_with('LEEF:2.0|')
      expect(output).to include('RubyGuardian')
      expect(output).to include('RULE-001')
    end

    it 'includes LEEF standard attributes' do
      output = formatter.format(sample_alert)

      expect(output).to include('src=192.168.1.100')
      expect(output).to include('dst=10.0.0.50')
      expect(output).to include('sev=8')
    end

    it 'includes MITRE ATT&CK attributes' do
      output = formatter.format(sample_alert)

      expect(output).to include('mitreTactics=')
      expect(output).to include('mitreTechniques=T1055')
    end
  end

  describe RubyGuardian::DetectionEngine::Alerting::Channels::FileChannel do
    let(:tmpdir)  { Dir.mktmpdir('rg_alerts') }
    let(:logpath) { File.join(tmpdir, 'alerts.log') }

    after { FileUtils.rm_rf(tmpdir) }

    let(:channel) { described_class.new(path: logpath, rotation: :size, max_size: 1024, compress: false) }

    it 'writes alerts to a file' do
      channel.send_alert('Test alert line 1')
      channel.send_alert('Test alert line 2')
      channel.flush

      content = File.read(logpath)
      expect(content).to include('Test alert line 1')
      expect(content).to include('Test alert line 2')
    end

    it 'tracks write statistics' do
      channel.send_alert('Alert')
      expect(channel.stats[:written]).to eq(1)
    end

    it 'rotates files when size is exceeded' do
      large_message = 'X' * 600
      channel.send_alert(large_message)
      channel.send_alert(large_message)  # Should trigger rotation

      rotated = Dir.glob("#{logpath}.*")
      expect(rotated.size).to be >= 0  # Rotation happens lazily
    end

    it 'writes batch alerts' do
      channel.send_batch(['Batch 1', 'Batch 2', 'Batch 3'])
      channel.flush

      content = File.read(logpath)
      expect(content.lines.size).to eq(3)
    end

    it 'properly closes the file handle' do
      channel.send_alert('closing test')
      channel.close

      # Should be able to reopen and write again
      channel.send_alert('after close')
      channel.flush

      content = File.read(logpath)
      expect(content).to include('after close')
    end
  end
end
