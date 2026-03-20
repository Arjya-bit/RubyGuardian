# frozen_string_literal: true

require "json"
require "time"
require "logger"
require "fileutils"
require "erb"

module RubyGuardian
  module Honeypot
    module Analysis
      # DailyReport generates comprehensive daily summary reports of honeypot
      # activity. It aggregates data from all capture engines, sandbox results,
      # and analysis modules into statistics, trends, and actionable intelligence.
      class DailyReport
        TEMPLATE_DIR = File.expand_path("../views", __dir__)

        attr_reader :report_date, :data

        def initialize(data_dir:, output_dir:, report_date: nil, logger: nil)
          @data_dir = data_dir
          @output_dir = output_dir
          @report_date = report_date || Date.today
          @logger = logger || default_logger
          @data = {}
        end

        # Generate the full daily report.
        def generate!
          @logger.info("[DailyReport] Generating report for #{@report_date}")

          @data = {
            metadata: build_metadata,
            capture_summary: build_capture_summary,
            sample_analysis: build_sample_analysis,
            network_activity: build_network_activity,
            credential_activity: build_credential_activity,
            threat_families: build_threat_families,
            geographic_distribution: build_geographic_distribution,
            trends: build_trends,
            iocs: build_ioc_summary,
            recommendations: build_recommendations
          }

          write_json_report
          write_text_report

          @logger.info("[DailyReport] Report generated: #{json_report_path}")
          @data
        end

        # Build report metadata.
        def build_metadata
          {
            report_date: @report_date.iso8601,
            generated_at: Time.now.utc.iso8601,
            reporting_period_start: "#{@report_date}T00:00:00Z",
            reporting_period_end: "#{@report_date}T23:59:59Z",
            version: "1.0.0",
            generator: "RubyGuardian::Honeypot::Analysis::DailyReport"
          }
        end

        private

        def build_capture_summary
          captures = load_captures_for_date

          {
            total_events: captures.size,
            events_by_type: captures.group_by { |c| c[:type] || "unknown" }.transform_values(&:size),
            events_by_hour: hourly_distribution(captures),
            unique_source_ips: captures.map { |c| c[:source_ip] }.compact.uniq.size,
            peak_hour: peak_hour(captures),
            gem_server_requests: captures.count { |c| c[:type] == "gem_request" },
            ci_runner_attempts: captures.count { |c| c[:type] == "ci_injection" },
            sandbox_executions: captures.count { |c| c[:type] == "sandbox_run" }
          }
        end

        def build_sample_analysis
          samples = load_sandbox_results

          analyzed = samples.select { |s| s[:status] == "completed" }
          malicious = analyzed.select { |s| (s.dig(:threat_assessment, :score) || 0) >= 50 }

          {
            total_samples_received: samples.size,
            samples_analyzed: analyzed.size,
            samples_pending: samples.count { |s| s[:status] == "pending" },
            malicious_samples: malicious.size,
            benign_samples: analyzed.size - malicious.size,
            detection_rate: analyzed.empty? ? 0 : (malicious.size.to_f / analyzed.size * 100).round(1),
            average_risk_score: analyzed.empty? ? 0 : (analyzed.sum { |s| s.dig(:threat_assessment, :score) || 0 }.to_f / analyzed.size).round(1),
            highest_risk_sample: analyzed.max_by { |s| s.dig(:threat_assessment, :score) || 0 },
            severity_distribution: analyzed.group_by { |s| s.dig(:threat_assessment, :risk_level) || :unknown }.transform_values(&:size)
          }
        end

        def build_network_activity
          network_events = load_network_captures

          {
            total_connections: network_events.size,
            unique_destinations: network_events.map { |n| n[:destination] }.compact.uniq.size,
            protocols: network_events.group_by { |n| n[:protocol] }.transform_values(&:size),
            top_destinations: network_events.group_by { |n| n[:destination] }
                                            .transform_values(&:size)
                                            .sort_by { |_, c| -c }
                                            .first(10)
                                            .to_h,
            top_ports: network_events.group_by { |n| n[:port] }
                                     .transform_values(&:size)
                                     .sort_by { |_, c| -c }
                                     .first(10)
                                     .to_h,
            dns_queries: network_events.count { |n| n[:type] == "dns" },
            exfiltration_attempts: network_events.count { |n| n[:is_known_exfil_port] }
          }
        end

        def build_credential_activity
          cred_events = load_credential_captures

          {
            total_access_attempts: cred_events.size,
            tokens_accessed: cred_events.group_by { |c| c[:token_name] }.transform_values(&:size),
            access_types: cred_events.group_by { |c| c[:access_type] }.transform_values(&:size),
            most_targeted: cred_events.group_by { |c| c[:token_name] }
                                      .max_by { |_, v| v.size }&.first,
            timeline: cred_events.map { |c| { time: c[:timestamp], token: c[:token_name], type: c[:access_type] } }
                                 .sort_by { |e| e[:time] }
          }
        end

        def build_threat_families
          matches = load_pattern_matches

          families = matches.group_by { |m| m[:family] }
          {
            total_matches: matches.size,
            unique_families: families.keys,
            family_counts: families.transform_values(&:size).sort_by { |_, c| -c }.to_h,
            top_rules: matches.group_by { |m| m[:rule_name] }
                              .transform_values(&:size)
                              .sort_by { |_, c| -c }
                              .first(5)
                              .to_h,
            severity_distribution: matches.group_by { |m| m[:severity] }.transform_values(&:size)
          }
        end

        def build_geographic_distribution
          enrichments = load_ip_enrichments

          countries = enrichments.map { |e| e.dig(:sources, :geolocation, :country) }.compact
          {
            unique_countries: countries.uniq.size,
            top_countries: countries.tally.sort_by { |_, c| -c }.first(10).to_h,
            hosting_percentage: enrichments.empty? ? 0 :
              (enrichments.count { |e| e.dig(:sources, :geolocation, :hosting) }.to_f / enrichments.size * 100).round(1),
            proxy_percentage: enrichments.empty? ? 0 :
              (enrichments.count { |e| e.dig(:sources, :geolocation, :proxy) }.to_f / enrichments.size * 100).round(1)
          }
        end

        def build_trends
          # Compare with previous day's data
          prev_data = load_previous_report
          current_events = @data.dig(:capture_summary, :total_events) || 0
          prev_events = prev_data.dig(:capture_summary, :total_events) || 0

          {
            events_change_pct: prev_events.zero? ? 0 : ((current_events - prev_events).to_f / prev_events * 100).round(1),
            new_families_detected: new_families(prev_data),
            activity_trend: current_events > prev_events ? :increasing : (current_events < prev_events ? :decreasing : :stable)
          }
        end

        def build_ioc_summary
          iocs = load_iocs

          {
            total_iocs: iocs.size,
            by_type: iocs.group_by { |i| i[:type] }.transform_values(&:size),
            unique_ips: iocs.select { |i| i[:type].to_s == "ip" }.map { |i| i[:value] }.uniq,
            unique_domains: iocs.select { |i| i[:type].to_s == "domain" }.map { |i| i[:value] }.uniq,
            unique_urls: iocs.select { |i| i[:type].to_s == "url" }.map { |i| i[:value] }.uniq
          }
        end

        def build_recommendations
          recs = []
          summary = @data[:capture_summary] || {}
          analysis = @data[:sample_analysis] || {}

          if (summary[:total_events] || 0) > 1000
            recs << { priority: :high, action: "High event volume detected. Review capacity and consider scaling honeypot infrastructure." }
          end
          if (analysis[:detection_rate] || 0) < 50 && (analysis[:total_samples_received] || 0) > 10
            recs << { priority: :medium, action: "Low detection rate. Update pattern matching rules and review false negatives." }
          end
          if (@data.dig(:threat_families, :unique_families)&.size || 0) > 5
            recs << { priority: :high, action: "Multiple threat families active. Prioritize analysis of new families." }
          end

          recs << { priority: :low, action: "Review and update honeytoken configurations for continued effectiveness." }
          recs
        end

        # Data loading helpers (read from JSON files in data_dir)

        def load_captures_for_date
          load_json_files("captures", "exec_captures_*.json") +
            load_json_files("captures", "file_captures_*.json") +
            load_json_files("captures", "network_captures_*.json")
        end

        def load_sandbox_results
          load_json_files("output", "behavior_summary_*.json")
        end

        def load_network_captures
          load_json_files("captures", "network_captures_*.json").flat_map { |f| f[:connections] || [] }
        end

        def load_credential_captures
          load_json_files("captures", "credential_accesses_*.json").flat_map { |f| f[:accesses] || [] }
        end

        def load_pattern_matches
          load_json_files("analysis", "pattern_matches_*.json").flat_map { |f| f[:matches] || [] }
        end

        def load_ip_enrichments
          load_json_files("analysis", "ip_enrichment_*.json")
        end

        def load_iocs
          load_json_files("output", "behavior_iocs_*.json").flat_map { |f| f[:iocs] || [] }
        end

        def load_previous_report
          prev_date = @report_date - 1
          path = File.join(@output_dir, "daily_report_#{prev_date.iso8601}.json")
          File.exist?(path) ? JSON.parse(File.read(path), symbolize_names: true) : {}
        rescue StandardError
          {}
        end

        def load_json_files(subdir, pattern)
          dir = File.join(@data_dir, subdir)
          return [] unless Dir.exist?(dir)

          Dir.glob(File.join(dir, pattern)).filter_map do |path|
            data = JSON.parse(File.read(path), symbolize_names: true)
            file_date = File.mtime(path).to_date
            data if file_date == @report_date
          rescue JSON::ParserError => e
            @logger.warn("[DailyReport] Failed to parse #{path}: #{e.message}")
            nil
          end
        end

        def new_families(prev_data)
          current = @data.dig(:threat_families, :unique_families) || []
          previous = prev_data.dig(:threat_families, :unique_families) || []
          current - previous
        end

        def hourly_distribution(events)
          (0..23).each_with_object({}) do |hour, dist|
            dist[format("%02d:00", hour)] = events.count { |e| Time.parse(e[:timestamp].to_s).hour == hour rescue false }
          end
        end

        def peak_hour(events)
          dist = hourly_distribution(events)
          dist.max_by { |_, c| c }&.first || "N/A"
        end

        def write_json_report
          FileUtils.mkdir_p(@output_dir)
          File.write(json_report_path, JSON.pretty_generate(@data))
        end

        def write_text_report
          FileUtils.mkdir_p(@output_dir)
          text_path = File.join(@output_dir, "daily_report_#{@report_date.iso8601}.txt")

          lines = []
          lines << "=" * 72
          lines << "  RubyGuardian Honeypot Daily Report - #{@report_date}"
          lines << "=" * 72
          lines << ""
          lines << "Generated: #{Time.now.utc.iso8601}"
          lines << ""
          lines << "--- Capture Summary ---"
          cs = @data[:capture_summary] || {}
          lines << "  Total events:         #{cs[:total_events] || 0}"
          lines << "  Unique source IPs:    #{cs[:unique_source_ips] || 0}"
          lines << "  Gem server requests:  #{cs[:gem_server_requests] || 0}"
          lines << "  CI runner attempts:   #{cs[:ci_runner_attempts] || 0}"
          lines << "  Sandbox executions:   #{cs[:sandbox_executions] || 0}"
          lines << ""
          lines << "--- Sample Analysis ---"
          sa = @data[:sample_analysis] || {}
          lines << "  Samples received:     #{sa[:total_samples_received] || 0}"
          lines << "  Analyzed:             #{sa[:samples_analyzed] || 0}"
          lines << "  Malicious:            #{sa[:malicious_samples] || 0}"
          lines << "  Detection rate:       #{sa[:detection_rate] || 0}%"
          lines << ""
          lines << "--- Recommendations ---"
          (@data[:recommendations] || []).each do |rec|
            lines << "  [#{rec[:priority].upcase}] #{rec[:action]}"
          end
          lines << ""
          lines << "=" * 72

          File.write(text_path, lines.join("\n"))
        end

        def json_report_path
          File.join(@output_dir, "daily_report_#{@report_date.iso8601}.json")
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::DailyReport")
        end
      end
    end
  end
end
