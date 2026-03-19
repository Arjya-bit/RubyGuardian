# frozen_string_literal: true

require 'json'
require 'yaml'
require 'time'
require 'fileutils'
require 'erb'
require 'digest'

module RubyGuardian
  module MemoryForensics
    # ReportGenerator creates comprehensive forensic reports from analysis results,
    # supporting multiple output formats (HTML, JSON, PDF via external tools).
    class ReportGenerator
      SUPPORTED_FORMATS = %i[html json text].freeze

      ReportSection = Struct.new(
        :title, :content, :severity, :order, keyword_init: true
      )

      ReportMetadata = Struct.new(
        :case_id, :title, :analyst, :organization, :classification,
        :generated_at, :tool_version, :evidence_hashes, keyword_init: true
      )

      attr_reader :config, :sections, :metadata

      def initialize(config: nil)
        @config = load_config(config)
        @sections = []
        @metadata = build_metadata
        @evidence_items = []
      end

      # Add analysis results to the report
      def add_dump_info(dump_metadata)
        add_section(
          title: 'Evidence Acquisition',
          content: {
            pid: dump_metadata.pid,
            timestamp: dump_metadata.timestamp,
            method: dump_metadata.method,
            file: dump_metadata.output_path,
            size: format_size(dump_metadata.size),
            hashes: dump_metadata.hashes,
            ruby_version: dump_metadata.ruby_version,
            acquisition_duration: "#{dump_metadata.duration}s",
            host: dump_metadata.acquisition_host,
            regions_captured: dump_metadata.memory_regions&.size
          },
          severity: :info,
          order: 10
        )
      end

      def add_heap_analysis(analysis_result)
        stats = analysis_result[:stats] || {}
        anomalies = analysis_result[:anomalies] || []
        risk_score = analysis_result[:risk_score] || 0

        severity = case risk_score
                   when 0..2 then :low
                   when 2..5 then :medium
                   when 5..8 then :high
                   else :critical
                   end

        add_section(
          title: 'Heap Analysis',
          content: {
            statistics: {
              total_slots: stats[:total_slots] || stats['total_slots'],
              used_slots: stats[:used_slots] || stats['used_slots'],
              free_slots: stats[:free_slots] || stats['free_slots'],
              fragmentation: stats[:fragmentation_ratio] || stats['fragmentation_ratio'],
              type_distribution: stats[:type_distribution] || stats['type_distribution']
            },
            anomalies: anomalies.map { |a| format_anomaly(a) },
            risk_score: risk_score,
            anomaly_count: anomalies.size
          },
          severity: severity,
          order: 20
        )
      end

      def add_ioc_results(scan_result)
        severity = if scan_result.matches_by_severity[:critical]&.positive?
                     :critical
                   elsif scan_result.matches_by_severity[:high]&.positive?
                     :high
                   elsif scan_result.matches_by_severity[:medium]&.positive?
                     :medium
                   else
                     :low
                   end

        # Limit evidence items
        max_items = @config.dig('reporting', 'max_evidence_items') || 1000
        limited_matches = scan_result.matches.first(max_items)

        add_section(
          title: 'Indicators of Compromise',
          content: {
            summary: {
              total_matches: scan_result.total_matches,
              by_severity: scan_result.matches_by_severity,
              by_category: scan_result.matches_by_category,
              rules_loaded: scan_result.rules_loaded,
              scan_duration: "#{scan_result.scan_duration}s"
            },
            matches: limited_matches.map { |m| format_ioc_match(m) },
            heuristic_hits: scan_result.heuristic_hits
          },
          severity: severity,
          order: 30
        )
      end

      def add_string_analysis(statistics, suspicious_strings)
        add_section(
          title: 'String Analysis',
          content: {
            statistics: statistics,
            suspicious_strings: suspicious_strings.first(100).map do |s|
              {
                value: truncate(s[:string].value, 200),
                address: s[:string].address ? "0x#{s[:string].address.to_s(16)}" : nil,
                score: s[:score],
                reasons: s[:reasons],
                categories: s[:string].categories,
                entropy: s[:string].entropy
              }
            end
          },
          severity: suspicious_strings.any? { |s| s[:score] >= 4 } ? :high : :medium,
          order: 40
        )
      end

      def add_network_analysis(extraction_result)
        suspicious = find_suspicious_network(extraction_result)
        severity = suspicious.any? ? :high : :info

        add_section(
          title: 'Network Artifacts',
          content: {
            summary: extraction_result.summary,
            urls: extraction_result.urls.first(200).map { |u| { url: u.url, host: u.host, port: u.port } },
            ip_addresses: extraction_result.ips.first(200).map do |ip|
              { ip: ip.ip, version: ip.version, port: ip.port, private: ip.is_private }
            end,
            dns_entries: extraction_result.dns_entries.first(100).map do |d|
              { name: d.query_name, type: d.query_type }
            end,
            http_artifacts: extraction_result.http_artifacts.first(50).map do |h|
              { method: h.method, url: h.url, status: h.status_code, is_request: h.is_request }
            end,
            tls_sessions: extraction_result.tls_artifacts.first(50).map do |t|
              { version: t.version, sni: t.server_name }
            end,
            suspicious_findings: suspicious
          },
          severity: severity,
          order: 50
        )
      end

      def add_code_reconstruction(results, suspicious_code)
        add_section(
          title: 'Code Reconstruction',
          content: {
            total_reconstructed: results.size,
            code_blocks: results.first(50).map do |r|
              {
                label: r.label,
                path: r.path,
                type: r.type.to_s,
                confidence: r.confidence,
                source_preview: truncate(r.source, 500),
                first_lineno: r.first_lineno
              }
            end,
            suspicious_code: suspicious_code.first(20).map do |s|
              {
                label: s[:code].label,
                matches: s[:matches],
                max_severity: s[:max_severity].to_s,
                source_preview: truncate(s[:code].source, 300)
              }
            end
          },
          severity: suspicious_code.any? { |s| s[:max_severity] == :critical } ? :critical : :medium,
          order: 60
        )
      end

      def add_timeline(timeline_summary)
        severity = if (timeline_summary[:critical_events] || 0) > 0
                     :critical
                   elsif (timeline_summary[:high_events] || 0) > 0
                     :high
                   else
                     :info
                   end

        add_section(
          title: 'Forensic Timeline',
          content: timeline_summary,
          severity: severity,
          order: 70
        )
      end

      def add_custom_section(title:, content:, severity: :info, order: 80)
        add_section(title: title, content: content, severity: severity, order: order)
      end

      # Generate the final report
      def generate(format: :json, output_path: nil)
        unless SUPPORTED_FORMATS.include?(format.to_sym)
          raise ArgumentError, "Unsupported format: #{format}. Supported: #{SUPPORTED_FORMATS.join(', ')}"
        end

        sorted_sections = @sections.sort_by(&:order)

        content = case format.to_sym
                  when :json
                    generate_json(sorted_sections)
                  when :html
                    generate_html(sorted_sections)
                  when :text
                    generate_text(sorted_sections)
                  end

        if output_path
          FileUtils.mkdir_p(File.dirname(output_path))
          File.write(output_path, content)
        end

        content
      end

      # Generate reports in all configured formats
      def generate_all(output_dir:)
        FileUtils.mkdir_p(output_dir)
        formats = (@config.dig('reporting', 'formats') || %w[json html]).map(&:to_sym)
        generated = {}

        formats.each do |fmt|
          next unless SUPPORTED_FORMATS.include?(fmt)

          ext = fmt.to_s
          path = File.join(output_dir, "forensic_report_#{@metadata.case_id}.#{ext}")
          generate(format: fmt, output_path: path)
          generated[fmt] = path
        end

        generated
      end

      private

      def add_section(title:, content:, severity:, order:)
        @sections << ReportSection.new(
          title: title,
          content: content,
          severity: severity,
          order: order
        )
      end

      def build_metadata
        ReportMetadata.new(
          case_id: generate_case_id,
          title: 'RubyGuardian Memory Forensics Report',
          analyst: @config.dig('reporting', 'analyst', 'name') || 'Unknown',
          organization: @config.dig('reporting', 'analyst', 'organization') || 'RubyGuardian',
          classification: @config.dig('reporting', 'classification') || 'CONFIDENTIAL',
          generated_at: Time.now.utc.iso8601,
          tool_version: @config.dig('general', 'version') || '4.0.0',
          evidence_hashes: {}
        )
      end

      def generate_case_id
        "RG-#{Time.now.utc.strftime('%Y%m%d')}-#{SecureRandom.hex(4).upcase}"
      rescue StandardError
        "RG-#{Time.now.utc.strftime('%Y%m%d')}-#{rand(0xFFFF).to_s(16).upcase.rjust(4, '0')}"
      end

      def generate_json(sections)
        report = {
          metadata: @metadata.to_h,
          executive_summary: build_executive_summary(sections),
          sections: sections.map do |s|
            {
              title: s.title,
              severity: s.severity.to_s,
              content: s.content
            }
          end,
          risk_assessment: build_risk_assessment(sections),
          recommendations: build_recommendations(sections)
        }

        JSON.pretty_generate(report)
      end

      def generate_html(sections)
        exec_summary = build_executive_summary(sections)
        risk = build_risk_assessment(sections)
        recommendations = build_recommendations(sections)

        html = <<~HTML
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <title>#{@metadata.title} - #{@metadata.case_id}</title>
            <style>
              body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; color: #333; background: #f5f5f5; }
              .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
              h1 { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 10px; }
              h2 { color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 8px; margin-top: 30px; }
              .classification { background: #c0392b; color: white; padding: 5px 15px; text-align: center; font-weight: bold; letter-spacing: 2px; }
              .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 20px 0; }
              .metadata table { width: 100%; border-collapse: collapse; }
              .metadata td { padding: 5px 10px; }
              .metadata td:first-child { font-weight: bold; width: 200px; }
              .severity-critical { color: #c0392b; font-weight: bold; }
              .severity-high { color: #e67e22; font-weight: bold; }
              .severity-medium { color: #f39c12; }
              .severity-low { color: #27ae60; }
              .severity-info { color: #3498db; }
              .section { margin: 25px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
              .section-critical { border-left: 4px solid #c0392b; }
              .section-high { border-left: 4px solid #e67e22; }
              .section-medium { border-left: 4px solid #f39c12; }
              .section-low { border-left: 4px solid #27ae60; }
              .section-info { border-left: 4px solid #3498db; }
              pre { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-size: 13px; }
              code { background: #eee; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
              table { width: 100%; border-collapse: collapse; margin: 10px 0; }
              th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
              th { background: #34495e; color: white; }
              tr:hover { background: #f5f5f5; }
              .risk-score { font-size: 48px; font-weight: bold; text-align: center; padding: 20px; }
              .recommendations li { margin: 8px 0; }
              .footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid #bdc3c7; font-size: 12px; color: #7f8c8d; text-align: center; }
            </style>
          </head>
          <body>
            <div class="classification">#{@metadata.classification}</div>
            <div class="container">
              <h1>#{@metadata.title}</h1>
              <div class="metadata">
                <table>
                  <tr><td>Case ID:</td><td>#{@metadata.case_id}</td></tr>
                  <tr><td>Analyst:</td><td>#{@metadata.analyst}</td></tr>
                  <tr><td>Organization:</td><td>#{@metadata.organization}</td></tr>
                  <tr><td>Generated:</td><td>#{@metadata.generated_at}</td></tr>
                  <tr><td>Tool Version:</td><td>#{@metadata.tool_version}</td></tr>
                </table>
              </div>

              <h2>Executive Summary</h2>
              <div class="section section-#{exec_summary[:overall_severity]}">
                <p><strong>Overall Risk Level:</strong> <span class="severity-#{exec_summary[:overall_severity]}">#{exec_summary[:overall_severity].to_s.upcase}</span></p>
                <p>#{exec_summary[:narrative]}</p>
                <ul>
                  #{exec_summary[:key_findings].map { |f| "<li>#{html_escape(f)}</li>" }.join("\n              ")}
                </ul>
              </div>

              #{sections.map { |s| render_html_section(s) }.join("\n")}

              <h2>Risk Assessment</h2>
              <div class="section">
                <div class="risk-score severity-#{risk[:level]}">#{risk[:score]}/10</div>
                <p><strong>Risk Level:</strong> #{risk[:level].to_s.upcase}</p>
                <p>#{risk[:explanation]}</p>
              </div>

              <h2>Recommendations</h2>
              <div class="section">
                <ul class="recommendations">
                  #{recommendations.map { |r| "<li><strong>[#{r[:priority].upcase}]</strong> #{html_escape(r[:text])}</li>" }.join("\n              ")}
                </ul>
              </div>

              <div class="footer">
                <p>#{@metadata.classification} - #{@metadata.organization}</p>
                <p>Generated by RubyGuardian Memory Forensics Toolkit v#{@metadata.tool_version}</p>
              </div>
            </div>
            <div class="classification">#{@metadata.classification}</div>
          </body>
          </html>
        HTML

        html
      end

      def generate_text(sections)
        lines = []
        lines << "=" * 70
        lines << @metadata.classification.center(70)
        lines << "=" * 70
        lines << ""
        lines << @metadata.title
        lines << "-" * @metadata.title.length
        lines << "Case ID: #{@metadata.case_id}"
        lines << "Analyst: #{@metadata.analyst}"
        lines << "Organization: #{@metadata.organization}"
        lines << "Generated: #{@metadata.generated_at}"
        lines << ""

        exec_summary = build_executive_summary(sections)
        lines << "EXECUTIVE SUMMARY"
        lines << "-" * 40
        lines << "Overall Risk: #{exec_summary[:overall_severity].to_s.upcase}"
        lines << ""
        lines << exec_summary[:narrative]
        lines << ""
        lines << "Key Findings:"
        exec_summary[:key_findings].each { |f| lines << "  - #{f}" }
        lines << ""

        sections.each do |section|
          lines << "=" * 50
          lines << "[#{section.severity.to_s.upcase}] #{section.title}"
          lines << "=" * 50
          lines << format_content_text(section.content, 0)
          lines << ""
        end

        recommendations = build_recommendations(sections)
        lines << "RECOMMENDATIONS"
        lines << "-" * 40
        recommendations.each { |r| lines << "  [#{r[:priority].upcase}] #{r[:text]}" }
        lines << ""
        lines << "=" * 70
        lines << @metadata.classification.center(70)
        lines << "=" * 70

        lines.join("\n")
      end

      def render_html_section(section)
        <<~HTML
          <h2>#{html_escape(section.title)}</h2>
          <div class="section section-#{section.severity}">
            <p><strong>Severity:</strong> <span class="severity-#{section.severity}">#{section.severity.to_s.upcase}</span></p>
            <pre>#{html_escape(JSON.pretty_generate(section.content))}</pre>
          </div>
        HTML
      end

      def build_executive_summary(sections)
        severities = sections.map(&:severity)
        overall = if severities.include?(:critical) then :critical
                  elsif severities.include?(:high) then :high
                  elsif severities.include?(:medium) then :medium
                  else :low
                  end

        findings = []
        sections.each do |s|
          case s.title
          when 'Indicators of Compromise'
            total = s.content.dig(:summary, :total_matches) || 0
            findings << "#{total} indicators of compromise detected" if total > 0
          when 'Heap Analysis'
            count = s.content[:anomaly_count] || 0
            findings << "#{count} heap anomalies identified" if count > 0
          when 'Network Artifacts'
            summary = s.content[:summary] || {}
            findings << "#{summary[:total_urls] || 0} URLs and #{summary[:external_ips] || 0} external IPs found"
          when 'Code Reconstruction'
            sus = s.content[:suspicious_code]&.size || 0
            findings << "#{sus} suspicious code blocks identified" if sus > 0
          end
        end

        findings << "No significant threats detected" if findings.empty?

        narrative = "Analysis of the memory dump revealed #{findings.size} key finding(s). " \
                    "The overall risk level is #{overall.to_s.upcase}."

        { overall_severity: overall, key_findings: findings, narrative: narrative }
      end

      def build_risk_assessment(sections)
        score = 0
        sections.each do |s|
          case s.severity
          when :critical then score += 3
          when :high then score += 2
          when :medium then score += 1
          end
        end
        score = [score, 10].min

        level = case score
                when 0..2 then :low
                when 3..5 then :medium
                when 6..7 then :high
                else :critical
                end

        explanation = case level
                      when :critical
                        'Critical threats detected requiring immediate incident response.'
                      when :high
                        'Significant threats identified that require prompt investigation.'
                      when :medium
                        'Moderate risk indicators found that warrant further analysis.'
                      else
                        'Low risk profile with no significant threats detected.'
                      end

        { score: score, level: level, explanation: explanation }
      end

      def build_recommendations(sections)
        recs = []
        sections.each do |s|
          case s.severity
          when :critical
            recs << { priority: 'critical', text: "Investigate #{s.title} findings immediately and initiate incident response procedures." }
          when :high
            recs << { priority: 'high', text: "Review #{s.title} findings and assess potential impact on production systems." }
          end
        end

        recs << { priority: 'medium', text: 'Update IOC signatures and YARA rules with newly discovered patterns.' }
        recs << { priority: 'low', text: 'Document findings and update security monitoring rules accordingly.' }
        recs << { priority: 'low', text: 'Review and harden Ruby application security configurations.' }

        recs
      end

      def format_anomaly(anomaly)
        if anomaly.is_a?(Hash)
          anomaly.transform_keys(&:to_s)
        else
          anomaly.to_h.transform_keys(&:to_s)
        end
      end

      def format_ioc_match(match)
        if match.is_a?(Hash)
          match
        else
          {
            rule: match.rule_name,
            category: match.category.to_s,
            severity: match.severity.to_s,
            description: match.description,
            address: match.address ? "0x#{match.address.to_s(16)}" : nil,
            confidence: match.confidence,
            matched_data: truncate(match.matched_data.to_s, 200)
          }
        end
      end

      def find_suspicious_network(result)
        findings = []
        result.ips.each do |ip|
          next if ip.is_private

          findings << "External IP: #{ip.ip}:#{ip.port}" if ip.port
        end
        result.urls.each do |url|
          findings << "Suspicious URL: #{url.url[0, 100]}" if url.host&.match?(/\A\d+\.\d+/)
        end
        findings.first(20)
      end

      def format_content_text(content, indent)
        case content
        when Hash
          content.map do |k, v|
            prefix = '  ' * indent
            "#{prefix}#{k}: #{format_content_text(v, indent + 1)}"
          end.join("\n")
        when Array
          content.first(20).map { |item| "  #{'  ' * indent}- #{format_content_text(item, indent + 1)}" }.join("\n")
        else
          content.to_s
        end
      end

      def html_escape(str)
        str.to_s
           .gsub('&', '&amp;')
           .gsub('<', '&lt;')
           .gsub('>', '&gt;')
           .gsub('"', '&quot;')
      end

      def format_size(bytes)
        return '0 B' unless bytes

        units = %w[B KB MB GB TB]
        idx = 0
        size = bytes.to_f
        while size >= 1024 && idx < units.size - 1
          size /= 1024
          idx += 1
        end
        "#{size.round(2)} #{units[idx]}"
      end

      def truncate(str, max_len)
        return '' unless str

        str.length > max_len ? "#{str[0, max_len]}..." : str
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end
    end
  end
end
