# frozen_string_literal: true

# RubyGuardian Phase 4 - Forensic Report Generator
# Generates comprehensive forensic reports from completed analysis results.
# Supports JSON, HTML, and plain-text output formats.
#
# Usage:
#   ruby scripts/generate_report.rb --input <analysis_dir>
#   ruby scripts/generate_report.rb --input <analysis_dir> --format html
#   ruby scripts/generate_report.rb --input <analysis_dir> --output /path/to/reports

require "optparse"
require "yaml"
require "json"
require "logger"
require "fileutils"
require "time"
require "digest"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "report_generator"
require "timeline_builder"

module RubyGuardian
  module MemoryForensics
    # ReportCLI provides a command-line interface for generating forensic
    # reports from previously completed analysis results stored on disk.
    class ReportCLI
      DEFAULT_CONFIG_PATH = File.expand_path("../config/forensics_config.yml", __dir__)
      SUPPORTED_FORMATS = %w[json html text all].freeze

      attr_reader :options, :config, :logger

      def initialize(options = {})
        @options = options
        @config = load_config
        @logger = build_logger
      end

      def run
        logger.info("RubyGuardian Forensic Report Generator")
        logger.info("=" * 50)

        input_dir = resolve_input_dir
        unless input_dir
          logger.error("No input directory specified or found")
          return false
        end

        logger.info("Input directory: #{input_dir}")
        output_dir = resolve_output_dir(input_dir)
        FileUtils.mkdir_p(output_dir)

        # Load analysis results from disk
        results = load_analysis_results(input_dir)
        if results.empty?
          logger.error("No analysis results found in #{input_dir}")
          return false
        end

        logger.info("Loaded #{results.size} analysis result files")

        # Build the report
        generator = ReportGenerator.new(config: @config)
        populate_report(generator, results)

        # Generate reports in requested formats
        formats = determine_formats
        generated = {}

        formats.each do |fmt|
          begin
            path = File.join(output_dir, "forensic_report.#{fmt}")
            content = generator.generate(format: fmt.to_sym, output_path: path)
            generated[fmt] = path
            logger.info("Generated #{fmt.upcase} report: #{path} (#{content.bytesize} bytes)")
          rescue StandardError => e
            logger.error("Failed to generate #{fmt} report: #{e.message}")
          end
        end

        # Generate executive summary if requested
        if options[:executive_summary]
          summary_path = File.join(output_dir, "executive_summary.txt")
          generate_executive_summary(generator, results, summary_path)
          generated["summary"] = summary_path
        end

        # Generate evidence index
        index_path = File.join(output_dir, "evidence_index.json")
        generate_evidence_index(input_dir, results, index_path)
        generated["evidence_index"] = index_path

        print_summary(generated)
        true
      end

      private

      def resolve_input_dir
        if options[:input]
          path = File.expand_path(options[:input])
          return path if File.directory?(path)

          logger.error("Input directory not found: #{path}")
          return nil
        end

        # Try to find the most recent analysis directory
        reports_base = File.expand_path("../reports", __dir__)
        if File.directory?(reports_base)
          dirs = Dir.glob(File.join(reports_base, "analysis_*")).sort_by { |d| File.mtime(d) }
          return dirs.last unless dirs.empty?
        end

        nil
      end

      def resolve_output_dir(input_dir)
        if options[:output]
          File.expand_path(options[:output])
        else
          File.join(input_dir, "reports_#{Time.now.utc.strftime('%Y%m%d_%H%M%S')}")
        end
      end

      def load_analysis_results(input_dir)
        results = {}

        # Load JSON result files
        Dir.glob(File.join(input_dir, "**/*.json")).each do |json_file|
          begin
            basename = File.basename(json_file, ".json")
            data = JSON.parse(File.read(json_file), symbolize_names: true)
            results[basename.to_sym] = data
            logger.debug("Loaded: #{basename}")
          rescue JSON::ParserError => e
            logger.warn("Skipping malformed JSON: #{json_file} (#{e.message})")
          end
        end

        # Load timeline data
        timeline_files = Dir.glob(File.join(input_dir, "timeline_*.json"))
        unless timeline_files.empty?
          begin
            timeline = JSON.parse(File.read(timeline_files.last), symbolize_names: true)
            results[:timeline] = timeline
          rescue JSON::ParserError => e
            logger.warn("Could not parse timeline: #{e.message}")
          end
        end

        results
      end

      def populate_report(generator, results)
        # Add heap analysis if present
        if results[:heap_analysis]
          generator.add_heap_analysis(results[:heap_analysis])
          logger.info("Added heap analysis to report")
        end

        # Add timeline if present
        if results[:timeline]
          generator.add_timeline(results[:timeline])
          logger.info("Added timeline to report")
        end

        # Add custom sections for remaining result types
        results.each do |key, data|
          next if %i[heap_analysis timeline dump_metadata].include?(key)

          title = key.to_s.split("_").map(&:capitalize).join(" ")
          severity = infer_severity(data)

          generator.add_custom_section(
            title: title,
            content: data,
            severity: severity,
            order: 50
          )
          logger.info("Added section: #{title} (severity: #{severity})")
        end
      end

      def determine_formats
        if options[:format] == "all"
          %w[json html text]
        elsif options[:format]
          [options[:format]]
        else
          %w[json html]
        end
      end

      def infer_severity(data)
        return :info unless data.is_a?(Hash)

        risk = data[:risk_score] || data[:risk] || 0
        case risk
        when 0..2 then :low
        when 3..5 then :medium
        when 6..8 then :high
        else :critical
        end
      end

      def generate_executive_summary(generator, results, output_path)
        lines = []
        lines << "RUBYGUARDIAN FORENSIC EXECUTIVE SUMMARY"
        lines << "=" * 50
        lines << "Generated: #{Time.now.utc.iso8601}"
        lines << ""
        lines << "ANALYSIS OVERVIEW"
        lines << "-" * 30
        lines << "Total result sets analyzed: #{results.size}"
        lines << ""

        # Summarize findings by severity
        severity_counts = { critical: 0, high: 0, medium: 0, low: 0 }
        results.each_value do |data|
          next unless data.is_a?(Hash)

          sev = infer_severity(data)
          severity_counts[sev] += 1
        end

        lines << "FINDINGS BY SEVERITY"
        lines << "-" * 30
        severity_counts.each do |level, count|
          lines << "  #{level.to_s.upcase}: #{count}" if count > 0
        end
        lines << ""

        # Key metrics
        lines << "KEY METRICS"
        lines << "-" * 30
        if results[:heap_analysis]
          anomalies = results[:heap_analysis][:anomalies]
          lines << "  Heap anomalies: #{anomalies&.size || 0}"
        end
        if results[:timeline]
          lines << "  Timeline events: #{results[:timeline][:total_events] || 0}"
        end

        lines << ""
        lines << "RECOMMENDATION"
        lines << "-" * 30
        if severity_counts[:critical] > 0
          lines << "  IMMEDIATE ACTION REQUIRED: Critical findings detected."
          lines << "  Initiate incident response procedures."
        elsif severity_counts[:high] > 0
          lines << "  HIGH PRIORITY: Significant findings require prompt investigation."
        else
          lines << "  No critical or high-severity findings detected."
          lines << "  Continue routine monitoring."
        end

        File.write(output_path, lines.join("\n"))
        logger.info("Executive summary written to #{output_path}")
      end

      def generate_evidence_index(input_dir, results, output_path)
        index = {
          generated_at: Time.now.utc.iso8601,
          input_directory: input_dir,
          evidence_files: [],
          result_summary: {}
        }

        Dir.glob(File.join(input_dir, "**/*")).each do |file_path|
          next unless File.file?(file_path)

          index[:evidence_files] << {
            path: file_path,
            relative_path: file_path.sub("#{input_dir}/", ""),
            size: File.size(file_path),
            modified: File.mtime(file_path).utc.iso8601,
            sha256: Digest::SHA256.file(file_path).hexdigest
          }
        end

        results.each do |key, data|
          index[:result_summary][key] = {
            type: data.class.name,
            keys: data.is_a?(Hash) ? data.keys.map(&:to_s) : nil,
            severity: infer_severity(data).to_s
          }
        end

        File.write(output_path, JSON.pretty_generate(index))
        logger.info("Evidence index written to #{output_path}")
      end

      def print_summary(generated)
        logger.info("")
        logger.info("=" * 50)
        logger.info("Report Generation Complete")
        logger.info("=" * 50)
        generated.each do |fmt, path|
          size = File.exist?(path) ? File.size(path) : 0
          logger.info("  #{fmt.upcase}: #{path} (#{size} bytes)")
        end
      end

      def load_config
        path = options[:config] || DEFAULT_CONFIG_PATH
        if File.exist?(path)
          YAML.safe_load(File.read(path), permitted_classes: [Symbol])
        else
          {}
        end
      end

      def build_logger
        logger = Logger.new($stdout)
        logger.level = options[:verbose] ? Logger::DEBUG : Logger::INFO
        logger.formatter = proc do |severity, datetime, _progname, msg|
          "[#{datetime.utc.iso8601}] #{severity.ljust(5)} #{msg}\n"
        end
        logger
      end
    end
  end
end

# CLI entry point
if __FILE__ == $PROGRAM_NAME
  options = {}

  OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
    opts.separator ""
    opts.separator "RubyGuardian Forensic Report Generator"
    opts.separator ""

    opts.on("-i", "--input DIR", "Input directory with analysis results") { |v| options[:input] = v }
    opts.on("-o", "--output DIR", "Output directory for reports") { |v| options[:output] = v }
    opts.on("-f", "--format FMT", "Output format (json, html, text, all)") { |v| options[:format] = v }
    opts.on("-c", "--config PATH", "Path to config file") { |v| options[:config] = v }
    opts.on("-e", "--executive-summary", "Generate executive summary") { options[:executive_summary] = true }
    opts.on("-v", "--verbose", "Enable verbose logging") { options[:verbose] = true }
    opts.on("-h", "--help", "Show this help message") { puts opts; exit }
  end.parse!

  cli = RubyGuardian::MemoryForensics::ReportCLI.new(options)
  success = cli.run
  exit(success ? 0 : 1)
end
