# frozen_string_literal: true

# RubyGuardian Phase 4 - Full Memory Forensic Analysis Orchestrator
# Coordinates all forensic analysis modules to produce a comprehensive
# investigation report from a memory dump or live process.
#
# Usage:
#   ruby scripts/run_full_analysis.rb --dump <path>    # Analyze existing dump
#   ruby scripts/run_full_analysis.rb --pid <pid>      # Capture and analyze live process
#   ruby scripts/run_full_analysis.rb --sample         # Analyze sample dumps in sample_dumps/

require "optparse"
require "yaml"
require "json"
require "logger"
require "fileutils"
require "time"

$LOAD_PATH.unshift(File.expand_path("../lib", __dir__))

require "memory_dumper"
require "dump_parser"
require "ruby_vm_parser"
require "heap_analyzer"
require "ioc_scanner"
require "string_extractor"
require "objectspace_reconstructor"
require "code_reconstructor"
require "deobfuscator"
require "network_artifact_extractor"
require "timeline_builder"
require "report_generator"

module RubyGuardian
  module MemoryForensics
    # FullAnalysis orchestrates a complete forensic investigation pipeline,
    # running each analysis module in sequence and aggregating results into
    # a final report with timeline, IOC findings, and risk assessment.
    class FullAnalysis
      DEFAULT_CONFIG_PATH = File.expand_path("../config/forensics_config.yml", __dir__)
      DEFAULT_OUTPUT_DIR  = File.expand_path("../reports", __dir__)

      ANALYSIS_PHASES = %i[
        dump_acquisition
        dump_parsing
        vm_structure_analysis
        heap_analysis
        ioc_scanning
        string_extraction
        objectspace_reconstruction
        code_reconstruction
        deobfuscation
        network_artifact_extraction
        timeline_construction
        report_generation
      ].freeze

      attr_reader :config, :logger, :results, :options

      def initialize(options = {})
        @options = options
        @config  = load_config(options[:config])
        @logger  = build_logger
        @results = {}
        @start_time = nil
        @errors  = []
      end

      # Run the complete forensic analysis pipeline
      def run
        @start_time = Time.now
        logger.info("=" * 70)
        logger.info("RubyGuardian Memory Forensics - Full Analysis")
        logger.info("Started: #{@start_time.utc.iso8601}")
        logger.info("=" * 70)

        dump_path = resolve_dump_path
        unless dump_path
          logger.error("No dump file available for analysis. Provide --dump or --pid.")
          return false
        end

        logger.info("Target dump: #{dump_path}")
        logger.info("Output directory: #{output_dir}")
        FileUtils.mkdir_p(output_dir)

        run_phase(:dump_parsing) { parse_dump(dump_path) }
        run_phase(:vm_structure_analysis) { analyze_vm_structures }
        run_phase(:heap_analysis) { analyze_heap }
        run_phase(:ioc_scanning) { scan_for_iocs(dump_path) }
        run_phase(:string_extraction) { extract_strings(dump_path) }
        run_phase(:objectspace_reconstruction) { reconstruct_objectspace }
        run_phase(:code_reconstruction) { reconstruct_code }
        run_phase(:deobfuscation) { run_deobfuscation }
        run_phase(:network_artifact_extraction) { extract_network_artifacts(dump_path) }
        run_phase(:timeline_construction) { build_timeline }
        run_phase(:report_generation) { generate_reports }

        duration = Time.now - @start_time
        print_summary(duration)

        @errors.empty?
      end

      private

      # ------------------------------------------------------------------
      # Phase execution wrapper with error handling and timing
      # ------------------------------------------------------------------
      def run_phase(phase_name)
        phase_start = Time.now
        logger.info("-" * 50)
        logger.info("Phase: #{phase_name}")

        result = yield
        @results[phase_name] = result

        elapsed = (Time.now - phase_start).round(2)
        logger.info("Phase #{phase_name} completed in #{elapsed}s")
        result
      rescue StandardError => e
        @errors << { phase: phase_name, error: e.message, backtrace: e.backtrace&.first(5) }
        logger.error("Phase #{phase_name} failed: #{e.class} - #{e.message}")
        logger.debug(e.backtrace&.first(10)&.join("\n")) if e.backtrace
        nil
      end

      # ------------------------------------------------------------------
      # Dump acquisition / resolution
      # ------------------------------------------------------------------
      def resolve_dump_path
        if options[:dump]
          path = File.expand_path(options[:dump])
          unless File.exist?(path)
            logger.error("Dump file not found: #{path}")
            return nil
          end
          return path
        end

        if options[:pid]
          return capture_live_process(options[:pid].to_i)
        end

        if options[:sample]
          return find_sample_dump
        end

        nil
      end

      def capture_live_process(pid)
        logger.info("Capturing memory dump from PID #{pid}")
        output_path = File.join(output_dir, "dump_pid#{pid}_#{timestamp_tag}")
        dumper = MemoryDumper.new(pid: pid, config: @config, logger: @logger)
        metadata = dumper.capture(output: output_path, compress: true)
        @results[:dump_acquisition] = metadata
        metadata.output_path
      end

      def find_sample_dump
        sample_dir = File.expand_path("../sample_dumps", __dir__)
        dumps = Dir.glob(File.join(sample_dir, "*.{raw,gz,dump,bin,core}")).sort_by { |f| File.mtime(f) }
        if dumps.empty?
          logger.warn("No sample dumps found in #{sample_dir}")
          return nil
        end
        logger.info("Using sample dump: #{dumps.last}")
        dumps.last
      end

      # ------------------------------------------------------------------
      # Analysis phases
      # ------------------------------------------------------------------
      def parse_dump(dump_path)
        parser = DumpParser.new(dump_path, config: @config, logger: @logger)
        parsed = parser.parse
        logger.info("Parsed #{parsed[:regions]&.size || 0} memory regions")
        parsed
      end

      def analyze_vm_structures
        parsed = @results[:dump_parsing]
        return nil unless parsed

        vm_parser = RubyVmParser.new(parsed, config: @config, logger: @logger)
        vm_result = vm_parser.analyze
        logger.info("Identified Ruby VM structures: #{vm_result[:structures_found] || 'N/A'}")
        vm_result
      end

      def analyze_heap
        parsed = @results[:dump_parsing]
        return nil unless parsed

        analyzer = HeapAnalyzer.new(parsed, config: @config, logger: @logger)
        heap_result = analyzer.analyze
        anomaly_count = heap_result[:anomalies]&.size || 0
        logger.info("Heap analysis: #{anomaly_count} anomalies, risk score #{heap_result[:risk_score] || 0}")
        heap_result
      end

      def scan_for_iocs(dump_path)
        scanner = IocScanner.new(dump_path, config: @config, logger: @logger)
        scan_result = scanner.scan
        logger.info("IOC scan: #{scan_result.total_matches rescue 0} matches across #{scan_result.rules_loaded rescue 0} rules")
        scan_result
      end

      def extract_strings(dump_path)
        extractor = StringExtractor.new(dump_path, config: @config, logger: @logger)
        extraction = extractor.extract
        stats = extraction[:statistics] || {}
        suspicious = extraction[:suspicious] || []
        logger.info("Strings: #{stats[:total_extracted] || 0} extracted, #{suspicious.size} suspicious")
        extraction
      end

      def reconstruct_objectspace
        parsed = @results[:dump_parsing]
        vm_data = @results[:vm_structure_analysis]
        return nil unless parsed

        reconstructor = ObjectspaceReconstructor.new(parsed, vm_data: vm_data, config: @config, logger: @logger)
        os_result = reconstructor.reconstruct
        logger.info("ObjectSpace: #{os_result[:objects_recovered] || 0} objects recovered")
        os_result
      end

      def reconstruct_code
        vm_data = @results[:vm_structure_analysis]
        os_data = @results[:objectspace_reconstruction]
        return nil unless vm_data || os_data

        reconstructor = CodeReconstructor.new(
          vm_data: vm_data, objectspace_data: os_data,
          config: @config, logger: @logger
        )
        code_result = reconstructor.reconstruct
        logger.info("Code reconstruction: #{code_result[:blocks]&.size || 0} code blocks recovered")
        code_result
      end

      def run_deobfuscation
        code_data = @results[:code_reconstruction]
        string_data = @results[:string_extraction]
        return nil unless code_data || string_data

        deobfuscator = Deobfuscator.new(
          code_data: code_data, string_data: string_data,
          config: @config, logger: @logger
        )
        deob_result = deobfuscator.deobfuscate
        logger.info("Deobfuscation: #{deob_result[:decoded_payloads]&.size || 0} payloads decoded")
        deob_result
      end

      def extract_network_artifacts(dump_path)
        extractor = NetworkArtifactExtractor.new(dump_path, config: @config, logger: @logger)
        net_result = extractor.extract
        summary = net_result.summary rescue {}
        logger.info("Network artifacts: #{summary[:total_urls] || 0} URLs, #{summary[:total_ips] || 0} IPs")
        net_result
      end

      def build_timeline
        builder = TimelineBuilder.new(config: @config, logger: @logger)

        # Feed all analysis results into the timeline
        builder.add_dump_metadata(@results[:dump_acquisition]) if @results[:dump_acquisition]
        builder.add_ioc_events(@results[:ioc_scanning]) if @results[:ioc_scanning]
        builder.add_network_events(@results[:network_artifact_extraction]) if @results[:network_artifact_extraction]
        builder.add_code_events(@results[:code_reconstruction]) if @results[:code_reconstruction]

        timeline = builder.build
        logger.info("Timeline: #{timeline[:total_events] || 0} events constructed")

        # Export timeline to file
        timeline_path = File.join(output_dir, "timeline_#{timestamp_tag}.json")
        File.write(timeline_path, JSON.pretty_generate(timeline))
        logger.info("Timeline exported to #{timeline_path}")

        timeline
      end

      def generate_reports
        generator = ReportGenerator.new(config: @config)

        generator.add_dump_info(@results[:dump_acquisition]) if @results[:dump_acquisition]
        generator.add_heap_analysis(@results[:heap_analysis]) if @results[:heap_analysis]
        generator.add_ioc_results(@results[:ioc_scanning]) if @results[:ioc_scanning]

        if @results[:string_extraction]
          stats = @results[:string_extraction][:statistics] || {}
          suspicious = @results[:string_extraction][:suspicious] || []
          generator.add_string_analysis(stats, suspicious)
        end

        generator.add_network_analysis(@results[:network_artifact_extraction]) if @results[:network_artifact_extraction]

        if @results[:code_reconstruction]
          blocks = @results[:code_reconstruction][:blocks] || []
          suspicious_code = @results[:code_reconstruction][:suspicious] || []
          generator.add_code_reconstruction(blocks, suspicious_code)
        end

        generator.add_timeline(@results[:timeline_construction]) if @results[:timeline_construction]

        # Add error summary if any phases failed
        unless @errors.empty?
          generator.add_custom_section(
            title: "Analysis Errors",
            content: { errors: @errors.map { |e| { phase: e[:phase].to_s, message: e[:error] } } },
            severity: :medium,
            order: 90
          )
        end

        generated = generator.generate_all(output_dir: output_dir)
        logger.info("Reports generated: #{generated.keys.join(', ')}")
        generated
      end

      # ------------------------------------------------------------------
      # Helpers
      # ------------------------------------------------------------------
      def print_summary(duration)
        logger.info("=" * 70)
        logger.info("Analysis Complete")
        logger.info("Duration: #{duration.round(2)}s")
        logger.info("Phases completed: #{@results.size}/#{ANALYSIS_PHASES.size}")
        logger.info("Errors: #{@errors.size}")

        if @errors.any?
          logger.warn("Failed phases:")
          @errors.each { |e| logger.warn("  - #{e[:phase]}: #{e[:error]}") }
        end

        logger.info("Output directory: #{output_dir}")
        logger.info("=" * 70)
      end

      def output_dir
        @output_dir ||= begin
          dir = options[:output] || File.join(DEFAULT_OUTPUT_DIR, "analysis_#{timestamp_tag}")
          File.expand_path(dir)
        end
      end

      def timestamp_tag
        @timestamp_tag ||= Time.now.utc.strftime("%Y%m%d_%H%M%S")
      end

      def load_config(path)
        config_path = path || DEFAULT_CONFIG_PATH
        if File.exist?(config_path)
          YAML.safe_load(File.read(config_path), permitted_classes: [Symbol])
        else
          {}
        end
      end

      def build_logger
        log_dir = File.expand_path("../logs", __dir__)
        FileUtils.mkdir_p(log_dir)
        log_path = File.join(log_dir, "analysis_#{timestamp_tag}.log")

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

# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------
if __FILE__ == $PROGRAM_NAME
  options = {}

  OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options]"
    opts.separator ""
    opts.separator "RubyGuardian Memory Forensics - Full Analysis Pipeline"
    opts.separator ""

    opts.on("-d", "--dump PATH", "Path to memory dump file") { |v| options[:dump] = v }
    opts.on("-p", "--pid PID", Integer, "Capture and analyze live process") { |v| options[:pid] = v }
    opts.on("-s", "--sample", "Analyze most recent sample dump") { options[:sample] = true }
    opts.on("-o", "--output DIR", "Output directory for reports") { |v| options[:output] = v }
    opts.on("-c", "--config PATH", "Path to config file") { |v| options[:config] = v }
    opts.on("-v", "--verbose", "Enable verbose logging") { options[:verbose] = true }
    opts.on("-h", "--help", "Show this help message") { puts opts; exit }
  end.parse!

  # Default to --sample if no arguments given
  options[:sample] = true if options.empty?

  analysis = RubyGuardian::MemoryForensics::FullAnalysis.new(options)
  success = analysis.run
  exit(success ? 0 : 1)
end
