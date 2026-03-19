# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Process Hollowing Demo Script
#
# EDUCATIONAL PURPOSE ONLY -- Demonstrates the process hollowing technique
# in a controlled, safe manner using dry-run mode by default.
#
# Usage:
#   ruby scripts/run_hollow_demo.rb [--dry-run] [--verbose] [--live]
#
# MITRE ATT&CK: T1055.012 - Process Injection: Process Hollowing
# =============================================================================

$LOAD_PATH.unshift(File.expand_path('../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path('../../shared/lib', __dir__))

require 'optparse'
require 'logger'

# Load shared modules
require 'logger'
require 'platform_detector'
require 'sandbox_detector'

# Load process hollowing modules
require 'process_hollower'
require 'anti_analysis'

module RubyGuardian
  module ProcessHollowing
    class HollowDemo
      BANNER = <<~BANNER
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         RubyGuardian - Process Hollowing Demonstration
         EDUCATIONAL PURPOSE ONLY - Authorized Security Research
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      BANNER

      def initialize
        @options = parse_options
        @log_output = StringIO.new
      end

      def run
        puts BANNER
        print_disclaimer

        if @options[:describe]
          run_describe_mode
          return
        end

        puts "\n[*] Phase 0: Environment Analysis"
        run_anti_analysis

        puts "\n[*] Phase 1: Process Hollowing Demonstration"
        run_hollowing

        puts "\n[*] Phase 2: Detection Artifacts"
        show_detection_artifacts

        puts "\n[*] Demo complete. Review the output above for educational details."
      end

      private

      def parse_options
        options = {
          dry_run: true,
          verbose: false,
          live: false,
          describe: false,
          target: '/bin/sleep',
          log_level: :info
        }

        OptionParser.new do |opts|
          opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

          opts.on('--dry-run', 'Run in dry-run mode (default)') do
            options[:dry_run] = true
          end

          opts.on('--live', 'Run in live mode (requires sandbox)') do
            options[:live] = true
            options[:dry_run] = false
          end

          opts.on('--verbose', 'Enable verbose output') do
            options[:verbose] = true
            options[:log_level] = :debug
          end

          opts.on('--describe', 'Show technique description and exit') do
            options[:describe] = true
          end

          opts.on('--target BINARY', 'Target binary for hollowing') do |t|
            options[:target] = t
          end

          opts.on('-h', '--help', 'Show this help') do
            puts opts
            exit
          end
        end.parse!

        options
      end

      def print_disclaimer
        puts <<~DISCLAIMER

          *** EDUCATIONAL DISCLAIMER ***
          This demonstration shows how process hollowing works for security
          research and defense development. All operations are performed in
          #{@options[:dry_run] ? 'DRY-RUN mode (no actual process modification)' : 'LIVE mode (actual process modification in sandbox)'}.

        DISCLAIMER
      end

      def run_describe_mode
        hollower = ProcessHollower.new(dry_run: true)
        puts hollower.describe

        puts "\n--- Anti-Analysis Techniques ---"
        anti_analysis = AntiAnalysis.new
        puts anti_analysis.describe
      end

      def run_anti_analysis
        anti_analysis = AntiAnalysis.new

        puts "  [+] Running anti-analysis checks..."
        results = anti_analysis.run_all_checks

        puts "  [+] Debugger detected:   #{results[:debugger][:detected]}"
        puts "  [+] VM detected:         #{results[:virtual_machine][:detected]}"
        if results[:virtual_machine][:hypervisor]
          puts "      Hypervisor:          #{results[:virtual_machine][:hypervisor]}"
        end
        puts "  [+] Sandbox detected:    #{results[:sandbox][:detected]}"
        puts "  [+] Analysis tools:      #{results[:analysis_tools][:tools_found].length} found"
        puts "  [+] Timing anomalies:    #{results[:timing_anomalies][:anomalies].length}"
        puts "  [+] Risk score:          #{results[:risk_score]}/100"
        puts "  [+] Recommendation:      #{results[:recommendation]}"
      end

      def run_hollowing
        config = {
          target_binary: @options[:target],
          dry_run: @options[:dry_run],
          require_sandbox: !@options[:dry_run],
          log_level: @options[:log_level],
          log_output: @options[:verbose] ? $stdout : @log_output
        }

        hollower = ProcessHollower.new(config)

        puts "  [+] Mode:           #{@options[:dry_run] ? 'DRY RUN' : 'LIVE'}"
        puts "  [+] Target binary:  #{config[:target_binary]}"
        puts "  [+] Platform:       #{hollower.platform}"

        puts "\n  [*] Executing process hollowing sequence..."
        result = hollower.execute

        puts "\n  [+] Result: #{result[:outcome]}"
        puts "  [+] Status: #{result[:status]}"
        puts "  [+] Target PID: #{result[:target_pid]}" if result[:target_pid]
        puts "  [+] Operations performed: #{result[:operations]}"

        if @options[:verbose] && result[:operation_log]
          puts "\n  --- Operation Log ---"
          result[:operation_log].each do |entry|
            puts "  #{entry[:timestamp]} [#{entry[:phase]}] #{entry[:message]}"
          end
        end

        # Cleanup
        puts "\n  [*] Running cleanup..."
        cleanup_result = hollower.cleanup
        puts "  [+] Cleanup complete"

        result
      end

      def show_detection_artifacts
        puts <<~ARTIFACTS
            Process hollowing leaves these detectable artifacts:

            1. Memory Anomalies:
               - Process image path doesn't match loaded code
               - RWX memory regions in non-JIT processes
               - Hollow process has no legitimate executable sections

            2. System Call Traces:
               - ptrace ATTACH from non-debugger process
               - process_vm_writev to foreign address space
               - Unusual /proc/<pid>/mem access patterns

            3. Behavioral Indicators:
               - Process tree anomalies (unexpected parent-child)
               - Network activity from a normally-quiet process
               - File system access patterns inconsistent with process name

            4. Sysmon/auditd Events:
               - Process creation with modified memory
               - Cross-process memory access events
               - Thread context modification events
        ARTIFACTS
      end
    end
  end
end

# Run the demo
if __FILE__ == $PROGRAM_NAME
  demo = RubyGuardian::ProcessHollowing::HollowDemo.new
  demo.run
end
