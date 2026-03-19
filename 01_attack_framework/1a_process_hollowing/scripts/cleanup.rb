# frozen_string_literal: true

# =============================================================================
# RubyGuardian Phase 1a -- Cleanup Script
#
# Cleans up all resources created during process hollowing demonstrations.
# This includes killing spawned processes, freeing memory, removing temp
# files, and restoring any modified system state.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
#
# Usage:
#   ruby scripts/cleanup.rb [--all] [--processes] [--files] [--verbose]
# =============================================================================

require 'optparse'
require 'fileutils'

module RubyGuardian
  module ProcessHollowing
    class Cleanup
      # Temp directories used by the framework
      TEMP_DIRS = [
        '/tmp/rubyguardian_hollowing',
        '/tmp/rg_payloads',
        '/tmp/rg_sysmon_events'
      ].freeze

      # Marker file that tracks spawned PIDs
      PID_TRACKING_FILE = '/tmp/rubyguardian_pids.txt'

      # File patterns to clean
      CLEANUP_PATTERNS = [
        '/tmp/rg_*.bin',
        '/tmp/rg_*.dat',
        '/tmp/rg_*.log',
        '/tmp/rubyguardian_*'
      ].freeze

      attr_reader :cleaned_items

      def initialize(verbose: false)
        @verbose = verbose
        @cleaned_items = { processes: [], files: [], dirs: [] }
      end

      # Run full cleanup.
      #
      # @return [Hash] Summary of cleaned items
      def cleanup_all
        log("Starting full cleanup...")

        cleanup_processes
        cleanup_temp_files
        cleanup_temp_dirs
        cleanup_ptrace_remnants
        cleanup_pid_tracking

        summary = {
          processes_killed: @cleaned_items[:processes].length,
          files_removed: @cleaned_items[:files].length,
          dirs_removed: @cleaned_items[:dirs].length,
          timestamp: Time.now.utc.iso8601
        }

        log("Cleanup complete: #{summary.inspect}")
        summary
      end

      # Kill any processes spawned by the hollowing demo.
      def cleanup_processes
        log("Cleaning up spawned processes...")

        # Read tracked PIDs from file
        if File.exist?(PID_TRACKING_FILE)
          pids = File.readlines(PID_TRACKING_FILE).map(&:strip).map(&:to_i).reject(&:zero?)
          pids.each { |pid| kill_process(pid) }
        end

        # Find zombie Ruby processes that might be hollowing targets
        find_orphaned_targets.each { |pid| kill_process(pid) }
      end

      # Remove temporary files created during demonstrations.
      def cleanup_temp_files
        log("Cleaning up temporary files...")

        CLEANUP_PATTERNS.each do |pattern|
          Dir.glob(pattern).each do |file|
            begin
              File.delete(file)
              @cleaned_items[:files] << file
              log("  Removed: #{file}")
            rescue Errno::EACCES, Errno::ENOENT => e
              log("  Cannot remove #{file}: #{e.message}")
            end
          end
        end
      end

      # Remove temporary directories.
      def cleanup_temp_dirs
        log("Cleaning up temporary directories...")

        TEMP_DIRS.each do |dir|
          if Dir.exist?(dir)
            begin
              FileUtils.rm_rf(dir)
              @cleaned_items[:dirs] << dir
              log("  Removed directory: #{dir}")
            rescue Errno::EACCES => e
              log("  Cannot remove #{dir}: #{e.message}")
            end
          end
        end
      end

      # Detach from any ptrace-attached processes.
      def cleanup_ptrace_remnants
        log("Checking for ptrace attachments...")

        # Find processes we're tracing by checking /proc/*/status
        Dir.glob('/proc/[0-9]*/status').each do |status_file|
          begin
            content = File.read(status_file)
            tracer_pid = content.match(/TracerPid:\s+(\d+)/)&.captures&.first&.to_i
            if tracer_pid == Process.pid
              target_pid = File.basename(File.dirname(status_file)).to_i
              log("  Found ptrace attachment to PID #{target_pid}")

              # Attempt to detach
              begin
                Process.kill('CONT', target_pid)
                log("  Sent SIGCONT to PID #{target_pid}")
              rescue Errno::ESRCH, Errno::EPERM
                # Process already gone or we can't signal it
              end
            end
          rescue Errno::ENOENT, Errno::EACCES
            next
          end
        end
      end

      # Remove the PID tracking file.
      def cleanup_pid_tracking
        if File.exist?(PID_TRACKING_FILE)
          File.delete(PID_TRACKING_FILE)
          log("  Removed PID tracking file")
        end
      end

      private

      def kill_process(pid)
        return if pid <= 1

        begin
          # First try graceful termination
          Process.kill('TERM', pid)
          log("  Sent SIGTERM to PID #{pid}")

          # Wait briefly for process to exit
          sleep(0.5)

          # Check if still alive
          Process.kill(0, pid)

          # Force kill if still alive
          Process.kill('KILL', pid)
          log("  Sent SIGKILL to PID #{pid}")
        rescue Errno::ESRCH
          log("  PID #{pid} already terminated")
        rescue Errno::EPERM
          log("  Cannot kill PID #{pid}: permission denied")
        end

        begin
          Process.wait(pid)
        rescue Errno::ECHILD, Errno::ESRCH
          # Not our child or already reaped
        end

        @cleaned_items[:processes] << pid
      end

      def find_orphaned_targets
        pids = []
        begin
          ps_output = `ps aux 2>/dev/null`
          ps_output.each_line do |line|
            # Look for sleep processes that we likely spawned
            if line.include?('sleep 86400') || line.include?('rubyguardian')
              pid = line.split[1].to_i
              pids << pid if pid > 1 && pid != Process.pid
            end
          end
        rescue StandardError
          # Ignore ps failures
        end
        pids
      end

      def log(message)
        return unless @verbose
        puts "[CLEANUP] #{message}"
      end
    end
  end
end

# CLI entry point
if __FILE__ == $PROGRAM_NAME
  options = { verbose: false, mode: :all }

  OptionParser.new do |opts|
    opts.banner = "Usage: #{$PROGRAM_NAME} [options]"

    opts.on('--all', 'Clean up everything (default)') { options[:mode] = :all }
    opts.on('--processes', 'Only clean up processes') { options[:mode] = :processes }
    opts.on('--files', 'Only clean up temp files') { options[:mode] = :files }
    opts.on('--verbose', 'Verbose output') { options[:verbose] = true }
    opts.on('-h', '--help', 'Show help') { puts opts; exit }
  end.parse!

  cleanup = RubyGuardian::ProcessHollowing::Cleanup.new(verbose: options[:verbose])

  case options[:mode]
  when :all
    result = cleanup.cleanup_all
  when :processes
    cleanup.cleanup_processes
    result = { processes_killed: cleanup.cleaned_items[:processes].length }
  when :files
    cleanup.cleanup_temp_files
    cleanup.cleanup_temp_dirs
    result = {
      files_removed: cleanup.cleaned_items[:files].length,
      dirs_removed: cleanup.cleaned_items[:dirs].length
    }
  end

  puts "Cleanup result: #{result}"
end
