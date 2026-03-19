# frozen_string_literal: true

# RubyGuardian Phase 5 -- Honeypot Sandbox: Executor
#
# Executes captured malware samples in an isolated sandbox environment.
# Uses containers and resource limits to safely analyze malicious code
# behavior.

require 'json'
require 'open3'
require 'timeout'
require 'fileutils'

module RubyGuardian
  module Honeypot
    class SandboxExecutor
      DEFAULT_TIMEOUT = 30 # seconds
      DEFAULT_MEMORY_LIMIT = '256m'
      DEFAULT_CPU_LIMIT = '0.5'

      attr_reader :config, :logger

      def initialize(config: {}, logger: nil)
        @config = config
        @logger = logger
        @timeout = config['timeout'] || DEFAULT_TIMEOUT
        @memory_limit = config['memory_limit'] || DEFAULT_MEMORY_LIMIT
        @cpu_limit = config['cpu_limit'] || DEFAULT_CPU_LIMIT
      end

      # Execute a sample in the sandbox and capture behavior
      def execute(sample_path, metadata: {})
        @logger&.info("[Sandbox] Executing sample: #{File.basename(sample_path)}")

        execution_id = SecureRandom.uuid
        output_dir = File.join('/tmp/ruby-guardian-sandbox', execution_id)
        FileUtils.mkdir_p(output_dir)

        start_time = Time.now

        begin
          result = run_in_container(sample_path, output_dir)
          duration = Time.now - start_time

          behavior = {
            execution_id: execution_id,
            sample_path: sample_path,
            started_at: start_time.utc.iso8601,
            duration_seconds: duration.round(3),
            exit_code: result[:exit_code],
            stdout: result[:stdout]&.slice(0, 10_000),
            stderr: result[:stderr]&.slice(0, 10_000),
            timed_out: result[:timed_out],
            syscalls: parse_strace(output_dir),
            network_activity: parse_network(output_dir),
            file_activity: parse_file_ops(output_dir),
            metadata: metadata
          }

          write_report(output_dir, behavior)
          @logger&.info("[Sandbox] Execution complete: #{execution_id} (#{duration.round(2)}s)")
          behavior
        ensure
          # Cleanup happens via container removal
        end
      end

      private

      def run_in_container(sample_path, output_dir)
        cmd = build_docker_command(sample_path, output_dir)

        stdout = stderr = ''
        timed_out = false
        exit_code = nil

        begin
          Timeout.timeout(@timeout + 5) do
            stdout, stderr, status = Open3.capture3(*cmd)
            exit_code = status.exitstatus
          end
        rescue Timeout::Error
          timed_out = true
          exit_code = -1
        end

        { stdout: stdout, stderr: stderr, exit_code: exit_code, timed_out: timed_out }
      end

      def build_docker_command(sample_path, output_dir)
        [
          'docker', 'run', '--rm',
          '--memory', @memory_limit,
          '--cpus', @cpu_limit,
          '--network', 'none',
          '--read-only',
          '--tmpfs', '/tmp:size=64m',
          '-v', "#{sample_path}:/sample.rb:ro",
          '-v', "#{output_dir}:/output",
          'ruby-guardian-sandbox:latest',
          'ruby', '/sample.rb'
        ]
      end

      def parse_strace(output_dir)
        strace_file = File.join(output_dir, 'strace.log')
        return [] unless File.exist?(strace_file)

        File.readlines(strace_file).map(&:strip).first(1000)
      end

      def parse_network(output_dir)
        net_file = File.join(output_dir, 'network.log')
        return [] unless File.exist?(net_file)

        JSON.parse(File.read(net_file)) rescue []
      end

      def parse_file_ops(output_dir)
        file_log = File.join(output_dir, 'file_ops.log')
        return [] unless File.exist?(file_log)

        File.readlines(file_log).map(&:strip).first(500)
      end

      def write_report(output_dir, behavior)
        report_path = File.join(output_dir, 'execution_report.json')
        File.write(report_path, JSON.pretty_generate(behavior))
      end
    end
  end
end
