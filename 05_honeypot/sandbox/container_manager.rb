# frozen_string_literal: true

require "json"
require "digest"
require "fileutils"
require "logger"
require "timeout"
require "securerandom"
require "open3"

module RubyGuardian
  module Honeypot
    module Sandbox
      # ContainerManager handles the lifecycle of Docker containers used for
      # isolated malware sample execution. It creates, configures, starts,
      # monitors, and destroys sandbox containers with strict resource limits.
      class ContainerManager
        SANDBOX_IMAGE = "rg-sandbox:latest"
        CONTAINER_PREFIX = "rg-sandbox-"
        MAX_CONCURRENT_CONTAINERS = 5
        DEFAULT_TIMEOUT = 120 # seconds
        SECCOMP_PROFILE = File.expand_path("../config/sandbox_seccomp.json", __dir__)

        attr_reader :active_containers

        def initialize(workspace_dir:, logger: nil)
          @workspace_dir = workspace_dir
          @logger = logger || default_logger
          @active_containers = {}
          @mutex = Mutex.new
        end

        # Create and start a sandbox container for a given sample.
        # Returns container metadata hash.
        def run_sample(sample_path:, sample_id: nil, timeout: DEFAULT_TIMEOUT, resource_limits: {})
          sample_id ||= generate_sample_id(sample_path)

          validate_capacity!
          validate_sample!(sample_path)

          container_name = "#{CONTAINER_PREFIX}#{sample_id}"
          output_dir = prepare_output_dir(sample_id)

          @logger.info("[ContainerManager] Creating sandbox for sample #{sample_id}")

          container_id = create_container(
            name: container_name,
            sample_path: sample_path,
            sample_id: sample_id,
            output_dir: output_dir,
            timeout: timeout,
            resource_limits: resource_limits
          )

          container_info = {
            container_id: container_id,
            container_name: container_name,
            sample_id: sample_id,
            sample_path: sample_path,
            output_dir: output_dir,
            timeout: timeout,
            started_at: Time.now.utc.iso8601,
            status: :running
          }

          @mutex.synchronize { @active_containers[sample_id] = container_info }

          # Start monitoring in a background thread
          monitor_thread = Thread.new { monitor_container(sample_id, container_id, timeout) }
          container_info[:monitor_thread] = monitor_thread

          @logger.info("[ContainerManager] Sandbox #{container_name} started (ID: #{container_id[0..11]})")
          container_info
        end

        # Stop and remove a sandbox container.
        def destroy_container(sample_id)
          info = @active_containers[sample_id]
          return unless info

          @logger.info("[ContainerManager] Destroying sandbox for sample #{sample_id}")

          docker_exec("stop", "--time", "5", info[:container_id])
          docker_exec("rm", "-f", info[:container_id])

          info[:status] = :destroyed
          info[:destroyed_at] = Time.now.utc.iso8601

          @mutex.synchronize { @active_containers.delete(sample_id) }
          @logger.info("[ContainerManager] Sandbox #{info[:container_name]} destroyed")
          info
        end

        # Destroy all active sandbox containers.
        def destroy_all
          @logger.info("[ContainerManager] Destroying all #{@active_containers.size} sandboxes")
          @active_containers.keys.each { |sid| destroy_container(sid) }
        end

        # Get logs from a sandbox container.
        def container_logs(sample_id, tail: 200)
          info = @active_containers[sample_id]
          return nil unless info

          stdout, _stderr, _status = docker_exec("logs", "--tail", tail.to_s, info[:container_id])
          stdout
        end

        # Collect execution results from the output directory.
        def collect_results(sample_id)
          info = @active_containers[sample_id]
          return nil unless info

          output_dir = info[:output_dir]
          results = { sample_id: sample_id, files: {} }

          Dir.glob(File.join(output_dir, "**", "*")).select { |f| File.file?(f) }.each do |file|
            relative = file.sub("#{output_dir}/", "")
            results[:files][relative] = {
              size: File.size(file),
              sha256: Digest::SHA256.file(file).hexdigest,
              modified: File.mtime(file).iso8601
            }
          end

          results[:container_info] = info.reject { |k, _| k == :monitor_thread }
          results
        end

        # List all active sandbox containers with status.
        def list_active
          @active_containers.map do |sid, info|
            {
              sample_id: sid,
              container_name: info[:container_name],
              status: info[:status],
              started_at: info[:started_at],
              uptime_seconds: (Time.now.utc - Time.parse(info[:started_at])).to_i
            }
          end
        end

        private

        def create_container(name:, sample_path:, sample_id:, output_dir:, timeout:, resource_limits:)
          limits = ResourceLimiter.new(resource_limits).to_docker_args

          args = [
            "create",
            "--name", name,
            "--network", "none",              # No network access
            "--read-only",                     # Read-only root filesystem
            "--tmpfs", "/tmp:rw,noexec,size=64m",
            "--tmpfs", "/var/tmp:rw,noexec,size=32m",
            "--cap-drop", "ALL",               # Drop all Linux capabilities
            "--security-opt", "no-new-privileges",
            "--pids-limit", "64",              # Limit process count
            "-v", "#{File.expand_path(sample_path)}:/sample:ro",
            "-v", "#{File.expand_path(output_dir)}:/output:rw",
            "-e", "SAMPLE_ID=#{sample_id}",
            "-e", "SANDBOX_TIMEOUT=#{timeout}",
            *limits,
            SANDBOX_IMAGE,
            "--timeout", timeout.to_s,
            "--trace-level", "full"
          ]

          # Add seccomp profile if available
          if File.exist?(SECCOMP_PROFILE)
            args.insert(args.index("--cap-drop"), "--security-opt")
            args.insert(args.index("--cap-drop"), "seccomp=#{SECCOMP_PROFILE}")
          end

          stdout, stderr, status = docker_exec(*args)
          unless status.success?
            raise "Failed to create container: #{stderr}"
          end

          container_id = stdout.strip

          # Start the container
          _out, err, stat = docker_exec("start", container_id)
          raise "Failed to start container: #{err}" unless stat.success?

          container_id
        end

        def monitor_container(sample_id, container_id, timeout)
          deadline = Time.now.utc + timeout + 10 # Grace period

          loop do
            break unless @active_containers.key?(sample_id)

            stdout, _stderr, _status = docker_exec("inspect", "--format", "{{.State.Status}}", container_id)
            state = stdout.strip

            case state
            when "exited", "dead"
              @logger.info("[ContainerManager] Sandbox #{sample_id} exited naturally")
              finalize_container(sample_id)
              break
            when "running"
              if Time.now.utc > deadline
                @logger.warn("[ContainerManager] Sandbox #{sample_id} exceeded timeout, killing")
                docker_exec("kill", container_id)
                finalize_container(sample_id)
                break
              end
            end

            sleep 2
          end
        rescue StandardError => e
          @logger.error("[ContainerManager] Monitor error for #{sample_id}: #{e.message}")
        end

        def finalize_container(sample_id)
          info = @active_containers[sample_id]
          return unless info

          info[:status] = :completed
          info[:completed_at] = Time.now.utc.iso8601

          # Copy any remaining logs
          logs = container_logs(sample_id)
          if logs && !logs.empty?
            log_path = File.join(info[:output_dir], "container_stdout.log")
            File.write(log_path, logs)
          end

          @logger.info("[ContainerManager] Sandbox #{sample_id} finalized")
        end

        def prepare_output_dir(sample_id)
          dir = File.join(@workspace_dir, "output", sample_id)
          FileUtils.mkdir_p(dir)
          FileUtils.mkdir_p(File.join(dir, "traces"))
          FileUtils.mkdir_p(File.join(dir, "artifacts"))
          dir
        end

        def validate_capacity!
          if @active_containers.size >= MAX_CONCURRENT_CONTAINERS
            raise "Maximum concurrent sandbox limit reached (#{MAX_CONCURRENT_CONTAINERS})"
          end
        end

        def validate_sample!(path)
          raise "Sample file not found: #{path}" unless File.exist?(path)
          raise "Sample too large (max 10MB)" if File.size(path) > 10 * 1024 * 1024
        end

        def generate_sample_id(path)
          hash = Digest::SHA256.file(path).hexdigest[0..15]
          "#{hash}-#{SecureRandom.hex(4)}"
        end

        def docker_exec(*args)
          Open3.capture3("docker", *args)
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::ContainerManager")
        end
      end
    end
  end
end
