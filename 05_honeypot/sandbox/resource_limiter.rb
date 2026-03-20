# frozen_string_literal: true

module RubyGuardian
  module Honeypot
    module Sandbox
      # ResourceLimiter applies cgroup-based resource constraints to sandbox
      # containers. It generates Docker run arguments for CPU, memory, network,
      # disk I/O, and process limits to prevent malware from escaping or
      # consuming excessive resources.
      class ResourceLimiter
        # Default resource limits for sandbox containers
        DEFAULTS = {
          cpu_shares: 256,            # Relative CPU weight (default is 1024)
          cpu_quota: 50_000,          # CPU quota in microseconds per cpu_period
          cpu_period: 100_000,        # CPU period in microseconds (100ms)
          cpus: "0.5",               # Number of CPUs (fractional)
          memory: "256m",            # Memory limit
          memory_swap: "256m",       # Memory + swap (same = no swap)
          memory_reservation: "128m", # Soft memory limit
          kernel_memory: "64m",      # Kernel memory limit
          pids_limit: 64,            # Maximum number of PIDs
          blkio_weight: 100,         # Block I/O weight (10-1000, default 500)
          device_read_bps: "10mb",   # Device read rate limit
          device_write_bps: "5mb",   # Device write rate limit
          device_read_iops: 1000,    # Device read IOPS limit
          device_write_iops: 500,    # Device write IOPS limit
          shm_size: "16m",          # Shared memory size
          ulimit_nofile: "256:512",  # File descriptor soft:hard limit
          ulimit_nproc: "64:128",    # Process soft:hard limit
          ulimit_fsize: "52428800",  # Max file size in bytes (50MB)
          network_mode: "none",      # Network mode (none = isolated)
          tmpfs_size: "64m",         # Tmpfs mount size
          storage_opt_size: "512m"   # Storage driver size limit
        }.freeze

        # Predefined profiles for different analysis scenarios
        PROFILES = {
          minimal: {
            cpus: "0.25",
            memory: "128m",
            memory_swap: "128m",
            pids_limit: 32,
            blkio_weight: 50,
            device_read_bps: "5mb",
            device_write_bps: "2mb"
          },
          standard: {},  # Uses DEFAULTS
          extended: {
            cpus: "1.0",
            memory: "512m",
            memory_swap: "512m",
            pids_limit: 128,
            blkio_weight: 200,
            device_read_bps: "20mb",
            device_write_bps: "10mb",
            shm_size: "32m"
          },
          intensive: {
            cpus: "2.0",
            memory: "1g",
            memory_swap: "1g",
            pids_limit: 256,
            blkio_weight: 500,
            device_read_bps: "50mb",
            device_write_bps: "25mb",
            shm_size: "64m"
          }
        }.freeze

        attr_reader :limits

        # Initialize with custom limits or a named profile.
        # @param overrides [Hash] custom limit values
        # @param profile [Symbol] named profile (:minimal, :standard, :extended, :intensive)
        def initialize(overrides = {}, profile: :standard)
          profile_limits = PROFILES.fetch(profile, {})
          @limits = DEFAULTS.merge(profile_limits).merge(symbolize_keys(overrides))
          validate_limits!
        end

        # Generate Docker CLI arguments for resource limits.
        # @return [Array<String>] docker run arguments
        def to_docker_args
          args = []

          # CPU limits
          args.push("--cpus", @limits[:cpus].to_s)
          args.push("--cpu-shares", @limits[:cpu_shares].to_s)
          args.push("--cpu-quota", @limits[:cpu_quota].to_s)
          args.push("--cpu-period", @limits[:cpu_period].to_s)

          # Memory limits
          args.push("--memory", @limits[:memory])
          args.push("--memory-swap", @limits[:memory_swap])
          args.push("--memory-reservation", @limits[:memory_reservation])

          # PID limit
          args.push("--pids-limit", @limits[:pids_limit].to_s)

          # Block I/O limits
          args.push("--blkio-weight", @limits[:blkio_weight].to_s)

          # Shared memory
          args.push("--shm-size", @limits[:shm_size])

          # Ulimits
          args.push("--ulimit", "nofile=#{@limits[:ulimit_nofile]}")
          args.push("--ulimit", "nproc=#{@limits[:ulimit_nproc]}")
          args.push("--ulimit", "fsize=#{@limits[:ulimit_fsize]}")

          # Network
          args.push("--network", @limits[:network_mode])

          args
        end

        # Generate a cgroup configuration hash for programmatic use.
        # @return [Hash] cgroup configuration
        def to_cgroup_config
          {
            cpu: {
              shares: @limits[:cpu_shares],
              quota: @limits[:cpu_quota],
              period: @limits[:cpu_period]
            },
            memory: {
              limit: parse_size(@limits[:memory]),
              swap_limit: parse_size(@limits[:memory_swap]),
              reservation: parse_size(@limits[:memory_reservation])
            },
            pids: {
              max: @limits[:pids_limit]
            },
            blkio: {
              weight: @limits[:blkio_weight],
              read_bps: parse_size(@limits[:device_read_bps]),
              write_bps: parse_size(@limits[:device_write_bps]),
              read_iops: @limits[:device_read_iops],
              write_iops: @limits[:device_write_iops]
            }
          }
        end

        # Human-readable summary of limits.
        # @return [String] formatted limit summary
        def to_s
          lines = [
            "Resource Limits:",
            "  CPU:     #{@limits[:cpus]} cores, #{@limits[:cpu_shares]} shares, quota #{@limits[:cpu_quota]}/#{@limits[:cpu_period]}us",
            "  Memory:  #{@limits[:memory]} (swap: #{@limits[:memory_swap]})",
            "  PIDs:    #{@limits[:pids_limit]} max",
            "  BlkIO:   weight #{@limits[:blkio_weight]}, read #{@limits[:device_read_bps]}/s, write #{@limits[:device_write_bps]}/s",
            "  Network: #{@limits[:network_mode]}",
            "  SHM:     #{@limits[:shm_size]}",
            "  Ulimits: nofile=#{@limits[:ulimit_nofile]}, nproc=#{@limits[:ulimit_nproc]}"
          ]
          lines.join("\n")
        end

        private

        def validate_limits!
          cpus = @limits[:cpus].to_f
          raise ArgumentError, "CPUs must be between 0.1 and 4.0" unless cpus.between?(0.1, 4.0)

          mem_bytes = parse_size(@limits[:memory])
          raise ArgumentError, "Memory must be at least 32MB" if mem_bytes < 32 * 1024 * 1024
          raise ArgumentError, "Memory must not exceed 4GB" if mem_bytes > 4 * 1024 * 1024 * 1024

          pids = @limits[:pids_limit].to_i
          raise ArgumentError, "PID limit must be between 8 and 1024" unless pids.between?(8, 1024)

          weight = @limits[:blkio_weight].to_i
          raise ArgumentError, "BlkIO weight must be between 10 and 1000" unless weight.between?(10, 1000)
        end

        # Parse a human-readable size string into bytes.
        # Supports k/m/g/t suffixes (case-insensitive).
        def parse_size(size_str)
          str = size_str.to_s.strip.downcase
          return str.to_i if str.match?(/^\d+$/)

          multipliers = { "k" => 1024, "kb" => 1024, "m" => 1024**2, "mb" => 1024**2,
                          "g" => 1024**3, "gb" => 1024**3, "t" => 1024**4, "tb" => 1024**4 }

          if (match = str.match(/^(\d+(?:\.\d+)?)\s*(k|kb|m|mb|g|gb|t|tb)$/))
            (match[1].to_f * multipliers[match[2]]).to_i
          else
            raise ArgumentError, "Invalid size format: #{size_str}"
          end
        end

        def symbolize_keys(hash)
          hash.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
        end
      end
    end
  end
end
