# frozen_string_literal: true

# RubyGuardian Detection Engine - Memory Inspector
# ==================================================
# Inspects process memory regions for anomalies including RWX pages,
# shellcode signatures, anonymous executable mappings, and memory
# injection indicators.

require "concurrent"

module RubyGuardian
  module Detection
    class MemoryInspector
      PROC_PATH = "/proc"

      # Common shellcode byte patterns (NOP sleds, syscall gadgets, etc.)
      # These are x86_64 patterns commonly found in exploit payloads
      SHELLCODE_SIGNATURES = {
        nop_sled_16: /\x90{16,}/n,
        syscall_gadget: /\x0f\x05/n,                    # syscall
        int80_gadget: /\xcd\x80/n,                       # int 0x80
        execve_setup: /\x48\x31\xc0.{0,20}\x48\x89\xc7/n, # xor rax,rax ... mov rdi,rax
        bin_sh_string: /\/bin\/sh/n,
        bin_bash_string: /\/bin\/bash/n,
        reverse_shell_connect: /\x6a\x29.{0,10}\x6a\x02/n, # socket setup
        mprotect_gadget: /\x48\xc7\xc0\x0a\x00\x00\x00/n,  # mov rax, 10 (mprotect)
        elf_header: /\x7fELF/n,
        packed_pe: /MZ/n
      }.freeze

      # Permission flags in /proc/PID/maps
      PERM_READ    = "r"
      PERM_WRITE   = "w"
      PERM_EXEC    = "x"
      PERM_PRIVATE = "p"

      attr_reader :state

      def initialize(config:, event_collector:, logger:)
        @config = config
        @event_collector = event_collector
        @logger = logger
        @state = :initialized
        @interval_ms = config.fetch("interval_ms", 5000)
        @detect_rwx = config.fetch("detect_rwx_regions", true)
        @detect_shellcode = config.fetch("detect_shellcode_patterns", true)
        @detect_anon_exec = config.fetch("detect_anon_exec", true)
        @max_regions = config.fetch("max_regions_per_scan", 1000)
        @rwx_whitelist = compile_whitelist(config.fetch("rwx_whitelist", []))
        @baseline = Concurrent::Map.new  # pid -> baseline snapshot
        @scan_count = Concurrent::AtomicFixnum.new(0)
        @event_count = Concurrent::AtomicFixnum.new(0)
        @scheduler = nil
      end

      def start
        @logger.info("MemoryInspector starting (interval: #{@interval_ms}ms)")
        @state = :running

        @scheduler = Concurrent::TimerTask.new(
          execution_interval: @interval_ms / 1000.0,
          timeout_interval: (@interval_ms / 1000.0) * 3
        ) { scan_cycle }

        @scheduler.execute
        @logger.info("MemoryInspector started")
      end

      def stop
        @logger.info("MemoryInspector stopping")
        @scheduler&.shutdown
        @state = :stopped
        @logger.info("MemoryInspector stopped (scans: #{@scan_count.value}, events: #{@event_count.value})")
      end

      def reconfigure(new_config)
        @config = new_config
        @interval_ms = new_config.fetch("interval_ms", 5000)
        @detect_rwx = new_config.fetch("detect_rwx_regions", true)
        @detect_shellcode = new_config.fetch("detect_shellcode_patterns", true)
        @detect_anon_exec = new_config.fetch("detect_anon_exec", true)
        @max_regions = new_config.fetch("max_regions_per_scan", 1000)
        @rwx_whitelist = compile_whitelist(new_config.fetch("rwx_whitelist", []))
      end

      def status
        {
          state: @state,
          scan_count: @scan_count.value,
          event_count: @event_count.value,
          baselined_processes: @baseline.size
        }
      end

      # Scan a specific process's memory regions
      def scan_process(pid)
        maps = parse_proc_maps(pid)
        return nil unless maps

        findings = []
        regions_scanned = 0

        maps.each do |region|
          break if regions_scanned >= @max_regions

          regions_scanned += 1

          if @detect_rwx && rwx_region?(region) && !whitelisted?(region)
            findings << build_rwx_finding(pid, region)
          end

          if @detect_anon_exec && anonymous_executable?(region)
            findings << build_anon_exec_finding(pid, region)
          end

          if @detect_shellcode && executable_region?(region)
            shellcode_hits = scan_for_shellcode(pid, region)
            shellcode_hits.each do |hit|
              findings << build_shellcode_finding(pid, region, hit)
            end
          end
        end

        check_baseline_changes(pid, maps, findings)

        findings
      end

      private

      def compile_whitelist(patterns)
        patterns.map do |pattern|
          Regexp.new(pattern.gsub("*", ".*"))
        end
      end

      def scan_cycle
        @scan_count.increment
        target_pids = discover_target_pids

        target_pids.each do |pid|
          findings = scan_process(pid)
          next unless findings && !findings.empty?

          findings.each { |f| emit_finding(f) }
        end
      rescue StandardError => e
        @logger.error("MemoryInspector scan error: #{e.message}")
        @logger.debug(e.backtrace&.first(5)&.join("\n"))
      end

      def discover_target_pids
        pids = []
        Dir.entries(PROC_PATH).each do |entry|
          next unless entry.match?(/\A\d+\z/)

          pid = entry.to_i
          cmdline = read_proc_cmdline(pid)
          next unless cmdline && ruby_process?(cmdline)

          pids << pid
        end
        pids
      rescue Errno::ENOENT, Errno::EACCES
        []
      end

      def ruby_process?(cmdline)
        cmdline.match?(/ruby|bundle|rails|puma|sidekiq|unicorn/i)
      end

      def read_proc_cmdline(pid)
        File.read(File.join(PROC_PATH, pid.to_s, "cmdline")).tr("\0", " ").strip
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      # Parse /proc/PID/maps into structured region data
      def parse_proc_maps(pid)
        path = File.join(PROC_PATH, pid.to_s, "maps")
        return nil unless File.exist?(path)

        regions = []
        File.readlines(path).each do |line|
          region = parse_maps_line(line)
          regions << region if region
        end
        regions
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      def parse_maps_line(line)
        # Format: address perms offset dev inode pathname
        parts = line.strip.split(/\s+/, 6)
        return nil if parts.size < 5

        addr_range = parts[0].split("-")
        return nil if addr_range.size != 2

        {
          addr_start: addr_range[0].to_i(16),
          addr_end: addr_range[1].to_i(16),
          permissions: parts[1],
          offset: parts[2].to_i(16),
          device: parts[3],
          inode: parts[4].to_i,
          pathname: parts[5]&.strip || "",
          size: addr_range[1].to_i(16) - addr_range[0].to_i(16)
        }
      end

      def rwx_region?(region)
        perms = region[:permissions]
        perms.include?(PERM_READ) &&
          perms.include?(PERM_WRITE) &&
          perms.include?(PERM_EXEC)
      end

      def executable_region?(region)
        region[:permissions].include?(PERM_EXEC)
      end

      def anonymous_executable?(region)
        perms = region[:permissions]
        perms.include?(PERM_EXEC) &&
          (region[:pathname].empty? || region[:pathname] == "[anon]") &&
          region[:inode].zero?
      end

      def whitelisted?(region)
        pathname = region[:pathname]
        return false if pathname.empty?

        @rwx_whitelist.any? { |pattern| pathname.match?(pattern) }
      end

      # Attempt to read process memory and scan for shellcode patterns
      def scan_for_shellcode(pid, region)
        hits = []
        mem_path = File.join(PROC_PATH, pid.to_s, "mem")
        return hits unless File.exist?(mem_path)

        # Only scan reasonably sized regions to avoid performance issues
        region_size = region[:size]
        return hits if region_size > 10 * 1024 * 1024 # Skip regions > 10MB
        return hits if region_size < 64                 # Skip tiny regions

        begin
          File.open(mem_path, "rb") do |f|
            f.seek(region[:addr_start])
            # Read in chunks to manage memory
            chunk_size = [region_size, 65536].min
            data = f.read(chunk_size)
            return hits unless data

            SHELLCODE_SIGNATURES.each do |sig_name, pattern|
              if data.match?(pattern)
                # Find the offset within the region
                match = data.match(pattern)
                offset = match.begin(0) if match

                hits << {
                  signature: sig_name,
                  offset: offset,
                  region_start: region[:addr_start],
                  absolute_addr: region[:addr_start] + (offset || 0),
                  context_bytes: extract_context(data, offset, 32)
                }
              end
            end
          end
        rescue Errno::EIO, Errno::ENOENT, Errno::EACCES, Errno::ESRCH, Errno::EINVAL
          # Cannot read this memory region (normal for many regions)
        end

        hits
      end

      def extract_context(data, offset, context_size)
        return nil unless offset

        start_pos = [offset - context_size, 0].max
        end_pos = [offset + context_size, data.size].min
        data[start_pos...end_pos]&.bytes&.map { |b| format("%02x", b) }&.join(" ")
      end

      def check_baseline_changes(pid, current_maps, findings)
        prev_baseline = @baseline[pid]

        current_summary = summarize_maps(current_maps)

        if prev_baseline
          # Check for new RWX regions that weren't in baseline
          new_rwx = current_summary[:rwx_regions] - prev_baseline[:rwx_regions]
          if new_rwx > 0
            findings << {
              type: :new_rwx_regions,
              pid: pid,
              severity: :high,
              previous_rwx_count: prev_baseline[:rwx_regions],
              current_rwx_count: current_summary[:rwx_regions],
              new_regions: new_rwx,
              description: "#{new_rwx} new RWX memory regions appeared since baseline"
            }
          end

          # Check for significant growth in anonymous executable regions
          new_anon = current_summary[:anon_exec_regions] - prev_baseline[:anon_exec_regions]
          if new_anon > 2
            findings << {
              type: :anon_exec_growth,
              pid: pid,
              severity: :medium,
              previous_count: prev_baseline[:anon_exec_regions],
              current_count: current_summary[:anon_exec_regions],
              description: "Significant growth in anonymous executable memory regions"
            }
          end

          # Check for suspicious total memory growth
          growth = current_summary[:total_exec_size] - prev_baseline[:total_exec_size]
          if growth > 50 * 1024 * 1024 # > 50MB growth in executable memory
            findings << {
              type: :exec_memory_growth,
              pid: pid,
              severity: :medium,
              growth_bytes: growth,
              description: "Executable memory grew by #{growth / 1024 / 1024}MB"
            }
          end
        end

        @baseline[pid] = current_summary
      end

      def summarize_maps(maps)
        {
          total_regions: maps.size,
          rwx_regions: maps.count { |r| rwx_region?(r) },
          anon_exec_regions: maps.count { |r| anonymous_executable?(r) },
          total_exec_size: maps.select { |r| executable_region?(r) }.sum { |r| r[:size] },
          total_size: maps.sum { |r| r[:size] },
          timestamp: Time.now.to_f
        }
      end

      def build_rwx_finding(pid, region)
        {
          type: :rwx_memory_region,
          pid: pid,
          severity: :high,
          addr_start: format("0x%016x", region[:addr_start]),
          addr_end: format("0x%016x", region[:addr_end]),
          size: region[:size],
          pathname: region[:pathname],
          description: "Read-Write-Execute memory region detected" \
                       "#{region[:pathname].empty? ? ' (anonymous)' : " in #{region[:pathname]}"}"
        }
      end

      def build_anon_exec_finding(pid, region)
        {
          type: :anonymous_executable_region,
          pid: pid,
          severity: :medium,
          addr_start: format("0x%016x", region[:addr_start]),
          addr_end: format("0x%016x", region[:addr_end]),
          size: region[:size],
          description: "Anonymous executable memory region detected (possible code injection)"
        }
      end

      def build_shellcode_finding(pid, region, hit)
        {
          type: :shellcode_pattern,
          pid: pid,
          severity: :critical,
          signature: hit[:signature],
          address: format("0x%016x", hit[:absolute_addr]),
          region_start: format("0x%016x", region[:addr_start]),
          region_pathname: region[:pathname],
          context_hex: hit[:context_bytes],
          description: "Shellcode pattern '#{hit[:signature]}' detected at #{format('0x%016x', hit[:absolute_addr])}"
        }
      end

      def emit_finding(finding)
        @event_count.increment
        event = {
          source: :memory_inspector,
          type: finding[:type],
          timestamp: Time.now.to_f,
          data: finding
        }
        @event_collector.push(event)

        severity = finding[:severity]
        if %i[critical high].include?(severity)
          @logger.warn("MemoryInspector [#{severity}]: #{finding[:description]}")
        else
          @logger.info("MemoryInspector [#{severity}]: #{finding[:description]}")
        end
      end
    end
  end
end
