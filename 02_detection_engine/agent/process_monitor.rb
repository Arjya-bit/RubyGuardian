# frozen_string_literal: true

# RubyGuardian Detection Engine - Process Monitor
# ================================================
# Monitors Ruby process behavior including fork, exec, and spawn operations.
# Inspects /proc filesystem for process state, memory maps, and file descriptors.

require "concurrent"
require "set"

module RubyGuardian
  module Detection
    class ProcessMonitor
      PROC_PATH = "/proc"
      STAT_FIELDS = %i[pid comm state ppid pgrp session tty_nr tpgid flags
                       minflt cminflt majflt cmajflt utime stime cutime cstime
                       priority nice num_threads].freeze

      attr_reader :tracked_processes, :state

      def initialize(config:, event_collector:, logger:)
        @config = config
        @event_collector = event_collector
        @logger = logger
        @state = :initialized
        @tracked_processes = Concurrent::Map.new
        @process_snapshots = Concurrent::Map.new
        @target_patterns = compile_patterns(config.fetch("target_patterns", []))
        @interval_ms = config.fetch("interval_ms", 1000)
        @max_tracked = config.fetch("max_tracked_processes", 500)
        @watch_fork = config.fetch("watch_fork", true)
        @watch_exec = config.fetch("watch_exec", true)
        @watch_spawn = config.fetch("watch_spawn", true)
        @watch_ptrace = config.fetch("watch_ptrace", true)
        @scheduler = nil
        @scan_count = Concurrent::AtomicFixnum.new(0)
        @event_count = Concurrent::AtomicFixnum.new(0)
        @mutex = Mutex.new
      end

      def start
        @logger.info("ProcessMonitor starting (interval: #{@interval_ms}ms)")
        @state = :running

        # Initial discovery of existing Ruby processes
        discover_ruby_processes

        @scheduler = Concurrent::TimerTask.new(
          execution_interval: @interval_ms / 1000.0,
          timeout_interval: (@interval_ms / 1000.0) * 2
        ) { scan_cycle }

        @scheduler.execute
        @logger.info("ProcessMonitor started, tracking #{@tracked_processes.size} processes")
      end

      def stop
        @logger.info("ProcessMonitor stopping")
        @scheduler&.shutdown
        @state = :stopped
        @logger.info("ProcessMonitor stopped (scans: #{@scan_count.value}, events: #{@event_count.value})")
      end

      def reconfigure(new_config)
        @config = new_config
        @target_patterns = compile_patterns(new_config.fetch("target_patterns", []))
        @interval_ms = new_config.fetch("interval_ms", 1000)
        @max_tracked = new_config.fetch("max_tracked_processes", 500)
      end

      def status
        {
          state: @state,
          tracked_processes: @tracked_processes.size,
          scan_count: @scan_count.value,
          event_count: @event_count.value
        }
      end

      private

      def compile_patterns(patterns)
        patterns.map { |p| Regexp.new(p, Regexp::IGNORECASE) }
      end

      # Discover currently running Ruby processes by scanning /proc
      def discover_ruby_processes
        each_process do |pid|
          cmdline = read_proc_cmdline(pid)
          next unless cmdline && matches_target?(cmdline)

          track_process(pid, cmdline)
        end

        @logger.info("Discovered #{@tracked_processes.size} Ruby processes")
      end

      # Main scan cycle - called periodically
      def scan_cycle
        @scan_count.increment
        current_pids = Set.new

        each_process do |pid|
          cmdline = read_proc_cmdline(pid)
          next unless cmdline

          if matches_target?(cmdline)
            current_pids.add(pid)

            if @tracked_processes.key?(pid)
              check_process_changes(pid, cmdline)
            else
              track_new_process(pid, cmdline)
            end
          end
        end

        detect_exited_processes(current_pids)
        detect_fork_events
        detect_suspicious_fd_activity
      rescue StandardError => e
        @logger.error("ProcessMonitor scan error: #{e.message}")
        @logger.debug(e.backtrace&.first(5)&.join("\n"))
      end

      def each_process(&block)
        Dir.entries(PROC_PATH).each do |entry|
          next unless entry.match?(/\A\d+\z/)

          yield entry.to_i
        end
      rescue Errno::ENOENT, Errno::EACCES => e
        @logger.debug("Error reading /proc: #{e.message}")
      end

      def read_proc_cmdline(pid)
        path = File.join(PROC_PATH, pid.to_s, "cmdline")
        return nil unless File.exist?(path)

        content = File.read(path)
        content.tr("\0", " ").strip
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      def read_proc_stat(pid)
        path = File.join(PROC_PATH, pid.to_s, "stat")
        return nil unless File.exist?(path)

        content = File.read(path)
        # Parse stat line: pid (comm) state ppid ...
        if content =~ /\A(\d+)\s+\((.+?)\)\s+(.+)/
          fields = $3.split
          {
            pid: $1.to_i,
            comm: $2,
            state: fields[0],
            ppid: fields[1].to_i,
            pgrp: fields[2].to_i,
            session: fields[3].to_i,
            flags: fields[6].to_i,
            num_threads: fields[17].to_i,
            utime: fields[11].to_i,
            stime: fields[12].to_i
          }
        end
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      def read_proc_status(pid)
        path = File.join(PROC_PATH, pid.to_s, "status")
        return nil unless File.exist?(path)

        result = {}
        File.readlines(path).each do |line|
          key, value = line.split(":", 2)
          result[key.strip] = value&.strip
        end
        result
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      def read_proc_children(pid)
        path = File.join(PROC_PATH, pid.to_s, "task", pid.to_s, "children")
        return [] unless File.exist?(path)

        File.read(path).split.map(&:to_i)
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        []
      end

      def read_proc_exe(pid)
        path = File.join(PROC_PATH, pid.to_s, "exe")
        File.readlink(path)
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      def read_proc_fd_count(pid)
        path = File.join(PROC_PATH, pid.to_s, "fd")
        return 0 unless File.directory?(path)

        Dir.entries(path).count { |e| e != "." && e != ".." }
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        0
      end

      def read_proc_maps_summary(pid)
        path = File.join(PROC_PATH, pid.to_s, "maps")
        return nil unless File.exist?(path)

        regions = { total: 0, rwx: 0, anonymous_exec: 0 }
        File.readlines(path).each do |line|
          regions[:total] += 1
          perms = line.split[1] || ""
          regions[:rwx] += 1 if perms.include?("rwx")
          if perms.include?("x") && line.strip.end_with?("0")
            regions[:anonymous_exec] += 1
          end
        end
        regions
      rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
        nil
      end

      def matches_target?(cmdline)
        @target_patterns.any? { |pattern| cmdline.match?(pattern) }
      end

      def track_process(pid, cmdline)
        return if @tracked_processes.size >= @max_tracked

        stat = read_proc_stat(pid)
        snapshot = {
          pid: pid,
          cmdline: cmdline,
          exe: read_proc_exe(pid),
          ppid: stat&.dig(:ppid),
          state: stat&.dig(:state),
          num_threads: stat&.dig(:num_threads),
          fd_count: read_proc_fd_count(pid),
          children: read_proc_children(pid),
          maps_summary: read_proc_maps_summary(pid),
          first_seen: Time.now,
          last_seen: Time.now
        }

        @tracked_processes[pid] = snapshot
        @process_snapshots[pid] = snapshot.dup
      end

      def track_new_process(pid, cmdline)
        track_process(pid, cmdline)
        emit_event(:process_discovered, {
          pid: pid,
          cmdline: cmdline,
          exe: @tracked_processes[pid]&.dig(:exe),
          ppid: @tracked_processes[pid]&.dig(:ppid)
        })
      end

      def check_process_changes(pid, cmdline)
        prev = @process_snapshots[pid]
        return unless prev

        current_stat = read_proc_stat(pid)
        return unless current_stat

        current_exe = read_proc_exe(pid)
        current_children = read_proc_children(pid)
        current_fd_count = read_proc_fd_count(pid)

        # Detect exec - executable path changed
        if @watch_exec && current_exe && prev[:exe] && current_exe != prev[:exe]
          emit_event(:process_exec_detected, {
            pid: pid,
            original_exe: prev[:exe],
            new_exe: current_exe,
            cmdline: cmdline,
            severity: :high
          })
        end

        # Detect fork - new children appeared
        if @watch_fork
          prev_children = Set.new(prev[:children] || [])
          new_children = current_children.reject { |c| prev_children.include?(c) }
          new_children.each do |child_pid|
            child_cmdline = read_proc_cmdline(child_pid)
            emit_event(:process_fork_detected, {
              parent_pid: pid,
              child_pid: child_pid,
              parent_cmdline: cmdline,
              child_cmdline: child_cmdline,
              severity: :medium
            })
          end
        end

        # Detect suspicious FD growth (potential exfiltration setup)
        if current_fd_count > (prev[:fd_count] || 0) + 20
          emit_event(:process_fd_spike, {
            pid: pid,
            cmdline: cmdline,
            previous_fd_count: prev[:fd_count],
            current_fd_count: current_fd_count,
            severity: :low
          })
        end

        # Detect ptrace attachment
        if @watch_ptrace
          status = read_proc_status(pid)
          tracer_pid = status&.dig("TracerPid")&.to_i
          if tracer_pid && tracer_pid > 0
            emit_event(:process_ptrace_detected, {
              pid: pid,
              tracer_pid: tracer_pid,
              cmdline: cmdline,
              severity: :high
            })
          end
        end

        # Update snapshot
        @process_snapshots[pid] = {
          pid: pid,
          cmdline: cmdline,
          exe: current_exe,
          ppid: current_stat[:ppid],
          state: current_stat[:state],
          num_threads: current_stat[:num_threads],
          fd_count: current_fd_count,
          children: current_children,
          maps_summary: read_proc_maps_summary(pid),
          first_seen: prev[:first_seen],
          last_seen: Time.now
        }
      end

      def detect_exited_processes(current_pids)
        @tracked_processes.each_pair do |pid, info|
          unless current_pids.include?(pid)
            emit_event(:process_exited, {
              pid: pid,
              cmdline: info[:cmdline],
              lifetime_seconds: (Time.now - info[:first_seen]).to_i
            })
            @tracked_processes.delete(pid)
            @process_snapshots.delete(pid)
          end
        end
      end

      def detect_fork_events
        return unless @watch_spawn

        @tracked_processes.each_pair do |pid, info|
          children = read_proc_children(pid)
          children.each do |child_pid|
            child_cmdline = read_proc_cmdline(child_pid)
            next unless child_cmdline

            # Detect spawn - child running a different binary
            child_exe = read_proc_exe(child_pid)
            parent_exe = info[:exe]
            if child_exe && parent_exe && !child_exe.include?("ruby")
              emit_event(:process_spawn_non_ruby, {
                parent_pid: pid,
                child_pid: child_pid,
                parent_exe: parent_exe,
                child_exe: child_exe,
                child_cmdline: child_cmdline,
                severity: :high
              })
            end
          end
        end
      end

      def detect_suspicious_fd_activity
        @tracked_processes.each_pair do |pid, _info|
          fd_path = File.join(PROC_PATH, pid.to_s, "fd")
          next unless File.directory?(fd_path)

          Dir.entries(fd_path).each do |fd|
            next if fd == "." || fd == ".."

            begin
              link = File.readlink(File.join(fd_path, fd))

              # Detect memfd file descriptors (fileless execution indicator)
              if link.include?("memfd:")
                emit_event(:process_memfd_detected, {
                  pid: pid,
                  fd: fd,
                  target: link,
                  severity: :high
                })
              end

              # Detect /dev/shm usage
              if link.start_with?("/dev/shm/")
                emit_event(:process_shm_fd_detected, {
                  pid: pid,
                  fd: fd,
                  target: link,
                  severity: :medium
                })
              end
            rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
              next
            end
          end
        rescue Errno::ENOENT, Errno::EACCES, Errno::ESRCH
          next
        end
      end

      def emit_event(type, data)
        @event_count.increment
        event = {
          source: :process_monitor,
          type: type,
          timestamp: Time.now.to_f,
          data: data
        }
        @event_collector.push(event)
        @logger.debug("ProcessMonitor event: #{type} #{data.inspect}")
      end
    end
  end
end
