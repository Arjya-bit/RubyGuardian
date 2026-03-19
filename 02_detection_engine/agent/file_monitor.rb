# frozen_string_literal: true

module RubyGuardian
  module Detection
    # Monitors filesystem changes using inotify for detecting malicious file operations
    # Watches sensitive paths, temp directories, and Ruby-specific locations
    class FileMonitor
      SENSITIVE_PATHS = %w[
        /etc/passwd /etc/shadow /etc/sudoers /etc/crontab
        /etc/ssh/sshd_config /etc/ld.so.preload
      ].freeze
      WATCH_DIRS = %w[/tmp /var/tmp /dev/shm].freeze
      RUBY_PATHS = %w[.gem .bundle .rbenv .rvm].freeze
      SUSPICIOUS_EXTENSIONS = %w[.so .dylib .dll .bin .elf .sh].freeze

      attr_reader :config, :logger, :event_collector

      def initialize(config:, logger:, event_collector:)
        @config = config
        @logger = logger
        @event_collector = event_collector
        @watches = {}
        @running = false
        @event_queue = Queue.new
        @file_hashes = {}
      end

      def start
        @running = true
        setup_watches
        @watch_thread = Thread.new { watch_loop }
        @process_thread = Thread.new { process_events }
        logger.info('FileMonitor started')
      end

      def stop
        @running = false
        @watch_thread&.join(5)
        @process_thread&.join(5)
        cleanup_watches
        logger.info('FileMonitor stopped')
      end

      private

      def setup_watches
        watch_directories = WATCH_DIRS.select { |d| File.directory?(d) }
        watch_directories += find_ruby_directories
        watch_directories.each do |dir|
          add_watch(dir)
        end
        logger.info("Watching #{@watches.size} directories")
      end

      def find_ruby_directories
        dirs = []
        Dir.glob('/home/*').each do |home|
          RUBY_PATHS.each do |rpath|
            full = File.join(home, rpath)
            dirs << full if File.directory?(full)
          end
        end
        dirs
      end

      def add_watch(path)
        return if @watches.key?(path)
        @watches[path] = { path: path, added_at: Time.now }
        baseline_directory(path)
      rescue StandardError => e
        logger.warn("Cannot watch #{path}: #{e.message}")
      end

      def baseline_directory(path)
        Dir.glob(File.join(path, '**', '*')).each do |file|
          next unless File.file?(file)
          @file_hashes[file] = compute_hash(file)
        rescue StandardError
          next
        end
      end

      def watch_loop
        while @running
          @watches.each_key do |dir|
            scan_directory(dir)
          end
          check_sensitive_files
          sleep(config.fetch(:file_poll_interval, 5))
        end
      end

      def scan_directory(dir)
        return unless File.directory?(dir)

        Dir.glob(File.join(dir, '*')).each do |file|
          next unless File.file?(file)
          current_hash = compute_hash(file)
          previous_hash = @file_hashes[file]

          if previous_hash.nil?
            handle_new_file(file)
          elsif previous_hash != current_hash
            handle_modified_file(file, previous_hash, current_hash)
          end
          @file_hashes[file] = current_hash
        rescue StandardError => e
          logger.debug("Scan error for #{file}: #{e.message}")
        end
      end

      def handle_new_file(file)
        severity = determine_severity(file)
        event_collector.emit(
          type: :file_created,
          severity: severity,
          source: 'file_monitor',
          details: {
            path: file,
            size: File.size(file),
            owner: File.stat(file).uid,
            permissions: File.stat(file).mode.to_s(8),
            executable: File.executable?(file),
            message: "New file detected: #{file}"
          }
        )
      end

      def handle_modified_file(file, old_hash, new_hash)
        event_collector.emit(
          type: :file_modified,
          severity: :medium,
          source: 'file_monitor',
          details: {
            path: file,
            old_hash: old_hash,
            new_hash: new_hash,
            message: "File modified: #{file}"
          }
        )
      end

      def check_sensitive_files
        SENSITIVE_PATHS.each do |path|
          next unless File.exist?(path)
          current_hash = compute_hash(path)
          previous = @file_hashes[path]

          if previous && previous != current_hash
            event_collector.emit(
              type: :sensitive_file_modified,
              severity: :critical,
              source: 'file_monitor',
              details: {
                path: path,
                message: "Sensitive file modified: #{path}"
              }
            )
          end
          @file_hashes[path] = current_hash
        rescue StandardError
          next
        end
      end

      def determine_severity(file)
        ext = File.extname(file)
        return :high if SUSPICIOUS_EXTENSIONS.include?(ext)
        return :high if File.executable?(file)
        return :medium if file.start_with?('/dev/shm')
        :low
      end

      def compute_hash(file)
        Digest::SHA256.file(file).hexdigest
      rescue StandardError
        nil
      end

      def process_events
        while @running
          event = @event_queue.pop(true) rescue nil
          process_event(event) if event
          sleep(0.1)
        end
      end

      def process_event(event)
        event_collector.emit(event)
      end

      def cleanup_watches
        @watches.clear
        @file_hashes.clear
      end
    end
  end
end
