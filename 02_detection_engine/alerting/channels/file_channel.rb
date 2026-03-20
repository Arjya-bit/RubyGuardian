# frozen_string_literal: true

require 'fileutils'
require 'time'
require 'zlib'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Channels
        # Writes formatted alerts to rotating log files with configurable
        # rotation by size, time, or both. Supports gzip compression of
        # rotated files and automatic cleanup of old archives.
        class FileChannel
          DEFAULT_MAX_SIZE       = 50 * 1024 * 1024  # 50 MB
          DEFAULT_MAX_FILES      = 10
          DEFAULT_ROTATION       = :size              # :size, :daily, :hourly, :both
          DEFAULT_PERMISSIONS    = 0o644
          DEFAULT_DIR_PERMISSIONS = 0o755

          attr_reader :config, :stats

          def initialize(config = {})
            @config = {
              path:            config.fetch(:path, '/var/log/rubyguardian/alerts.log'),
              rotation:        config.fetch(:rotation, DEFAULT_ROTATION).to_sym,
              max_size:        config.fetch(:max_size, DEFAULT_MAX_SIZE),
              max_files:       config.fetch(:max_files, DEFAULT_MAX_FILES),
              compress:        config.fetch(:compress, true),
              permissions:     config.fetch(:permissions, DEFAULT_PERMISSIONS),
              dir_permissions: config.fetch(:dir_permissions, DEFAULT_DIR_PERMISSIONS),
              buffer_size:     config.fetch(:buffer_size, 4096),
              sync_write:      config.fetch(:sync_write, true)
            }
            @mutex = Mutex.new
            @stats = { written: 0, rotations: 0, errors: 0, bytes_written: 0 }
            @current_file = nil
            @current_date = nil
            @current_hour = nil

            ensure_directory
          end

          # Write a formatted alert string to the log file.
          #
          # @param formatted_alert [String] pre-formatted alert string
          def send_alert(formatted_alert)
            @mutex.synchronize do
              rotate_if_needed
              write_line(formatted_alert)
            end
          rescue IOError, SystemCallError => e
            @stats[:errors] += 1
            reopen_file
            raise WriteError, "Failed to write alert: #{e.message}"
          end

          # Write a batch of alerts to the log file.
          #
          # @param alerts [Array<String>] pre-formatted alert strings
          def send_batch(alerts)
            @mutex.synchronize do
              alerts.each do |alert|
                rotate_if_needed
                write_line(alert)
              end
            end
          rescue IOError, SystemCallError => e
            @stats[:errors] += 1
            reopen_file
            raise WriteError, "Failed to write alert batch: #{e.message}"
          end

          # Flush the file buffer and sync to disk.
          def flush
            @mutex.synchronize do
              @current_file&.flush
              @current_file&.fsync if @config[:sync_write]
            end
          end

          # Close the current log file.
          def close
            @mutex.synchronize do
              @current_file&.close
              @current_file = nil
            end
          end

          # Return the current log file size in bytes.
          #
          # @return [Integer]
          def current_file_size
            File.size(@config[:path])
          rescue Errno::ENOENT
            0
          end

          private

          def ensure_directory
            dir = File.dirname(@config[:path])
            FileUtils.mkdir_p(dir, mode: @config[:dir_permissions])
          end

          def open_file
            @current_file&.close
            @current_file = File.open(@config[:path], 'a')
            @current_file.sync = @config[:sync_write]
            @current_file.chmod(@config[:permissions]) rescue nil
            @current_date = Date.today
            @current_hour = Time.now.hour
          end

          def reopen_file
            @mutex.synchronize do
              @current_file&.close rescue nil
              @current_file = nil
            end
          end

          def write_line(line)
            open_file if @current_file.nil?
            entry = line.end_with?("\n") ? line : "#{line}\n"
            @current_file.write(entry)
            @stats[:written] += 1
            @stats[:bytes_written] += entry.bytesize
          end

          def rotate_if_needed
            case @config[:rotation]
            when :size
              rotate! if size_exceeded?
            when :daily
              rotate! if date_changed?
            when :hourly
              rotate! if hour_changed?
            when :both
              rotate! if size_exceeded? || date_changed?
            end
          end

          def size_exceeded?
            current_file_size >= @config[:max_size]
          end

          def date_changed?
            @current_date && Date.today != @current_date
          end

          def hour_changed?
            @current_date && (Date.today != @current_date || Time.now.hour != @current_hour)
          end

          def rotate!
            return unless File.exist?(@config[:path])

            @current_file&.close
            @current_file = nil

            rotated_path = generate_rotated_name
            File.rename(@config[:path], rotated_path)

            compress_file(rotated_path) if @config[:compress]
            cleanup_old_files

            @stats[:rotations] += 1
            open_file
          end

          def generate_rotated_name
            timestamp = Time.now.utc.strftime('%Y%m%d-%H%M%S')
            base = @config[:path]
            "#{base}.#{timestamp}"
          end

          def compress_file(path)
            compressed_path = "#{path}.gz"
            Zlib::GzipWriter.open(compressed_path) do |gz|
              File.open(path, 'rb') do |f|
                while (chunk = f.read(16_384))
                  gz.write(chunk)
                end
              end
            end
            File.delete(path)
            compressed_path
          rescue StandardError => e
            @stats[:errors] += 1
            nil
          end

          def cleanup_old_files
            pattern = "#{@config[:path]}.*"
            files = Dir.glob(pattern).sort_by { |f| File.mtime(f) }

            while files.size > @config[:max_files]
              oldest = files.shift
              File.delete(oldest)
            end
          rescue StandardError => e
            @stats[:errors] += 1
          end
        end

        class WriteError < StandardError; end
      end
    end
  end
end
