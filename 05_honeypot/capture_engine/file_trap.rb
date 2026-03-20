# frozen_string_literal: true

module RubyGuardian
  module Honeypot
    module CaptureEngine
      # FileTrap intercepts and logs all file system operations performed by
      # analyzed scripts. It patches File, FileUtils, Dir, and IO to capture
      # reads, writes, deletes, permission changes, and directory traversals.
      class FileTrap
        SENSITIVE_PATHS = %w[
          /etc/passwd /etc/shadow /etc/hosts
          .ssh/id_rsa .ssh/id_ed25519 .ssh/authorized_keys
          .aws/credentials .gem/credentials
          .env .bashrc .zshrc .netrc
          .git/config
        ].freeze

        attr_reader :captures, :started_at

        def initialize(log_dir:, sample_id:, logger: nil)
          @log_dir = log_dir
          @sample_id = sample_id
          @logger = logger || default_logger
          @captures = []
          @started_at = nil
          @mutex = Mutex.new
          @original_methods = {}
          @sensitive_access_count = 0
        end

        # Activate file system traps.
        def activate!
          @started_at = Time.now.utc
          @logger.info("[FileTrap] Activating file system traps for sample #{@sample_id}")

          trap_file_read
          trap_file_write
          trap_file_delete
          trap_file_chmod
          trap_file_exist
          trap_dir_glob
          trap_dir_entries

          self
        end

        # Deactivate traps and restore originals.
        def deactivate!
          @logger.info("[FileTrap] Deactivating file system traps for sample #{@sample_id}")
          restore_original_methods
          flush_captures
          self
        end

        # Record a file system operation.
        def record(operation:, path:, details: {}, caller_location: nil)
          is_sensitive = sensitive_path?(path)
          @sensitive_access_count += 1 if is_sensitive

          entry = {
            timestamp: Time.now.utc.iso8601(6),
            sample_id: @sample_id,
            operation: operation.to_s,
            path: path.to_s,
            resolved_path: safe_realpath(path),
            is_sensitive: is_sensitive,
            details: details,
            caller_location: caller_location || extract_caller,
            elapsed_ms: elapsed_ms,
            pid: Process.pid
          }

          @mutex.synchronize { @captures << entry }

          level = is_sensitive ? :error : :warn
          @logger.send(level, "[FileTrap] #{operation} on #{path}#{is_sensitive ? ' [SENSITIVE]' : ''}")
          entry
        end

        # Flush captures to JSON on disk.
        def flush_captures
          return if @captures.empty?

          output_path = File.join(@log_dir, "file_captures_#{@sample_id}.json")
          @original_methods[:file_write]&.bind_call(File, output_path, JSON.pretty_generate(report_data))
          @logger.info("[FileTrap] Flushed #{@captures.size} file operation captures")
        end

        # Summary statistics.
        def summary
          {
            sample_id: @sample_id,
            total_operations: @captures.size,
            operations_breakdown: @captures.map { |c| c[:operation] }.tally,
            sensitive_accesses: @sensitive_access_count,
            unique_paths: @captures.map { |c| c[:path] }.uniq.size,
            paths_accessed: @captures.map { |c| c[:path] }.uniq.sort
          }
        end

        private

        def trap_file_read
          trap = self
          @original_methods[:file_read] = File.method(:read)

          File.define_singleton_method(:read) do |path, *args|
            trap.record(operation: :read, path: path, details: { args: args.map(&:to_s) },
                        caller_location: caller_locations(1, 1).first.to_s)
            # Return empty content for sensitive files, real content for others
            if trap.send(:sensitive_path?, path)
              trap.send(:fake_sensitive_content, path)
            else
              trap.instance_variable_get(:@original_methods)[:file_read].call(path, *args)
            end
          rescue Errno::ENOENT
            ""
          end
        end

        def trap_file_write
          trap = self
          @original_methods[:file_write] = File.method(:write)

          File.define_singleton_method(:write) do |path, content, *args|
            trap.record(operation: :write, path: path,
                        details: { size: content.to_s.bytesize, sha256: Digest::SHA256.hexdigest(content.to_s) },
                        caller_location: caller_locations(1, 1).first.to_s)
            # Redirect writes to capture directory
            capture_path = File.join(trap.instance_variable_get(:@log_dir), "written_files", Digest::SHA256.hexdigest(path))
            FileUtils.mkdir_p(File.dirname(capture_path))
            trap.instance_variable_get(:@original_methods)[:file_write].call(capture_path, content, *args)
          end
        end

        def trap_file_delete
          trap = self
          @original_methods[:file_delete] = File.method(:delete)

          File.define_singleton_method(:delete) do |*paths|
            paths.each do |path|
              trap.record(operation: :delete, path: path,
                          caller_location: caller_locations(1, 1).first.to_s)
            end
            paths.size # Return count without actually deleting
          end
        end

        def trap_file_chmod
          trap = self
          @original_methods[:file_chmod] = File.method(:chmod)

          File.define_singleton_method(:chmod) do |mode, *paths|
            paths.each do |path|
              trap.record(operation: :chmod, path: path,
                          details: { mode: format("0%o", mode) },
                          caller_location: caller_locations(1, 1).first.to_s)
            end
            0 # Return without changing permissions
          end
        end

        def trap_file_exist
          trap = self
          @original_methods[:file_exist] = File.method(:exist?)

          File.define_singleton_method(:exist?) do |path|
            trap.record(operation: :exist_check, path: path,
                        caller_location: caller_locations(1, 1).first.to_s)
            # Sensitive files "exist" to bait the malware
            return true if trap.send(:sensitive_path?, path)

            trap.instance_variable_get(:@original_methods)[:file_exist].call(path)
          end
        end

        def trap_dir_glob
          trap = self
          @original_methods[:dir_glob] = Dir.method(:glob)

          Dir.define_singleton_method(:glob) do |pattern, *args|
            trap.record(operation: :dir_glob, path: pattern.to_s,
                        caller_location: caller_locations(1, 1).first.to_s)
            trap.instance_variable_get(:@original_methods)[:dir_glob].call(pattern, *args)
          end
        end

        def trap_dir_entries
          trap = self
          @original_methods[:dir_entries] = Dir.method(:entries)

          Dir.define_singleton_method(:entries) do |path, *args|
            trap.record(operation: :dir_entries, path: path,
                        caller_location: caller_locations(1, 1).first.to_s)
            trap.instance_variable_get(:@original_methods)[:dir_entries].call(path, *args)
          rescue Errno::ENOENT
            []
          end
        end

        def restore_original_methods
          @original_methods.each do |name, method_obj|
            case name
            when :file_read    then File.define_singleton_method(:read, method_obj)
            when :file_write   then File.define_singleton_method(:write, method_obj)
            when :file_delete  then File.define_singleton_method(:delete, method_obj)
            when :file_chmod   then File.define_singleton_method(:chmod, method_obj)
            when :file_exist   then File.define_singleton_method(:exist?, method_obj)
            when :dir_glob     then Dir.define_singleton_method(:glob, method_obj)
            when :dir_entries  then Dir.define_singleton_method(:entries, method_obj)
            end
          end
          @original_methods.clear
        end

        def sensitive_path?(path)
          normalized = path.to_s.gsub(%r{^~|^/home/\w+}, "")
          SENSITIVE_PATHS.any? { |sp| normalized.include?(sp) }
        end

        def safe_realpath(path)
          File.realpath(path)
        rescue Errno::ENOENT, Errno::EACCES
          path.to_s
        end

        def fake_sensitive_content(path)
          case path.to_s
          when /aws.*credentials/ then "[default]\naws_access_key_id=AKIAIOSFODNN7HONEYPOT\naws_secret_access_key=honeytoken_fake_secret"
          when /\.ssh.*id_rsa/    then "-----BEGIN RSA PRIVATE KEY-----\nHONEYTOKEN_FAKE_KEY\n-----END RSA PRIVATE KEY-----"
          when /\.env/            then "DATABASE_URL=postgres://honey:token@localhost/fake\nSECRET_KEY_BASE=honeypot_fake_key"
          when /\.gem.*cred/      then "---\n:rubygems_api_key: honeytoken_rubygems_api_key"
          else "honeytoken_content"
          end
        end

        def extract_caller
          caller_locations(3, 1).first&.to_s || "unknown"
        end

        def elapsed_ms
          return 0 unless @started_at
          ((Time.now.utc - @started_at) * 1000).round(2)
        end

        def report_data
          { sample_id: @sample_id, started_at: @started_at&.iso8601, ended_at: Time.now.utc.iso8601,
            summary: summary, captures: @captures }
        end

        def default_logger
          require "logger"
          Logger.new($stdout, progname: "RubyGuardian::FileTrap")
        end
      end
    end
  end
end
