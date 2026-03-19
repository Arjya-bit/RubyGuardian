# frozen_string_literal: true

# RubyGuardian Phase 5 -- Honeypot Capture Engine: Request Logger
#
# Captures and logs all incoming HTTP requests to honeypot decoy apps.
# Extracts metadata, payloads, and attack indicators for analysis.

require 'json'
require 'time'
require 'digest'
require 'fileutils'

module RubyGuardian
  module Honeypot
    class RequestLogger
      attr_reader :config, :logger, :log_dir, :stats

      def initialize(config: {}, logger: nil)
        @config = config
        @logger = logger
        @log_dir = config['log_dir'] || '/var/log/ruby-guardian/honeypot'
        @stats = { total: 0, suspicious: 0, attacks_detected: 0 }
        @mutex = Mutex.new

        FileUtils.mkdir_p(@log_dir)
      end

      # Log an incoming HTTP request
      def log_request(env)
        entry = extract_request_data(env)
        entry[:indicators] = analyze_indicators(entry)
        entry[:is_suspicious] = entry[:indicators].any?

        @mutex.synchronize do
          @stats[:total] += 1
          @stats[:suspicious] += 1 if entry[:is_suspicious]
        end

        write_log_entry(entry)
        @logger&.info("[Honeypot] #{entry[:method]} #{entry[:path]} from #{entry[:remote_ip]} " \
                      "#{entry[:is_suspicious] ? '[SUSPICIOUS]' : '[benign]'}")
        entry
      end

      # Analyze request for known attack indicators
      def analyze_indicators(entry)
        indicators = []

        # SQL injection patterns
        if entry[:query_string]&.match?(/('|--|;|union\s+select|or\s+1\s*=\s*1)/i)
          indicators << { type: 'sqli', detail: 'SQL injection pattern in query string' }
        end

        # XSS patterns
        if entry[:body]&.match?(/<script|javascript:|on\w+\s*=/i)
          indicators << { type: 'xss', detail: 'XSS pattern in request body' }
        end

        # Path traversal
        if entry[:path]&.match?(/\.\.[\/\\]/)
          indicators << { type: 'path_traversal', detail: 'Directory traversal in path' }
        end

        # Command injection
        if entry[:body]&.match?(/[;&|`$]|\beval\b|\bsystem\b|\bexec\b/i)
          indicators << { type: 'command_injection', detail: 'Command injection pattern' }
        end

        # Ruby-specific: eval/send/system in parameters
        if entry[:query_string]&.match?(/\b(eval|instance_eval|send|__send__|system)\b/)
          indicators << { type: 'ruby_injection', detail: 'Ruby method injection attempt' }
        end

        indicators
      end

      private

      def extract_request_data(env)
        body = env['rack.input']&.read
        env['rack.input']&.rewind

        {
          timestamp: Time.now.utc.iso8601(3),
          request_id: SecureRandom.uuid,
          method: env['REQUEST_METHOD'],
          path: env['PATH_INFO'],
          query_string: env['QUERY_STRING'],
          remote_ip: env['REMOTE_ADDR'],
          remote_port: env['REMOTE_PORT'],
          user_agent: env['HTTP_USER_AGENT'],
          content_type: env['CONTENT_TYPE'],
          body: body,
          body_hash: body ? Digest::SHA256.hexdigest(body) : nil,
          headers: extract_headers(env)
        }
      end

      def extract_headers(env)
        env.select { |k, _| k.start_with?('HTTP_') }
           .transform_keys { |k| k.sub('HTTP_', '').split('_').map(&:capitalize).join('-') }
      end

      def write_log_entry(entry)
        date = Time.now.strftime('%Y-%m-%d')
        log_file = File.join(@log_dir, "requests_#{date}.jsonl")
        File.open(log_file, 'a') { |f| f.puts(JSON.generate(entry)) }
      end
    end
  end
end
