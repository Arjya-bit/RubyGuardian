# frozen_string_literal: true

require 'logger'
require 'json'

module RubyGuardian
  module Shared
    # Centralized logging for all attack framework modules
    # Supports multiple output formats and destinations
    class AttackLogger
      SEVERITY_COLORS = {
        'DEBUG' => "\e[36m",   # Cyan
        'INFO' => "\e[32m",    # Green
        'WARN' => "\e[33m",    # Yellow
        'ERROR' => "\e[31m",   # Red
        'FATAL' => "\e[35m"    # Magenta
      }.freeze

      RESET = "\e[0m"

      attr_reader :logger, :module_name

      def initialize(module_name, output: $stdout, level: :info, format: :pretty)
        @module_name = module_name
        @format = format
        @logger = ::Logger.new(output)
        @logger.level = parse_level(level)
        @logger.formatter = method(:format_message)
      end

      %i[debug info warn error fatal].each do |level|
        define_method(level) do |message, **metadata|
          @logger.send(level, build_entry(message, metadata))
        end
      end

      # Log an attack technique execution
      def technique(name, mitre_id:, status:, **details)
        info("[TECHNIQUE] #{name} (#{mitre_id}) - #{status}", **details)
      end

      # Log a detection event (for testing detection engine)
      def detection_event(rule_name, severity:, **details)
        warn("[DETECTION] Rule: #{rule_name} | Severity: #{severity}", **details)
      end

      # Log a safety check
      def safety_check(check_name, passed:)
        level = passed ? :info : :error
        send(level, "[SAFETY] #{check_name}: #{passed ? 'PASSED' : 'FAILED'}")
      end

      private

      def parse_level(level)
        case level.to_s.downcase
        when 'debug' then ::Logger::DEBUG
        when 'info'  then ::Logger::INFO
        when 'warn'  then ::Logger::WARN
        when 'error' then ::Logger::ERROR
        when 'fatal' then ::Logger::FATAL
        else ::Logger::INFO
        end
      end

      def build_entry(message, metadata)
        {
          module: @module_name,
          message: message,
          metadata: metadata,
          timestamp: Time.now.utc.iso8601
        }
      end

      def format_message(severity, _time, _progname, entry)
        case @format
        when :json
          format_json(severity, entry)
        when :pretty
          format_pretty(severity, entry)
        else
          format_simple(severity, entry)
        end
      end

      def format_json(severity, entry)
        JSON.generate(
          severity: severity,
          timestamp: entry[:timestamp] || Time.now.utc.iso8601,
          module: entry[:module],
          message: entry[:message],
          metadata: entry[:metadata]
        ) + "\n"
      end

      def format_pretty(severity, entry)
        color = SEVERITY_COLORS[severity] || ''
        ts = entry[:timestamp] || Time.now.utc.strftime('%H:%M:%S')
        mod = entry[:module] || 'unknown'
        msg = entry[:message] || entry.to_s
        meta = entry[:metadata]&.any? ? " #{entry[:metadata]}" : ''

        "#{color}[#{severity}]#{RESET} #{ts} [#{mod}] #{msg}#{meta}\n"
      end

      def format_simple(severity, entry)
        msg = entry.is_a?(Hash) ? entry[:message] : entry.to_s
        "[#{severity}] #{msg}\n"
      end
    end
  end
end
