# frozen_string_literal: true

# RubyGuardian Phase 5 -- Honeypot Analysis: Sample Analyzer
#
# Analyzes captured malware samples using static analysis, pattern
# matching, and YARA rules. Provides IOC extraction and classification.

require 'json'
require 'digest'

module RubyGuardian
  module Honeypot
    class SampleAnalyzer
      DANGEROUS_METHODS = %w[
        eval instance_eval class_eval module_eval
        system exec ` IO.popen Open3.popen3
        Kernel.exec Process.spawn
        send __send__ public_send
        require load require_relative
        Marshal.load YAML.load
        ObjectSpace
      ].freeze

      OBFUSCATION_PATTERNS = [
        { name: 'base64_eval', pattern: /Base64\.(decode64|strict_decode64).*eval/m },
        { name: 'marshal_load', pattern: /Marshal\.load/ },
        { name: 'char_array_pack', pattern: /\[[\d,\s]+\]\.pack\s*\(\s*['"]C\*['"]\s*\)/ },
        { name: 'hex_string', pattern: /\\x[0-9a-f]{2}/i },
        { name: 'xor_decode', pattern: /\^\s*\d+/ },
        { name: 'zlib_inflate', pattern: /Zlib::Inflate/ },
        { name: 'string_reverse_eval', pattern: /\.reverse.*eval/m },
      ].freeze

      attr_reader :logger

      def initialize(logger: nil)
        @logger = logger
      end

      # Perform full static analysis on a Ruby source file
      def analyze(source_code, metadata: {})
        @logger&.info('[Analyzer] Starting static analysis')

        {
          metadata: {
            size: source_code.bytesize,
            lines: source_code.lines.count,
            sha256: Digest::SHA256.hexdigest(source_code),
            analyzed_at: Time.now.utc.iso8601,
            **metadata
          },
          dangerous_methods: find_dangerous_methods(source_code),
          obfuscation: detect_obfuscation(source_code),
          network_iocs: extract_network_iocs(source_code),
          file_iocs: extract_file_iocs(source_code),
          strings_of_interest: extract_strings(source_code),
          risk_score: calculate_risk_score(source_code),
          classification: classify(source_code)
        }
      end

      private

      def find_dangerous_methods(source)
        DANGEROUS_METHODS.each_with_object([]) do |method, findings|
          source.scan(/\b#{Regexp.escape(method)}\b/).each do
            findings << { method: method, count: source.scan(/\b#{Regexp.escape(method)}\b/).size }
          end
        end.uniq
      end

      def detect_obfuscation(source)
        OBFUSCATION_PATTERNS.each_with_object([]) do |pattern, findings|
          matches = source.scan(pattern[:pattern])
          next if matches.empty?

          findings << {
            technique: pattern[:name],
            occurrences: matches.size
          }
        end
      end

      def extract_network_iocs(source)
        iocs = []
        # IP addresses
        source.scan(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/).flatten.each do |ip|
          iocs << { type: 'ip', value: ip } unless ip.start_with?('127.', '0.', '10.', '192.168.')
        end
        # URLs
        source.scan(%r{https?://[^\s'"]+}).each { |url| iocs << { type: 'url', value: url } }
        # Domains
        source.scan(/[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}/).each do |domain|
          iocs << { type: 'domain', value: domain } unless %w[example.com localhost].include?(domain)
        end
        iocs.uniq
      end

      def extract_file_iocs(source)
        paths = []
        source.scan(%r{['"](/(?:etc|tmp|var|home|usr|opt)/[^'"]+)['"]}).flatten.each do |path|
          paths << { type: 'file_path', value: path }
        end
        paths
      end

      def extract_strings(source)
        # Extract interesting strings (base64, hex, etc.)
        strings = []
        source.scan(/['"]([A-Za-z0-9+\/]{20,}=*)['"]/).flatten.each do |s|
          strings << { type: 'possible_base64', value: s[0..100] }
        end
        strings.first(20)
      end

      def calculate_risk_score(source)
        score = 0
        score += find_dangerous_methods(source).size * 10
        score += detect_obfuscation(source).size * 20
        score += extract_network_iocs(source).size * 15
        score += 25 if source.match?(/eval.*Base64/m)
        score += 30 if source.match?(/require\s+['"]socket['"]/i)
        [score, 100].min
      end

      def classify(source)
        score = calculate_risk_score(source)
        if score >= 70
          { label: 'malicious', confidence: 'high' }
        elsif score >= 40
          { label: 'suspicious', confidence: 'medium' }
        else
          { label: 'benign', confidence: 'low' }
        end
      end
    end
  end
end
