# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Exfiltration: DNS-based Data Exfiltration
#
# Demonstrates data exfiltration using Ruby's built-in DNS resolution
# capabilities. DNS is commonly allowed through firewalls, making it
# an attractive exfiltration channel.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1048.003 - Exfiltration Over Alternative Protocol: DNS

require 'resolv'
require 'base64'
require 'digest'

module RubyGuardian
  module LoLRuby
    module Exfiltration
      class DnsExfiltrator
        MAX_LABEL_LENGTH = 63
        MAX_DOMAIN_LENGTH = 253
        CHUNK_SIZE = 45 # Base32 safe chunk size for DNS labels

        attr_reader :logger, :exfil_log

        def initialize(domain: 'example.com', logger: nil, dry_run: true)
          @domain = domain
          @logger = logger
          @dry_run = dry_run
          @exfil_log = []
        end

        # Demonstrate encoding data into DNS queries (dry run only)
        def demonstrate_encode(data)
          @logger&.info('[LoLRuby] Demonstrating DNS exfiltration encoding')

          chunks = encode_for_dns(data)
          queries = chunks.each_with_index.map do |chunk, idx|
            "#{chunk}.#{idx}.#{@domain}"
          end

          result = {
            technique: 'dns_exfiltration',
            data_size: data.bytesize,
            encoded_chunks: chunks.size,
            sample_queries: queries.first(3),
            total_queries_needed: queries.size,
            dry_run: @dry_run,
            detection_notes: [
              'High volume of DNS queries to a single domain',
              'Unusually long subdomain labels',
              'Base32/Base64 encoded subdomain patterns',
              'Sequential query patterns with incrementing counters'
            ]
          }

          @exfil_log << result
          result
        end

        # Analyze DNS query patterns for exfiltration indicators
        def analyze_query_pattern(queries)
          {
            total_queries: queries.size,
            unique_domains: queries.map { |q| q.split('.').last(2).join('.') }.uniq.size,
            avg_subdomain_length: queries.map { |q| q.split('.').first.length }.sum.to_f / queries.size,
            contains_encoded_data: queries.any? { |q| q.split('.').first.match?(/^[A-Z2-7]+=*$/i) },
            sequential_pattern: detect_sequential_pattern(queries),
            risk_assessment: 'Review queries with long encoded subdomains to single domain'
          }
        end

        def describe
          <<~DESC
            DNS Exfiltration (T1048.003)
            ━━━━━━━━━━━━━━━━━━━━━━━━━━━
            Ruby's Resolv library allows DNS queries without external tools.
            Data is encoded into DNS subdomain labels and sent as lookups.
            Since DNS is rarely blocked, this is an effective covert channel.

            Detection: Monitor for high-volume DNS queries to a single domain,
            unusually long subdomain labels, and encoded data patterns.
          DESC
        end

        private

        def encode_for_dns(data)
          # Use base32-like encoding (DNS-safe characters)
          encoded = Base64.strict_encode64(data).tr('+/', '-_').delete('=')
          encoded.scan(/.{1,#{CHUNK_SIZE}}/)
        end

        def detect_sequential_pattern(queries)
          return false if queries.size < 3

          subdomains = queries.map { |q| q.split('.') }
          # Check if there's an incrementing numeric component
          subdomains.each_cons(2).all? do |a, b|
            idx_a = a.find { |part| part.match?(/^\d+$/) }&.to_i
            idx_b = b.find { |part| part.match?(/^\d+$/) }&.to_i
            idx_a && idx_b && idx_b == idx_a + 1
          end
        end
      end
    end
  end
end
