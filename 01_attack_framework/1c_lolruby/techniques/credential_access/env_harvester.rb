# frozen_string_literal: true

# RubyGuardian Phase 1c -- LoLRuby Credential Access: ENV Harvester
#
# Demonstrates how Ruby's built-in ENV access can be used to harvest
# credentials from environment variables -- a common technique in
# cloud-native and CI/CD environments.
#
# EDUCATIONAL PURPOSE ONLY -- Authorized security research.
# MITRE ATT&CK: T1552.001 - Unsecured Credentials: Credentials In Files

module RubyGuardian
  module LoLRuby
    module CredentialAccess
      class EnvHarvester
        # Common environment variable names that may contain secrets
        SENSITIVE_PATTERNS = [
          /password/i, /secret/i, /token/i, /api_key/i, /apikey/i,
          /access_key/i, /private_key/i, /credential/i, /auth/i,
          /database_url/i, /connection_string/i, /aws_/i, /github_token/i
        ].freeze

        SENSITIVE_FILES = [
          '.env', '.env.local', '.env.production',
          'config/secrets.yml', 'config/credentials.yml.enc',
          'config/database.yml', '.git/config'
        ].freeze

        attr_reader :findings, :logger

        def initialize(logger: nil)
          @logger = logger
          @findings = []
        end

        # Scan environment variables for potential credentials
        def scan_environment
          @logger&.info('[LoLRuby] Scanning ENV for credential patterns')

          ENV.each do |key, value|
            SENSITIVE_PATTERNS.each do |pattern|
              if key.match?(pattern)
                @findings << {
                  source: 'environment_variable',
                  key: key,
                  value_preview: mask_value(value),
                  pattern_matched: pattern.source,
                  timestamp: Time.now.utc.iso8601
                }
                break
              end
            end
          end

          @logger&.info("[LoLRuby] Found #{@findings.size} potential credentials in ENV")
          @findings
        end

        # Scan common config files for credential patterns
        def scan_config_files(base_dir: '.')
          @logger&.info("[LoLRuby] Scanning config files in #{base_dir}")

          SENSITIVE_FILES.each do |rel_path|
            full_path = File.join(base_dir, rel_path)
            next unless File.exist?(full_path)

            @findings << {
              source: 'config_file',
              path: full_path,
              size: File.size(full_path),
              readable: File.readable?(full_path),
              timestamp: Time.now.utc.iso8601
            }
          end

          @findings
        end

        # Describe the technique for educational purposes
        def describe
          <<~DESC
            ENV Harvester (T1552.001)
            ━━━━━━━━━━━━━━━━━━━━━━━━
            Ruby's ENV hash provides direct access to all environment variables.
            In cloud/container environments, secrets are commonly passed via ENV.

            Detection: Monitor for bulk ENV access patterns, especially from
            non-application code paths. Alert on ENV access to known secret
            variable names from unexpected Ruby source locations.
          DESC
        end

        private

        def mask_value(value)
          return '(empty)' if value.nil? || value.empty?
          return '***' if value.length <= 4

          "#{value[0..1]}#{'*' * [value.length - 4, 3].max}#{value[-2..]}"
        end
      end
    end
  end
end
