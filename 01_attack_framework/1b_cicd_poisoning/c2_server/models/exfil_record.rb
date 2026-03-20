# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Exfiltration Record Model
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This model represents a logged exfiltration attempt in the simulated C2
#   framework. In real CI/CD poisoning attacks, exfiltrated data typically
#   includes: CI secrets, API tokens, SSH keys, cloud credentials, source
#   code, and build artifacts.
#
#   This model is used strictly for logging and analysis. No actual data
#   exfiltration is performed. All "payload" data is discarded immediately.
#
# MITRE ATT&CK References:
#   - T1041     : Exfiltration Over C2 Channel
#   - T1567     : Exfiltration Over Web Service
#   - T1560.001 : Archive Collected Data: Archive via Utility
#   - T1552.001 : Unsecured Credentials: Credentials In Files
# =============================================================================

module RubyGuardian
  module C2
    module Models
      # ExfilRecord logs metadata about a simulated exfiltration attempt.
      #
      # In real attacks against CI/CD pipelines, exfiltration typically targets:
      #   - Environment variables containing secrets (T1552.001)
      #   - Cloud provider credentials (AWS keys, GCP service accounts)
      #   - SSH keys and GPG keys stored in the build environment
      #   - Source code repositories accessible from the runner
      #   - Build artifacts and container images
      #   - Internal network service tokens
      #
      # This model records the *metadata* of such attempts for research
      # purposes. No actual secret data is ever captured or stored.
      #
      # Attributes:
      #   data_type  [String] - Category of exfiltrated data (e.g., 'env_vars')
      #   source     [String] - Where the data was collected from
      #   size       [Integer] - Size of the payload in bytes
      #   timestamp  [Time]   - When the exfiltration was logged
      class ExfilRecord
        # Known data types that CI/CD attacks commonly target
        KNOWN_DATA_TYPES = %w[
          env_vars
          ssh_keys
          api_tokens
          cloud_credentials
          source_code
          build_artifacts
          docker_config
          kubeconfig
          npm_tokens
          gem_credentials
          unknown
        ].freeze

        # Common sources of exfiltrated data in CI/CD environments
        KNOWN_SOURCES = %w[
          ci_pipeline
          build_environment
          artifact_store
          secret_manager
          config_files
          container_runtime
          network_scan
          unknown
        ].freeze

        attr_accessor :data_type, :source, :size, :timestamp
        attr_reader :record_id

        # Initialize a new ExfilRecord
        #
        # @param data_type [String]  Category of the exfiltrated data
        # @param source    [String]  Origin of the data within the CI system
        # @param size      [Integer] Payload size in bytes
        # @param timestamp [Time]    When the exfiltration occurred
        def initialize(data_type:, source:, size:, timestamp: nil)
          @record_id = generate_record_id
          @data_type = normalize_data_type(data_type)
          @source    = normalize_source(source)
          @size      = size.to_i
          @timestamp = timestamp || Time.now
        end

        # Human-readable size string
        #
        # @return [String] formatted size (e.g., "1.5 KB", "3.2 MB")
        def formatted_size
          if @size < 1024
            "#{@size} B"
          elsif @size < 1024 * 1024
            format('%.1f KB', @size / 1024.0)
          elsif @size < 1024 * 1024 * 1024
            format('%.1f MB', @size / (1024.0 * 1024))
          else
            format('%.1f GB', @size / (1024.0 * 1024 * 1024))
          end
        end

        # Assess the severity of the exfiltration attempt based on data type.
        # Used for alerting and reporting in the research framework.
        #
        # @return [Symbol] :critical, :high, :medium, or :low
        def severity
          case @data_type
          when 'cloud_credentials', 'ssh_keys', 'kubeconfig'
            :critical
          when 'api_tokens', 'gem_credentials', 'npm_tokens', 'docker_config'
            :high
          when 'env_vars', 'source_code'
            :medium
          when 'build_artifacts'
            :low
          else
            :medium
          end
        end

        # Return the corresponding MITRE ATT&CK technique IDs for this
        # type of exfiltration attempt.
        #
        # @return [Array<String>] relevant ATT&CK technique IDs
        def mitre_techniques
          base = ['T1041'] # Exfiltration Over C2 Channel

          case @data_type
          when 'env_vars', 'cloud_credentials', 'api_tokens'
            base + ['T1552.001'] # Unsecured Credentials: Credentials In Files
          when 'ssh_keys'
            base + ['T1552.004'] # Unsecured Credentials: Private Keys
          when 'source_code', 'build_artifacts'
            base + ['T1560.001'] # Archive Collected Data
          else
            base
          end
        end

        # Serialize the record to a hash for JSON responses
        #
        # @return [Hash] record data suitable for JSON serialization
        def to_h
          {
            record_id: @record_id,
            data_type: @data_type,
            source: @source,
            size_bytes: @size,
            size_formatted: formatted_size,
            severity: severity,
            mitre_techniques: mitre_techniques,
            timestamp: @timestamp&.iso8601,
            note: 'SIMULATION ONLY - No actual data was exfiltrated or stored'
          }
        end

        # Serialize to JSON string
        #
        # @return [String] JSON representation
        def to_json(*_args)
          to_h.to_json
        end

        # Create an ExfilRecord from a database row hash
        #
        # @param row [Hash] database row with string keys
        # @return [ExfilRecord] populated record object
        def self.from_db_row(row)
          record = new(
            data_type: row['data_type'],
            source:    row['source'],
            size:      row['size'] || 0,
            timestamp: row['timestamp'] ? Time.parse(row['timestamp']) : nil
          )
          record
        end

        private

        # Generate a unique record identifier
        #
        # @return [String] UUID-based record ID
        def generate_record_id
          "exfil-#{SecureRandom.uuid}"
        end

        # Normalize the data type to a known category
        #
        # @param dtype [String] raw data type string
        # @return [String] normalized data type
        def normalize_data_type(dtype)
          normalized = dtype.to_s.strip.downcase.gsub(/\s+/, '_')
          KNOWN_DATA_TYPES.include?(normalized) ? normalized : 'unknown'
        end

        # Normalize the source to a known category
        #
        # @param src [String] raw source string
        # @return [String] normalized source
        def normalize_source(src)
          normalized = src.to_s.strip.downcase.gsub(/\s+/, '_')
          KNOWN_SOURCES.include?(normalized) ? normalized : 'unknown'
        end
      end
    end
  end
end
