# frozen_string_literal: true

require 'json'
require 'time'
require 'securerandom'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Formatters
        # Formats alerts as structured JSON with complete field mapping,
        # ISO 8601 timestamps, and severity-to-numeric mapping.
        class JsonFormatter
          SEVERITY_MAP = {
            'critical' => 1,
            'high'     => 2,
            'medium'   => 3,
            'low'      => 4,
            'info'     => 5
          }.freeze

          REQUIRED_FIELDS = %i[rule_id rule_name severity source_ip event_type].freeze

          attr_reader :options

          def initialize(options = {})
            @options = {
              pretty:            options.fetch(:pretty, false),
              include_raw_event: options.fetch(:include_raw_event, false),
              timestamp_format:  options.fetch(:timestamp_format, :iso8601),
              schema_version:    options.fetch(:schema_version, '2.0'),
              max_payload_bytes: options.fetch(:max_payload_bytes, 65_536)
            }
          end

          # Format a single alert into a JSON string.
          #
          # @param alert [Hash] the alert data
          # @return [String] JSON-encoded alert
          def format(alert)
            validate_alert!(alert)
            payload = build_payload(alert)
            encoded = encode_json(payload)
            enforce_size_limit!(encoded)
            encoded
          end

          # Format multiple alerts into a JSON array string.
          #
          # @param alerts [Array<Hash>] collection of alert data
          # @return [String] JSON-encoded array of alerts
          def format_batch(alerts)
            payloads = alerts.map { |a| build_payload(a) }
            wrapper = {
              schema_version: @options[:schema_version],
              batch_id: SecureRandom.uuid,
              count: payloads.size,
              generated_at: format_timestamp(Time.now),
              alerts: payloads
            }
            encode_json(wrapper)
          end

          private

          def build_payload(alert)
            now = Time.now

            payload = {
              schema_version:   @options[:schema_version],
              alert_id:         alert[:alert_id] || SecureRandom.uuid,
              timestamp:        format_timestamp(alert[:timestamp] || now),
              received_at:      format_timestamp(now),
              rule: {
                id:          alert[:rule_id],
                name:        alert[:rule_name],
                description: alert[:rule_description],
                version:     alert[:rule_version] || '1.0',
                mitre_attack: extract_mitre_mappings(alert)
              },
              severity: {
                label:   normalize_severity(alert[:severity]),
                numeric: SEVERITY_MAP[normalize_severity(alert[:severity])]
              },
              source: {
                ip:       alert[:source_ip],
                port:     alert[:source_port],
                hostname: alert[:source_hostname],
                user:     alert[:source_user]
              },
              destination: {
                ip:       alert[:dest_ip],
                port:     alert[:dest_port],
                hostname: alert[:dest_hostname],
                service:  alert[:dest_service]
              },
              event: {
                type:     alert[:event_type],
                category: alert[:event_category],
                action:   alert[:event_action],
                outcome:  alert[:event_outcome]
              },
              context: build_context(alert),
              tags: Array(alert[:tags])
            }

            payload[:raw_event] = alert[:raw_event] if @options[:include_raw_event] && alert[:raw_event]
            payload
          end

          def build_context(alert)
            ctx = {}
            ctx[:process_name]    = alert[:process_name] if alert[:process_name]
            ctx[:process_pid]     = alert[:process_pid] if alert[:process_pid]
            ctx[:parent_process]  = alert[:parent_process] if alert[:parent_process]
            ctx[:command_line]    = alert[:command_line] if alert[:command_line]
            ctx[:file_path]       = alert[:file_path] if alert[:file_path]
            ctx[:registry_key]    = alert[:registry_key] if alert[:registry_key]
            ctx[:network_protocol] = alert[:network_protocol] if alert[:network_protocol]
            ctx[:additional]      = alert[:additional_context] if alert[:additional_context]
            ctx
          end

          def extract_mitre_mappings(alert)
            return nil unless alert[:mitre_tactics] || alert[:mitre_techniques]

            {
              tactics:    Array(alert[:mitre_tactics]),
              techniques: Array(alert[:mitre_techniques])
            }
          end

          def normalize_severity(severity)
            label = severity.to_s.downcase.strip
            unless SEVERITY_MAP.key?(label)
              raise ArgumentError, "Unknown severity '#{severity}'. Valid: #{SEVERITY_MAP.keys.join(', ')}"
            end
            label
          end

          def format_timestamp(time)
            case @options[:timestamp_format]
            when :iso8601    then time.utc.iso8601(3)
            when :epoch      then time.to_f
            when :epoch_ms   then (time.to_f * 1000).to_i
            else time.utc.iso8601(3)
            end
          end

          def encode_json(payload)
            if @options[:pretty]
              JSON.pretty_generate(payload)
            else
              JSON.generate(payload)
            end
          end

          def enforce_size_limit!(encoded)
            if encoded.bytesize > @options[:max_payload_bytes]
              raise PayloadTooLargeError,
                    "Alert payload #{encoded.bytesize} bytes exceeds limit of #{@options[:max_payload_bytes]} bytes"
            end
          end

          def validate_alert!(alert)
            missing = REQUIRED_FIELDS.select { |f| alert[f].nil? || alert[f].to_s.empty? }
            unless missing.empty?
              raise ValidationError, "Missing required alert fields: #{missing.join(', ')}"
            end
          end
        end

        class PayloadTooLargeError < StandardError; end
        class ValidationError < StandardError; end
      end
    end
  end
end
