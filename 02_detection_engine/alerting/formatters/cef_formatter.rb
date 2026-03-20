# frozen_string_literal: true

require 'time'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Formatters
        # Formats alerts in ArcSight Common Event Format (CEF).
        #
        # CEF format:
        #   CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
        #
        # Severity mapping (CEF uses 0-10 scale):
        #   critical -> 10, high -> 8, medium -> 5, low -> 3, info -> 1
        class CefFormatter
          CEF_VERSION = 0
          DEVICE_VENDOR  = 'RubyGuardian'
          DEVICE_PRODUCT = 'DetectionEngine'
          DEVICE_VERSION = '2.0.0'

          SEVERITY_MAP = {
            'critical' => 10,
            'high'     => 8,
            'medium'   => 5,
            'low'      => 3,
            'info'     => 1
          }.freeze

          # CEF extension key mapping from internal alert fields
          EXTENSION_KEYS = {
            source_ip:        'src',
            source_port:      'spt',
            source_hostname:  'shost',
            source_user:      'suser',
            dest_ip:          'dst',
            dest_port:        'dpt',
            dest_hostname:    'dhost',
            dest_service:     'dproc',
            process_name:     'sproc',
            process_pid:      'spid',
            file_path:        'filePath',
            event_action:     'act',
            event_outcome:    'outcome',
            network_protocol: 'proto',
            command_line:     'cs1',
            parent_process:   'cs2',
            registry_key:     'cs3',
            rule_description: 'cs4'
          }.freeze

          CUSTOM_STRING_LABELS = {
            'cs1' => 'cs1Label=CommandLine',
            'cs2' => 'cs2Label=ParentProcess',
            'cs3' => 'cs3Label=RegistryKey',
            'cs4' => 'cs4Label=RuleDescription'
          }.freeze

          def initialize(options = {})
            @device_vendor  = options.fetch(:device_vendor, DEVICE_VENDOR)
            @device_product = options.fetch(:device_product, DEVICE_PRODUCT)
            @device_version = options.fetch(:device_version, DEVICE_VERSION)
            @max_length     = options.fetch(:max_length, 65_536)
          end

          # Format a single alert as a CEF string.
          #
          # @param alert [Hash] the alert data
          # @return [String] CEF formatted message
          def format(alert)
            header = build_header(alert)
            extension = build_extension(alert)
            message = "#{header}|#{extension}"
            truncate_if_needed(message)
          end

          # Format multiple alerts, one CEF line per alert.
          #
          # @param alerts [Array<Hash>]
          # @return [String] newline-separated CEF messages
          def format_batch(alerts)
            alerts.map { |a| format(a) }.join("\n")
          end

          private

          def build_header(alert)
            signature_id = escape_header_field(alert[:rule_id] || 'UNKNOWN')
            name = escape_header_field(alert[:rule_name] || 'Unknown Rule')
            severity = map_severity(alert[:severity])

            "CEF:#{CEF_VERSION}|#{escape_header_field(@device_vendor)}|" \
              "#{escape_header_field(@device_product)}|" \
              "#{escape_header_field(@device_version)}|" \
              "#{signature_id}|#{name}|#{severity}"
          end

          def build_extension(alert)
            pairs = []

            # Timestamp fields
            now = Time.now
            pairs << "rt=#{format_cef_timestamp(alert[:timestamp] || now)}"
            pairs << "deviceReceiptTime=#{format_cef_timestamp(now)}"

            # Map standard fields
            EXTENSION_KEYS.each do |alert_key, cef_key|
              value = alert[alert_key]
              next if value.nil? || value.to_s.empty?

              pairs << "#{cef_key}=#{escape_extension_value(value)}"

              # Add custom string labels if applicable
              if CUSTOM_STRING_LABELS.key?(cef_key)
                pairs << CUSTOM_STRING_LABELS[cef_key]
              end
            end

            # MITRE ATT&CK fields using flexible extension
            if alert[:mitre_tactics]
              pairs << "deviceCustomString5=#{escape_extension_value(Array(alert[:mitre_tactics]).join(','))}"
              pairs << 'deviceCustomString5Label=MitreTactics'
            end

            if alert[:mitre_techniques]
              pairs << "deviceCustomString6=#{escape_extension_value(Array(alert[:mitre_techniques]).join(','))}"
              pairs << 'deviceCustomString6Label=MitreTechniques'
            end

            # Tags
            if alert[:tags] && !alert[:tags].empty?
              pairs << "cat=#{escape_extension_value(Array(alert[:tags]).join(','))}"
            end

            # Alert identifier
            pairs << "externalId=#{escape_extension_value(alert[:alert_id])}" if alert[:alert_id]

            pairs.join(' ')
          end

          def map_severity(severity)
            SEVERITY_MAP.fetch(severity.to_s.downcase, 5)
          end

          def format_cef_timestamp(time)
            # CEF timestamp: MMM dd yyyy HH:mm:ss.SSS zzz
            time.utc.strftime('%b %d %Y %H:%M:%S.%L UTC')
          end

          def escape_header_field(value)
            value.to_s
                 .gsub('\\', '\\\\')
                 .gsub('|', '\\|')
          end

          def escape_extension_value(value)
            value.to_s
                 .gsub('\\', '\\\\')
                 .gsub('=', '\\=')
                 .gsub("\n", '\\n')
                 .gsub("\r", '\\r')
          end

          def truncate_if_needed(message)
            if message.bytesize > @max_length
              message.byteslice(0, @max_length - 3) + '...'
            else
              message
            end
          end
        end
      end
    end
  end
end
