# frozen_string_literal: true

require 'time'
require 'cgi'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Formatters
        # Formats alerts in IBM QRadar Log Event Extended Format (LEEF).
        #
        # LEEF format:
        #   LEEF:Version|Vendor|Product|Version|EventID|<tab-separated key=value pairs>
        #
        # LEEF 2.0 supports a custom delimiter specified after EventID.
        class LeefFormatter
          LEEF_VERSION   = '2.0'
          VENDOR         = 'RubyGuardian'
          PRODUCT        = 'DetectionEngine'
          PRODUCT_VERSION = '2.0.0'

          # LEEF severity mapping (1-10)
          SEVERITY_MAP = {
            'critical' => 10,
            'high'     => 8,
            'medium'   => 5,
            'low'      => 3,
            'info'     => 1
          }.freeze

          # Standard LEEF attribute keys mapped from internal alert fields
          LEEF_KEYS = {
            source_ip:        'src',
            source_port:      'srcPort',
            source_hostname:  'srcName',
            source_user:      'usrName',
            dest_ip:          'dst',
            dest_port:        'dstPort',
            dest_hostname:    'dstName',
            event_action:     'action',
            network_protocol: 'proto',
            process_name:     'process',
            process_pid:      'pid',
            event_category:   'cat',
            event_outcome:    'outcome'
          }.freeze

          DELIMITER = "\t"

          def initialize(options = {})
            @vendor          = options.fetch(:vendor, VENDOR)
            @product         = options.fetch(:product, PRODUCT)
            @product_version = options.fetch(:product_version, PRODUCT_VERSION)
            @delimiter       = options.fetch(:delimiter, DELIMITER)
            @include_raw     = options.fetch(:include_raw_event, false)
          end

          # Format a single alert as a LEEF string.
          #
          # @param alert [Hash] the alert data
          # @return [String] LEEF formatted message
          def format(alert)
            header = build_header(alert)
            attributes = build_attributes(alert)
            "#{header}#{@delimiter}#{attributes}"
          end

          # Format multiple alerts, one per line.
          #
          # @param alerts [Array<Hash>]
          # @return [String] newline-separated LEEF messages
          def format_batch(alerts)
            alerts.map { |a| format(a) }.join("\n")
          end

          private

          def build_header(alert)
            event_id = escape_pipe(alert[:rule_id] || 'UNKNOWN')
            delimiter_hex = @delimiter == "\t" ? nil : "0x#{@delimiter.ord.to_s(16)}"

            parts = [
              "LEEF:#{LEEF_VERSION}",
              escape_pipe(@vendor),
              escape_pipe(@product),
              escape_pipe(@product_version),
              event_id
            ]

            parts << delimiter_hex if delimiter_hex
            parts.join('|')
          end

          def build_attributes(alert)
            attrs = []

            # Timestamp in LEEF epoch millisecond format
            timestamp = alert[:timestamp] || Time.now
            attrs << kv('devTime', format_leef_timestamp(timestamp))
            attrs << kv('devTimeFormat', 'MMM dd yyyy HH:mm:ss.SSS Z')

            # Severity
            attrs << kv('sev', map_severity(alert[:severity]))

            # Identity / alert ID
            attrs << kv('eventId', alert[:alert_id]) if alert[:alert_id]

            # Rule metadata
            attrs << kv('ruleName', alert[:rule_name]) if alert[:rule_name]
            attrs << kv('ruleDescription', alert[:rule_description]) if alert[:rule_description]

            # Standard LEEF keys from alert fields
            LEEF_KEYS.each do |alert_key, leef_key|
              value = alert[alert_key]
              next if value.nil? || value.to_s.empty?
              attrs << kv(leef_key, value)
            end

            # Extended context attributes
            attrs << kv('commandLine', alert[:command_line]) if alert[:command_line]
            attrs << kv('parentProcess', alert[:parent_process]) if alert[:parent_process]
            attrs << kv('filePath', alert[:file_path]) if alert[:file_path]
            attrs << kv('registryKey', alert[:registry_key]) if alert[:registry_key]

            # MITRE ATT&CK mapping
            if alert[:mitre_tactics]
              attrs << kv('mitreTactics', Array(alert[:mitre_tactics]).join(','))
            end
            if alert[:mitre_techniques]
              attrs << kv('mitreTechniques', Array(alert[:mitre_techniques]).join(','))
            end

            # Tags
            if alert[:tags] && !alert[:tags].empty?
              attrs << kv('tags', Array(alert[:tags]).join(','))
            end

            # Raw event (optional)
            if @include_raw && alert[:raw_event]
              attrs << kv('rawEvent', alert[:raw_event].to_s.gsub(@delimiter, ' '))
            end

            attrs.compact.join(@delimiter)
          end

          def kv(key, value)
            return nil if value.nil? || value.to_s.empty?
            "#{key}=#{escape_value(value)}"
          end

          def escape_pipe(value)
            value.to_s.gsub('|', '\\|')
          end

          def escape_value(value)
            val = value.to_s
            val = val.gsub('\\', '\\\\')
            val = val.gsub('=', '\\=')
            val = val.gsub("\n", '\\n')
            val = val.gsub("\r", '\\r')
            val = val.gsub(@delimiter, ' ') if @delimiter != "\t"
            val
          end

          def map_severity(severity)
            SEVERITY_MAP.fetch(severity.to_s.downcase, 5)
          end

          def format_leef_timestamp(time)
            time.utc.strftime('%b %d %Y %H:%M:%S.%L %z')
          end
        end
      end
    end
  end
end
