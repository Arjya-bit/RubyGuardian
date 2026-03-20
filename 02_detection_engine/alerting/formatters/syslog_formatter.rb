# frozen_string_literal: true

require 'time'
require 'socket'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Formatters
        # Formats alerts in RFC 5424 syslog format with facility/severity mapping.
        # Produces structured data elements for MITRE ATT&CK and alert metadata.
        #
        # RFC 5424 format:
        #   <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID SD-PARAMS] MSG
        class SyslogFormatter
          # Syslog facility codes
          FACILITY = {
            kern:     0,  user:    1,  mail:     2,  daemon:  3,
            auth:     4,  syslog:  5,  lpr:      6,  news:    7,
            uucp:     8,  cron:    9,  authpriv: 10, ftp:     11,
            ntp:      12, audit:   13, alert:    14, clock:   15,
            local0:   16, local1:  17, local2:   18, local3:  19,
            local4:   20, local5:  21, local6:   22, local7:  23
          }.freeze

          # Syslog severity codes (RFC 5424)
          SEVERITY = {
            emergency:     0,
            alert:         1,
            critical:      2,
            error:         3,
            warning:       4,
            notice:        5,
            informational: 6,
            debug:         7
          }.freeze

          # Map RubyGuardian severity to syslog severity
          ALERT_SEVERITY_MAP = {
            'critical' => :critical,
            'high'     => :error,
            'medium'   => :warning,
            'low'      => :notice,
            'info'     => :informational
          }.freeze

          SD_ID_ALERT  = 'alert@48577'
          SD_ID_MITRE  = 'mitre@48577'
          SD_ID_SOURCE = 'source@48577'

          attr_reader :facility, :app_name, :hostname

          def initialize(options = {})
            @facility  = options.fetch(:facility, :local0)
            @app_name  = options.fetch(:app_name, 'RubyGuardian')
            @hostname  = options.fetch(:hostname, Socket.gethostname)
            @proc_id   = options.fetch(:proc_id, Process.pid.to_s)
            @enterprise_id = options.fetch(:enterprise_id, '48577')

            unless FACILITY.key?(@facility)
              raise ArgumentError, "Invalid facility: #{@facility}. Valid: #{FACILITY.keys.join(', ')}"
            end
          end

          # Format a single alert as an RFC 5424 syslog message.
          #
          # @param alert [Hash] the alert data
          # @return [String] RFC 5424 formatted message
          def format(alert)
            pri = calculate_priority(alert[:severity])
            timestamp = format_timestamp(alert[:timestamp] || Time.now)
            msg_id = alert[:rule_id] || '-'
            structured_data = build_structured_data(alert)
            message = build_message(alert)

            "<#{pri}>1 #{timestamp} #{@hostname} #{@app_name} #{@proc_id} #{msg_id} #{structured_data} #{message}"
          end

          # Format multiple alerts, one per line.
          #
          # @param alerts [Array<Hash>]
          # @return [String] newline-separated syslog messages
          def format_batch(alerts)
            alerts.map { |a| format(a) }.join("\n")
          end

          # Calculate the PRI value from facility and alert severity.
          #
          # @param alert_severity [String] RubyGuardian severity label
          # @return [Integer] PRI value
          def calculate_priority(alert_severity)
            syslog_sev = ALERT_SEVERITY_MAP.fetch(alert_severity.to_s.downcase, :warning)
            (FACILITY[@facility] * 8) + SEVERITY[syslog_sev]
          end

          private

          def format_timestamp(time)
            time.utc.strftime('%Y-%m-%dT%H:%M:%S.%6NZ')
          end

          def build_structured_data(alert)
            parts = []

            # Alert metadata SD element
            alert_params = []
            alert_params << sd_param('id', alert[:alert_id])
            alert_params << sd_param('ruleName', alert[:rule_name])
            alert_params << sd_param('severity', alert[:severity])
            alert_params << sd_param('eventType', alert[:event_type])
            alert_params << sd_param('eventAction', alert[:event_action])
            parts << "[#{SD_ID_ALERT} #{alert_params.compact.join(' ')}]"

            # MITRE ATT&CK SD element
            if alert[:mitre_tactics] || alert[:mitre_techniques]
              mitre_params = []
              mitre_params << sd_param('tactics', Array(alert[:mitre_tactics]).join(','))
              mitre_params << sd_param('techniques', Array(alert[:mitre_techniques]).join(','))
              parts << "[#{SD_ID_MITRE} #{mitre_params.compact.join(' ')}]"
            end

            # Source context SD element
            source_params = []
            source_params << sd_param('ip', alert[:source_ip])
            source_params << sd_param('port', alert[:source_port])
            source_params << sd_param('hostname', alert[:source_hostname])
            source_params << sd_param('user', alert[:source_user])
            filtered = source_params.compact
            parts << "[#{SD_ID_SOURCE} #{filtered.join(' ')}]" unless filtered.empty?

            parts.empty? ? '-' : parts.join('')
          end

          def sd_param(name, value)
            return nil if value.nil? || value.to_s.empty?

            escaped = value.to_s
                          .gsub('\\', '\\\\')
                          .gsub('"', '\\"')
                          .gsub(']', '\\]')
            "#{name}=\"#{escaped}\""
          end

          def build_message(alert)
            parts = []
            parts << "rule=#{alert[:rule_name]}"
            parts << "severity=#{alert[:severity]}"
            parts << "src=#{alert[:source_ip]}" if alert[:source_ip]
            parts << "dst=#{alert[:dest_ip]}" if alert[:dest_ip]
            parts << "action=#{alert[:event_action]}" if alert[:event_action]
            parts << "process=#{alert[:process_name]}" if alert[:process_name]
            parts << "cmd=#{alert[:command_line]}" if alert[:command_line]
            parts.join(' ')
          end
        end
      end
    end
  end
end
