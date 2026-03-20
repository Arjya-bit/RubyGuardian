# frozen_string_literal: true

require 'net/http'
require 'uri'
require 'json'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Channels
        # Sends alerts to Slack via incoming webhook with severity-based
        # color coding, rich Block Kit formatting, and rate limiting.
        class SlackChannel
          SLACK_COLORS = {
            'critical' => '#FF0000',
            'high'     => '#FF6600',
            'medium'   => '#FFAA00',
            'low'      => '#0066FF',
            'info'     => '#999999'
          }.freeze

          SEVERITY_EMOJI = {
            'critical' => ':rotating_light:',
            'high'     => ':warning:',
            'medium'   => ':large_orange_diamond:',
            'low'      => ':large_blue_diamond:',
            'info'     => ':information_source:'
          }.freeze

          DEFAULT_RATE_LIMIT  = 1.0  # seconds between messages
          DEFAULT_TIMEOUT     = 15
          MAX_RETRIES         = 2

          attr_reader :config, :stats

          def initialize(config = {})
            @config = {
              webhook_url:   config.fetch(:webhook_url),
              channel:       config.fetch(:channel, nil),
              username:      config.fetch(:username, 'RubyGuardian'),
              icon_emoji:    config.fetch(:icon_emoji, ':shield:'),
              min_severity:  config.fetch(:min_severity, 'low'),
              rate_limit:    config.fetch(:rate_limit, DEFAULT_RATE_LIMIT),
              timeout:       config.fetch(:timeout, DEFAULT_TIMEOUT),
              mention_users: config.fetch(:mention_users, {}),
              mention_channel_on: config.fetch(:mention_channel_on, ['critical'])
            }
            @last_send_time = Time.at(0)
            @mutex = Mutex.new
            @stats = { sent: 0, dropped: 0, failed: 0, rate_limited: 0 }
            @severity_order = %w[info low medium high critical]
          end

          # Send an alert to Slack.
          #
          # @param alert [Hash] alert data (not pre-formatted; uses raw alert hash)
          def send_alert(alert)
            severity = alert[:severity].to_s.downcase

            unless meets_severity_threshold?(severity)
              @stats[:dropped] += 1
              return
            end

            payload = build_payload(alert)

            @mutex.synchronize do
              enforce_rate_limit
              post_to_slack(payload)
              @stats[:sent] += 1
              @last_send_time = Time.now
            end
          rescue RateLimitError
            @stats[:rate_limited] += 1
          rescue StandardError => e
            @stats[:failed] += 1
            raise SlackDeliveryError, "Failed to send Slack alert: #{e.message}"
          end

          # Send a summary of multiple alerts as a single Slack message.
          #
          # @param alerts [Array<Hash>] alert data
          def send_summary(alerts)
            return if alerts.empty?

            grouped = alerts.group_by { |a| a[:severity].to_s.downcase }
            payload = build_summary_payload(grouped, alerts.size)

            @mutex.synchronize do
              enforce_rate_limit
              post_to_slack(payload)
              @stats[:sent] += 1
              @last_send_time = Time.now
            end
          end

          private

          def meets_severity_threshold?(severity)
            @severity_order.index(severity).to_i >= @severity_order.index(@config[:min_severity]).to_i
          end

          def enforce_rate_limit
            elapsed = Time.now - @last_send_time
            if elapsed < @config[:rate_limit]
              sleep_time = @config[:rate_limit] - elapsed
              sleep(sleep_time)
            end
          end

          def build_payload(alert)
            severity = alert[:severity].to_s.downcase
            emoji = SEVERITY_EMOJI.fetch(severity, ':question:')
            color = SLACK_COLORS.fetch(severity, '#999999')

            mentions = build_mentions(severity)

            payload = {
              username: @config[:username],
              icon_emoji: @config[:icon_emoji]
            }
            payload[:channel] = @config[:channel] if @config[:channel]

            payload[:attachments] = [{
              color: color,
              fallback: "#{emoji} [#{severity.upcase}] #{alert[:rule_name]}",
              blocks: build_alert_blocks(alert, emoji, mentions)
            }]

            payload
          end

          def build_alert_blocks(alert, emoji, mentions)
            severity = alert[:severity].to_s.upcase
            blocks = []

            # Header
            header_text = "#{emoji} *#{severity} Alert: #{alert[:rule_name]}*"
            header_text = "#{mentions} #{header_text}" unless mentions.empty?
            blocks << { type: 'section', text: { type: 'mrkdwn', text: header_text } }

            # Rule details
            if alert[:rule_description]
              blocks << { type: 'section', text: { type: 'mrkdwn', text: "> #{alert[:rule_description]}" } }
            end

            # Fields
            fields = []
            fields << field('Rule ID', "`#{alert[:rule_id]}`") if alert[:rule_id]
            fields << field('Source IP', "`#{alert[:source_ip]}`") if alert[:source_ip]
            fields << field('Destination', "`#{alert[:dest_ip]}`") if alert[:dest_ip]
            fields << field('Event Type', alert[:event_type]) if alert[:event_type]
            fields << field('Process', "`#{alert[:process_name]}`") if alert[:process_name]
            fields << field('User', alert[:source_user]) if alert[:source_user]

            fields.each_slice(2) do |pair|
              blocks << { type: 'section', fields: pair }
            end

            # MITRE ATT&CK
            if alert[:mitre_tactics] || alert[:mitre_techniques]
              mitre_parts = []
              mitre_parts << "Tactics: #{Array(alert[:mitre_tactics]).join(', ')}" if alert[:mitre_tactics]
              mitre_parts << "Techniques: #{Array(alert[:mitre_techniques]).join(', ')}" if alert[:mitre_techniques]
              blocks << { type: 'context', elements: [{ type: 'mrkdwn', text: mitre_parts.join(' | ') }] }
            end

            # Timestamp
            ts = alert[:timestamp] || Time.now
            blocks << { type: 'context', elements: [{ type: 'mrkdwn', text: "Detected at: #{ts.utc.iso8601}" }] }

            blocks
          end

          def build_summary_payload(grouped, total)
            lines = ["*Alert Summary* (#{total} alerts)"]
            @severity_order.reverse.each do |sev|
              next unless grouped[sev]
              emoji = SEVERITY_EMOJI[sev]
              lines << "#{emoji} *#{sev.upcase}*: #{grouped[sev].size}"
            end

            {
              username: @config[:username],
              icon_emoji: @config[:icon_emoji],
              channel: @config[:channel],
              text: lines.join("\n")
            }.compact
          end

          def build_mentions(severity)
            parts = []
            if @config[:mention_channel_on].include?(severity)
              parts << '<!channel>'
            end
            if @config[:mention_users][severity]
              Array(@config[:mention_users][severity]).each { |u| parts << "<@#{u}>" }
            end
            parts.join(' ')
          end

          def field(label, value)
            { type: 'mrkdwn', text: "*#{label}:*\n#{value}" }
          end

          def post_to_slack(payload)
            uri = URI.parse(@config[:webhook_url])
            retries = 0

            begin
              http = Net::HTTP.new(uri.host, uri.port)
              http.use_ssl = (uri.scheme == 'https')
              http.open_timeout = @config[:timeout]
              http.read_timeout = @config[:timeout]

              request = Net::HTTP::Post.new(uri.path)
              request['Content-Type'] = 'application/json'
              request.body = JSON.generate(payload)

              response = http.request(request)

              unless response.code.to_i == 200
                raise SlackDeliveryError, "Slack returned HTTP #{response.code}: #{response.body}"
              end
            rescue Net::OpenTimeout, Net::ReadTimeout => e
              retries += 1
              retry if retries <= MAX_RETRIES
              raise SlackDeliveryError, "Slack timeout after #{MAX_RETRIES} retries: #{e.message}"
            end
          end
        end

        class SlackDeliveryError < StandardError; end
        class RateLimitError < StandardError; end
      end
    end
  end
end
