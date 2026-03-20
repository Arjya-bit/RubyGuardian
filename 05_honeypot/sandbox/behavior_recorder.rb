# frozen_string_literal: true

require "json"
require "digest"
require "fileutils"
require "logger"

module RubyGuardian
  module Honeypot
    module Sandbox
      # BehaviorRecorder observes and records all observable behaviors during
      # sandbox execution. It aggregates data from exec, file, credential,
      # and network traps into a unified timeline with categorized events.
      class BehaviorRecorder
        EVENT_CATEGORIES = %i[
          process_execution file_access file_modification file_deletion
          credential_access network_connection dns_resolution
          environment_access permission_change suspicious_pattern
        ].freeze

        SEVERITY_LEVELS = { low: 1, medium: 2, high: 3, critical: 4 }.freeze

        attr_reader :events, :sample_id, :started_at

        def initialize(sample_id:, output_dir:, logger: nil)
          @sample_id = sample_id
          @output_dir = output_dir
          @logger = logger || default_logger
          @events = []
          @started_at = nil
          @ended_at = nil
          @mutex = Mutex.new
          @tags = Set.new
          @ioc_list = []
        end

        # Start recording behaviors.
        def start!
          @started_at = Time.now.utc
          @logger.info("[BehaviorRecorder] Recording started for sample #{@sample_id}")
          self
        end

        # Stop recording and finalize.
        def stop!
          @ended_at = Time.now.utc
          @logger.info("[BehaviorRecorder] Recording stopped for sample #{@sample_id} (#{@events.size} events)")
          generate_outputs
          self
        end

        # Record a single behavioral event.
        def record_event(category:, description:, severity: :medium, details: {}, source: nil)
          raise "Recording not started" unless @started_at
          raise "Unknown category: #{category}" unless EVENT_CATEGORIES.include?(category)

          event = {
            id: @events.size + 1,
            timestamp: Time.now.utc.iso8601(6),
            elapsed_ms: elapsed_ms,
            category: category,
            severity: severity,
            severity_score: SEVERITY_LEVELS[severity] || 2,
            description: description,
            details: details,
            source: source || "unknown"
          }

          @mutex.synchronize { @events << event }

          auto_tag(event)
          auto_extract_iocs(event)

          log_event(event)
          event
        end

        # Import events from a capture engine trap (exec, file, network, credential).
        def import_from_trap(trap_instance)
          trap_type = trap_instance.class.name.split("::").last.downcase
          captures = trap_instance.respond_to?(:captures) ? trap_instance.captures : []

          captures.each do |capture|
            category, severity = classify_trap_capture(trap_type, capture)
            record_event(
              category: category,
              description: format_capture_description(trap_type, capture),
              severity: severity,
              details: capture,
              source: trap_type
            )
          end

          @logger.info("[BehaviorRecorder] Imported #{captures.size} events from #{trap_type}")
        end

        # Generate the full behavioral timeline.
        def timeline
          @events.sort_by { |e| e[:timestamp] }.map do |event|
            {
              time: event[:timestamp],
              elapsed_ms: event[:elapsed_ms],
              category: event[:category],
              severity: event[:severity],
              description: event[:description]
            }
          end
        end

        # Generate summary statistics.
        def summary
          {
            sample_id: @sample_id,
            started_at: @started_at&.iso8601,
            ended_at: @ended_at&.iso8601,
            duration_seconds: duration_seconds,
            total_events: @events.size,
            events_by_category: @events.group_by { |e| e[:category] }.transform_values(&:size),
            events_by_severity: @events.group_by { |e| e[:severity] }.transform_values(&:size),
            max_severity: max_severity,
            risk_score: calculate_risk_score,
            tags: @tags.to_a.sort,
            ioc_count: @ioc_list.size,
            iocs: @ioc_list
          }
        end

        private

        def generate_outputs
          FileUtils.mkdir_p(@output_dir)

          # Full event log
          write_json("behavior_events_#{@sample_id}.json", {
            sample_id: @sample_id, events: @events
          })

          # Timeline
          write_json("behavior_timeline_#{@sample_id}.json", {
            sample_id: @sample_id, timeline: timeline
          })

          # Summary report
          write_json("behavior_summary_#{@sample_id}.json", summary)

          # IOCs
          write_json("behavior_iocs_#{@sample_id}.json", {
            sample_id: @sample_id, iocs: @ioc_list
          })

          @logger.info("[BehaviorRecorder] Generated outputs in #{@output_dir}")
        end

        def classify_trap_capture(trap_type, capture)
          case trap_type
          when /exec/
            cmd = capture[:command].to_s
            severity = if cmd.match?(/curl|wget|nc|ncat|bash -c|eval|base64/)
                         :critical
                       elsif cmd.match?(/chmod|chown|rm -rf|kill/)
                         :high
                       else
                         :medium
                       end
            [:process_execution, severity]
          when /file/
            op = capture[:operation].to_s
            if capture[:is_sensitive]
              [:credential_access, :critical]
            elsif op == "write" || op == "delete"
              [:file_modification, :high]
            else
              [:file_access, :low]
            end
          when /network/
            if capture[:is_known_exfil_port]
              [:network_connection, :critical]
            else
              [:network_connection, :high]
            end
          when /credential/
            [:credential_access, :critical]
          else
            [:suspicious_pattern, :medium]
          end
        end

        def format_capture_description(trap_type, capture)
          case trap_type
          when /exec/    then "Executed command: #{capture[:command]} #{Array(capture[:args]).join(' ')}".strip
          when /file/    then "File #{capture[:operation]}: #{capture[:path]}"
          when /network/ then "Network connection to #{capture[:destination]}:#{capture[:port]} (#{capture[:protocol]})"
          when /cred/    then "Credential access: #{capture[:token_name]} (#{capture[:access_type]})"
          else "Unknown trap event from #{trap_type}"
          end
        end

        def auto_tag(event)
          desc = event[:description].to_s.downcase
          details = event[:details].to_s.downcase

          @tags << "data_exfiltration" if desc.match?(/curl|wget|nc |ncat/) || event[:category] == :network_connection
          @tags << "credential_theft"  if event[:category] == :credential_access
          @tags << "persistence"       if desc.match?(/cron|systemd|\.bashrc|\.profile|authorized_keys/)
          @tags << "defense_evasion"   if desc.match?(/rm -rf|unset.*hist|kill.*audit/)
          @tags << "reconnaissance"    if desc.match?(/uname|whoami|id |hostname|ifconfig|env/)
          @tags << "crypto_mining"     if details.match?(/xmrig|stratum|mining|monero/)
          @tags << "reverse_shell"     if details.match?(/\/dev\/tcp|bash -i|nc -e|ncat/)
          @tags << "code_injection"    if desc.match?(/eval|instance_eval|class_eval|send\(/)
        end

        def auto_extract_iocs(event)
          text = "#{event[:description]} #{event[:details]}"

          # Extract IPs
          text.scan(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/).flatten.each do |ip|
            next if ip.start_with?("127.", "10.", "192.168.", "172.")
            @ioc_list << { type: :ip, value: ip, event_id: event[:id] }
          end

          # Extract domains
          text.scan(/\b([a-z0-9][-a-z0-9]*\.[a-z]{2,}(?:\.[a-z]{2,})?)\b/).flatten.each do |domain|
            next if domain.match?(/example\.com|localhost|internal/)
            @ioc_list << { type: :domain, value: domain, event_id: event[:id] }
          end

          # Extract URLs
          text.scan(%r{https?://[^\s"'<>]+}).each do |url|
            @ioc_list << { type: :url, value: url, event_id: event[:id] }
          end

          @ioc_list.uniq! { |ioc| [ioc[:type], ioc[:value]] }
        end

        def calculate_risk_score
          return 0 if @events.empty?

          total = @events.sum { |e| SEVERITY_LEVELS[e[:severity]] || 0 }
          category_diversity = @events.map { |e| e[:category] }.uniq.size
          critical_count = @events.count { |e| e[:severity] == :critical }

          base_score = [total.to_f / @events.size * 25, 100].min
          diversity_bonus = [category_diversity * 5, 25].min
          critical_bonus = [critical_count * 10, 50].min

          [base_score + diversity_bonus + critical_bonus, 100].min.round(1)
        end

        def max_severity
          return :none if @events.empty?
          @events.max_by { |e| SEVERITY_LEVELS[e[:severity]] || 0 }[:severity]
        end

        def elapsed_ms
          return 0 unless @started_at
          ((Time.now.utc - @started_at) * 1000).round(2)
        end

        def duration_seconds
          return 0 unless @started_at && @ended_at
          (@ended_at - @started_at).round(2)
        end

        def write_json(filename, data)
          path = File.join(@output_dir, filename)
          File.write(path, JSON.pretty_generate(data))
        end

        def log_event(event)
          method = event[:severity] == :critical ? :error : (event[:severity] == :high ? :warn : :info)
          @logger.send(method, "[BehaviorRecorder] [#{event[:severity]}] #{event[:description]}")
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::BehaviorRecorder")
        end
      end
    end
  end
end
