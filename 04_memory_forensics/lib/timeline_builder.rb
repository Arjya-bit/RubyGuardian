# frozen_string_literal: true

require 'json'
require 'yaml'
require 'time'
require 'csv'

module RubyGuardian
  module MemoryForensics
    # TimelineBuilder constructs forensic timelines from memory artifacts,
    # correlating events from multiple analysis sources into a unified
    # chronological view.
    class TimelineBuilder
      GRANULARITY_MAP = {
        'second' => '%Y-%m-%d %H:%M:%S',
        'minute' => '%Y-%m-%d %H:%M',
        'hour' => '%Y-%m-%d %H:00'
      }.freeze

      TimelineEntry = Struct.new(
        :timestamp, :event_type, :source, :description,
        :severity, :evidence, :address, :tags, keyword_init: true
      )

      Timeline = Struct.new(
        :entries, :start_time, :end_time, :duration,
        :event_counts, :sources, keyword_init: true
      )

      EVENT_TYPES = %i[
        process_start process_exit memory_allocation memory_free
        code_execution code_injection network_connection network_request
        file_access credential_access ioc_detection anomaly_detection
        object_creation object_destruction method_definition
        library_load string_creation dns_query tls_handshake
        heap_modification privilege_escalation data_exfiltration
      ].freeze

      SEVERITY_LEVELS = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }.freeze

      attr_reader :entries, :config, :timezone

      def initialize(config: nil)
        @config = load_config(config)
        @entries = []
        @timezone = @config.dig('timeline', 'timezone') || 'UTC'
        @granularity = @config.dig('timeline', 'granularity') || 'second'
        @time_format = GRANULARITY_MAP[@granularity] || GRANULARITY_MAP['second']
      end

      # Add a single event to the timeline
      def add_event(timestamp:, event_type:, source:, description:, severity: :info, evidence: nil, address: nil, tags: [])
        entry = TimelineEntry.new(
          timestamp: normalize_timestamp(timestamp),
          event_type: event_type,
          source: source,
          description: description,
          severity: severity,
          evidence: evidence,
          address: address,
          tags: Array(tags)
        )

        @entries << entry
        entry
      end

      # Import events from IOC scanner results
      def import_ioc_results(scan_result, dump_timestamp: nil)
        base_time = dump_timestamp || Time.now.utc

        scan_result.matches.each_with_index do |match, idx|
          add_event(
            timestamp: base_time + idx * 0.001, # Sub-second ordering
            event_type: :ioc_detection,
            source: 'ioc_scanner',
            description: "IOC detected: #{match.description} (#{match.rule_name})",
            severity: match.severity,
            evidence: {
              rule: match.rule_name,
              category: match.category,
              matched_data: match.matched_data.to_s[0, 200],
              confidence: match.confidence
            },
            address: match.address,
            tags: [:ioc, match.category].compact
          )
        end
      end

      # Import events from heap analyzer results
      def import_heap_analysis(analysis_result, dump_timestamp: nil)
        base_time = dump_timestamp || Time.now.utc

        (analysis_result[:anomalies] || []).each_with_index do |anomaly, idx|
          add_event(
            timestamp: base_time + idx * 0.001,
            event_type: :anomaly_detection,
            source: 'heap_analyzer',
            description: anomaly[:description] || anomaly['description'],
            severity: (anomaly[:severity] || anomaly['severity'] || :medium).to_sym,
            evidence: anomaly[:evidence] || anomaly['evidence'],
            address: anomaly[:address] || anomaly['address'],
            tags: [:heap, (anomaly[:type] || anomaly['type'])].compact
          )
        end
      end

      # Import events from network artifact extraction
      def import_network_artifacts(extraction_result, dump_timestamp: nil)
        base_time = dump_timestamp || Time.now.utc
        offset = 0

        extraction_result.urls.each do |url|
          add_event(
            timestamp: base_time + (offset += 0.001),
            event_type: :network_request,
            source: 'network_extractor',
            description: "URL found: #{url.url[0, 200]}",
            severity: :info,
            evidence: { url: url.url, host: url.host, port: url.port },
            address: url.address,
            tags: [:network, :url]
          )
        end

        extraction_result.sockets.each do |sock|
          severity = sock.remote_port && ![80, 443].include?(sock.remote_port) ? :medium : :info
          add_event(
            timestamp: base_time + (offset += 0.001),
            event_type: :network_connection,
            source: 'network_extractor',
            description: "Socket: #{sock.remote_addr}:#{sock.remote_port}",
            severity: severity,
            evidence: {
              remote_addr: sock.remote_addr,
              remote_port: sock.remote_port,
              family: sock.family
            },
            address: sock.address,
            tags: [:network, :socket]
          )
        end

        extraction_result.dns_entries.each do |dns|
          add_event(
            timestamp: dns.timestamp || base_time + (offset += 0.001),
            event_type: :dns_query,
            source: 'network_extractor',
            description: "DNS: #{dns.query_name} (#{dns.query_type})",
            severity: :info,
            evidence: { name: dns.query_name, type: dns.query_type, ips: dns.response_ips },
            address: dns.address,
            tags: [:network, :dns]
          )
        end

        extraction_result.tls_artifacts.each do |tls|
          add_event(
            timestamp: base_time + (offset += 0.001),
            event_type: :tls_handshake,
            source: 'network_extractor',
            description: "TLS session: #{tls.server_name || 'unknown'} (#{tls.version})",
            severity: :info,
            evidence: { version: tls.version, sni: tls.server_name },
            address: tls.address,
            tags: [:network, :tls]
          )
        end
      end

      # Import events from code reconstruction
      def import_code_reconstruction(results, dump_timestamp: nil)
        base_time = dump_timestamp || Time.now.utc

        results.each_with_index do |result, idx|
          add_event(
            timestamp: base_time + idx * 0.001,
            event_type: :code_execution,
            source: 'code_reconstructor',
            description: "Reconstructed: #{result.type} `#{result.label}` from #{result.path}",
            severity: :info,
            evidence: {
              type: result.type,
              label: result.label,
              path: result.path,
              confidence: result.confidence,
              source_preview: result.source[0, 200]
            },
            address: result.iseq_address,
            tags: [:code, result.type]
          )
        end
      end

      # Import events from string extraction suspicious findings
      def import_suspicious_strings(suspicious_strings, dump_timestamp: nil)
        base_time = dump_timestamp || Time.now.utc

        suspicious_strings.each_with_index do |entry, idx|
          str = entry[:string]
          add_event(
            timestamp: base_time + idx * 0.001,
            event_type: :ioc_detection,
            source: 'string_extractor',
            description: "Suspicious string: #{str.value[0, 100]}",
            severity: entry[:score] >= 4 ? :high : :medium,
            evidence: {
              value: str.value[0, 200],
              score: entry[:score],
              reasons: entry[:reasons],
              categories: str.categories,
              entropy: str.entropy
            },
            address: str.address,
            tags: [:string, :suspicious]
          )
        end
      end

      # Build the final timeline (sorted chronologically)
      def build
        sorted = @entries.sort_by { |e| [e.timestamp, SEVERITY_LEVELS[e.severity] || 0] }

        event_counts = Hash.new(0)
        sources = Set.new
        sorted.each do |e|
          event_counts[e.event_type] += 1
          sources.add(e.source)
        end

        start_time = sorted.first&.timestamp
        end_time = sorted.last&.timestamp
        duration = start_time && end_time ? end_time - start_time : 0

        Timeline.new(
          entries: sorted,
          start_time: start_time,
          end_time: end_time,
          duration: duration,
          event_counts: event_counts,
          sources: sources.to_a
        )
      end

      # Filter timeline entries
      def filter(event_type: nil, severity: nil, source: nil, tags: nil, time_range: nil)
        filtered = @entries.dup

        filtered.select! { |e| e.event_type == event_type } if event_type
        filtered.select! { |e| e.source == source } if source

        if severity
          min_level = SEVERITY_LEVELS[severity.to_sym] || 0
          filtered.select! { |e| (SEVERITY_LEVELS[e.severity] || 0) >= min_level }
        end

        if tags
          tag_set = Array(tags).map(&:to_sym)
          filtered.select! { |e| (e.tags.map(&:to_sym) & tag_set).any? }
        end

        if time_range
          filtered.select! { |e| e.timestamp >= time_range.first && e.timestamp <= time_range.last }
        end

        filtered
      end

      # Export timeline in various formats
      def export(format: :json, output_path: nil)
        timeline = build

        content = case format.to_sym
                  when :json
                    export_json(timeline)
                  when :csv
                    export_csv(timeline)
                  when :bodyfile
                    export_bodyfile(timeline)
                  when :text
                    export_text(timeline)
                  else
                    raise ArgumentError, "Unknown format: #{format}"
                  end

        if output_path
          FileUtils.mkdir_p(File.dirname(output_path))
          File.write(output_path, content)
        end

        content
      end

      # Generate a summary of the timeline
      def summary
        timeline = build

        severity_counts = Hash.new(0)
        hourly_distribution = Hash.new(0)
        tag_counts = Hash.new(0)

        timeline.entries.each do |e|
          severity_counts[e.severity] += 1
          hour_key = e.timestamp.strftime('%Y-%m-%d %H:00') rescue 'unknown'
          hourly_distribution[hour_key] += 1
          e.tags.each { |t| tag_counts[t] += 1 }
        end

        {
          total_events: timeline.entries.size,
          start_time: timeline.start_time&.iso8601,
          end_time: timeline.end_time&.iso8601,
          duration_seconds: timeline.duration,
          event_type_counts: timeline.event_counts,
          severity_counts: severity_counts,
          sources: timeline.sources,
          hourly_distribution: hourly_distribution,
          top_tags: tag_counts.sort_by { |_, v| -v }.first(10).to_h,
          critical_events: timeline.entries.count { |e| e.severity == :critical },
          high_events: timeline.entries.count { |e| e.severity == :high }
        }
      end

      private

      def normalize_timestamp(ts)
        case ts
        when Time
          ts.utc
        when String
          Time.parse(ts).utc
        when Numeric
          Time.at(ts).utc
        when nil
          Time.now.utc
        else
          ts.respond_to?(:to_time) ? ts.to_time.utc : Time.now.utc
        end
      end

      def export_json(timeline)
        data = {
          timeline: {
            metadata: {
              start_time: timeline.start_time&.iso8601,
              end_time: timeline.end_time&.iso8601,
              duration: timeline.duration,
              total_events: timeline.entries.size,
              sources: timeline.sources,
              generated_at: Time.now.utc.iso8601
            },
            events: timeline.entries.map { |e| entry_to_hash(e) }
          }
        }
        JSON.pretty_generate(data)
      end

      def export_csv(timeline)
        CSV.generate do |csv|
          csv << %w[timestamp event_type source severity description address tags]
          timeline.entries.each do |e|
            csv << [
              e.timestamp.iso8601,
              e.event_type,
              e.source,
              e.severity,
              e.description,
              e.address ? "0x#{e.address.to_s(16)}" : '',
              e.tags.join(';')
            ]
          end
        end
      end

      def export_bodyfile(timeline)
        # Bodyfile format: MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
        lines = timeline.entries.map do |e|
          ts = e.timestamp.to_i
          description = "#{e.event_type}|#{e.source}|#{e.description}".gsub('|', '-')
          "0|#{description}|0|#{e.severity}|0|0|0|#{ts}|#{ts}|#{ts}|#{ts}"
        end
        lines.join("\n")
      end

      def export_text(timeline)
        lines = ["FORENSIC TIMELINE", "=" * 60, ""]
        lines << "Period: #{timeline.start_time&.iso8601} - #{timeline.end_time&.iso8601}"
        lines << "Total Events: #{timeline.entries.size}"
        lines << ""

        timeline.entries.each do |e|
          severity_marker = case e.severity
                            when :critical then '[!!!]'
                            when :high then '[!! ]'
                            when :medium then '[!  ]'
                            when :low then '[.  ]'
                            else '[   ]'
                            end

          addr_str = e.address ? " @ 0x#{e.address.to_s(16)}" : ''
          lines << "#{e.timestamp.strftime(@time_format)} #{severity_marker} [#{e.source}] #{e.description}#{addr_str}"
        end

        lines.join("\n")
      end

      def entry_to_hash(entry)
        {
          timestamp: entry.timestamp.iso8601(3),
          event_type: entry.event_type.to_s,
          source: entry.source,
          description: entry.description,
          severity: entry.severity.to_s,
          evidence: entry.evidence,
          address: entry.address ? "0x#{entry.address.to_s(16)}" : nil,
          tags: entry.tags.map(&:to_s)
        }
      end

      def load_config(config)
        return config if config.is_a?(Hash)

        path = config || File.join(__dir__, '..', 'config', 'forensics_config.yml')
        File.exist?(path) ? YAML.safe_load(File.read(path)) : {}
      end
    end
  end
end
