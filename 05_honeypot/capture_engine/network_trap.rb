# frozen_string_literal: true

require "json"
require "socket"
require "logger"
require "digest"

module RubyGuardian
  module Honeypot
    module CaptureEngine
      # NetworkTrap intercepts all network connection attempts made by analyzed
      # scripts. It patches TCPSocket, UDPSocket, Net::HTTP, and common HTTP
      # client libraries to capture destination, port, protocol, and payload data.
      class NetworkTrap
        KNOWN_EXFIL_PORTS = [53, 80, 443, 8080, 8443, 4444, 1337, 9001].freeze
        DNS_QUERY_PORT = 53

        attr_reader :captures, :started_at

        def initialize(log_dir:, sample_id:, logger: nil)
          @log_dir = log_dir
          @sample_id = sample_id
          @logger = logger || default_logger
          @captures = []
          @started_at = nil
          @mutex = Mutex.new
          @original_methods = {}
          @dns_queries = []
        end

        # Activate network traps.
        def activate!
          @started_at = Time.now.utc
          @logger.info("[NetworkTrap] Activating network traps for sample #{@sample_id}")

          trap_tcp_socket
          trap_udp_socket
          trap_net_http
          trap_socket_getaddrinfo

          self
        end

        # Deactivate traps and restore originals.
        def deactivate!
          @logger.info("[NetworkTrap] Deactivating network traps for sample #{@sample_id}")
          restore_original_methods
          flush_captures
          self
        end

        # Record a captured network connection attempt.
        def record(protocol:, destination:, port:, details: {}, caller_location: nil)
          entry = {
            timestamp: Time.now.utc.iso8601(6),
            sample_id: @sample_id,
            protocol: protocol.to_s,
            destination: destination.to_s,
            port: port.to_i,
            is_known_exfil_port: KNOWN_EXFIL_PORTS.include?(port.to_i),
            details: sanitize_details(details),
            caller_location: caller_location || extract_caller,
            elapsed_ms: elapsed_ms,
            pid: Process.pid
          }

          @mutex.synchronize { @captures << entry }

          severity = entry[:is_known_exfil_port] ? :error : :warn
          @logger.send(severity, "[NetworkTrap] #{protocol.upcase} -> #{destination}:#{port}")
          entry
        end

        # Record a DNS resolution attempt.
        def record_dns(hostname:, caller_location: nil)
          entry = {
            timestamp: Time.now.utc.iso8601(6),
            sample_id: @sample_id,
            type: :dns_resolution,
            hostname: hostname.to_s,
            caller_location: caller_location || extract_caller,
            elapsed_ms: elapsed_ms
          }

          @mutex.synchronize { @dns_queries << entry }
          @logger.warn("[NetworkTrap] DNS lookup: #{hostname}")
          entry
        end

        # Summary statistics.
        def summary
          {
            sample_id: @sample_id,
            total_connections: @captures.size,
            dns_queries: @dns_queries.size,
            unique_destinations: @captures.map { |c| c[:destination] }.uniq,
            unique_ports: @captures.map { |c| c[:port] }.uniq.sort,
            protocols_used: @captures.map { |c| c[:protocol] }.tally,
            exfil_port_hits: @captures.count { |c| c[:is_known_exfil_port] },
            unique_hostnames: @dns_queries.map { |d| d[:hostname] }.uniq,
            connection_timeline: @captures.map { |c| { time: c[:timestamp], dest: "#{c[:destination]}:#{c[:port]}", proto: c[:protocol] } }
          }
        end

        # Flush all captures to disk.
        def flush_captures
          return if @captures.empty? && @dns_queries.empty?

          output_path = File.join(@log_dir, "network_captures_#{@sample_id}.json")
          File.write(output_path, JSON.pretty_generate(report_data))
          @logger.info("[NetworkTrap] Flushed #{@captures.size} network captures and #{@dns_queries.size} DNS queries")
        end

        private

        def trap_tcp_socket
          trap = self
          @original_methods[:tcp_new] = TCPSocket.method(:new)

          TCPSocket.define_singleton_method(:new) do |host, port, *args|
            trap.record(
              protocol: :tcp,
              destination: host,
              port: port,
              details: { method: "TCPSocket.new", args_count: args.size },
              caller_location: caller_locations(1, 1).first.to_s
            )
            # Return a fake socket that captures sent data
            trap.send(:create_fake_tcp_socket, host, port)
          end

          # Also trap TCPSocket#initialize for inherited usage
          @original_methods[:tcp_open] = TCPSocket.method(:open) if TCPSocket.respond_to?(:open)
          TCPSocket.define_singleton_method(:open) do |host, port, *args|
            trap.record(
              protocol: :tcp,
              destination: host,
              port: port,
              details: { method: "TCPSocket.open" },
              caller_location: caller_locations(1, 1).first.to_s
            )
            trap.send(:create_fake_tcp_socket, host, port)
          end
        end

        def trap_udp_socket
          trap = self
          original_send = UDPSocket.instance_method(:send)
          @original_methods[:udp_send] = original_send

          UDPSocket.define_method(:send) do |data, flags, *dest|
            host = dest[0] || "unknown"
            port = dest[1] || 0
            trap.record(
              protocol: :udp,
              destination: host,
              port: port,
              details: {
                method: "UDPSocket#send",
                payload_size: data.bytesize,
                payload_sha256: Digest::SHA256.hexdigest(data),
                payload_preview: data[0..128]&.force_encoding("UTF-8")&.scrub("?")
              },
              caller_location: caller_locations(1, 1).first.to_s
            )
            data.bytesize # Pretend we sent it
          end
        end

        def trap_net_http
          return unless defined?(Net::HTTP)

          trap = self
          @original_methods[:net_http_start] = Net::HTTP.method(:start)

          Net::HTTP.define_singleton_method(:start) do |address, port = nil, *args, &block|
            port ||= 443
            trap.record(
              protocol: :http,
              destination: address,
              port: port,
              details: { method: "Net::HTTP.start", use_ssl: port == 443 },
              caller_location: caller_locations(1, 1).first.to_s
            )
            # Return a mock that captures request details
            mock = trap.send(:create_fake_http, address, port)
            block ? block.call(mock) : mock
          end
        end

        def trap_socket_getaddrinfo
          trap = self
          @original_methods[:getaddrinfo] = Socket.method(:getaddrinfo)

          Socket.define_singleton_method(:getaddrinfo) do |host, *args|
            trap.record_dns(hostname: host, caller_location: caller_locations(1, 1).first.to_s)
            # Return localhost to prevent real resolution
            [["AF_INET", 0, "localhost", "127.0.0.1", 2, 1, 6]]
          end
        end

        def create_fake_tcp_socket(_host, _port)
          StringIO.new("").tap do |io|
            io.define_singleton_method(:write) { |data| data.bytesize }
            io.define_singleton_method(:send) { |data, *_args| data.bytesize }
            io.define_singleton_method(:recv) { |_len| "" }
            io.define_singleton_method(:close) { nil }
            io.define_singleton_method(:closed?) { false }
            io.define_singleton_method(:setsockopt) { |*_args| 0 }
          end
        end

        def create_fake_http(address, port)
          Object.new.tap do |mock|
            mock.define_singleton_method(:address) { address }
            mock.define_singleton_method(:port) { port }
            mock.define_singleton_method(:request) do |req|
              Struct.new(:code, :body, :header).new("200", "", {})
            end
            mock.define_singleton_method(:get) { |*_| "" }
            mock.define_singleton_method(:post) { |*_| Struct.new(:code, :body).new("200", "") }
            mock.define_singleton_method(:finish) { nil }
          end
        end

        def restore_original_methods
          if @original_methods[:tcp_new]
            TCPSocket.define_singleton_method(:new, @original_methods[:tcp_new])
          end
          if @original_methods[:tcp_open]
            TCPSocket.define_singleton_method(:open, @original_methods[:tcp_open])
          end
          if @original_methods[:udp_send]
            UDPSocket.define_method(:send, @original_methods[:udp_send])
          end
          if @original_methods[:net_http_start] && defined?(Net::HTTP)
            Net::HTTP.define_singleton_method(:start, @original_methods[:net_http_start])
          end
          if @original_methods[:getaddrinfo]
            Socket.define_singleton_method(:getaddrinfo, @original_methods[:getaddrinfo])
          end
          @original_methods.clear
        end

        def sanitize_details(details)
          details.transform_values do |v|
            case v
            when String
              v.bytesize > 4096 ? "#{v[0..4095]}... (truncated, #{v.bytesize} bytes)" : v
            else
              v
            end
          end
        end

        def extract_caller
          caller_locations(3, 1).first&.to_s || "unknown"
        end

        def elapsed_ms
          return 0 unless @started_at
          ((Time.now.utc - @started_at) * 1000).round(2)
        end

        def report_data
          {
            sample_id: @sample_id,
            started_at: @started_at&.iso8601,
            ended_at: Time.now.utc.iso8601,
            summary: summary,
            connections: @captures,
            dns_queries: @dns_queries
          }
        end

        def default_logger
          Logger.new($stdout, progname: "RubyGuardian::NetworkTrap")
        end
      end
    end
  end
end
