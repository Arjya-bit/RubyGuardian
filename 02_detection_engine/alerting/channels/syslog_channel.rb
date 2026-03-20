# frozen_string_literal: true

require 'socket'
require 'timeout'

module RubyGuardian
  module DetectionEngine
    module Alerting
      module Channels
        # Sends formatted alert messages via syslog protocol over UDP or TCP.
        # Supports RFC 5424 transport with optional TLS for TCP connections.
        # Includes connection pooling for TCP and automatic reconnection logic.
        class SyslogChannel
          DEFAULT_PORT       = 514
          TCP_CONNECT_TIMEOUT = 5
          TCP_SEND_TIMEOUT    = 10
          MAX_UDP_PAYLOAD     = 65_507
          MAX_RETRIES         = 3
          RECONNECT_DELAY     = 1.0

          attr_reader :config, :stats

          def initialize(config = {})
            @config = {
              host:       config.fetch(:host, '127.0.0.1'),
              port:       config.fetch(:port, DEFAULT_PORT),
              protocol:   config.fetch(:protocol, :udp).to_sym,
              tls:        config.fetch(:tls, false),
              tls_cert:   config.fetch(:tls_cert, nil),
              tls_key:    config.fetch(:tls_key, nil),
              tls_ca:     config.fetch(:tls_ca, nil),
              tls_verify: config.fetch(:tls_verify, true),
              tcp_keepalive: config.fetch(:tcp_keepalive, true),
              framing:    config.fetch(:framing, :octet_counting).to_sym  # :octet_counting or :newline
            }
            @socket = nil
            @mutex = Mutex.new
            @stats = { sent: 0, failed: 0, reconnects: 0, bytes_sent: 0 }

            validate_config!
          end

          # Send a single formatted alert via syslog.
          #
          # @param formatted_alert [String] pre-formatted syslog message
          def send_alert(formatted_alert)
            @mutex.synchronize do
              case @config[:protocol]
              when :udp then send_udp(formatted_alert)
              when :tcp then send_tcp(formatted_alert)
              else raise ConfigError, "Unsupported protocol: #{@config[:protocol]}"
              end
              @stats[:sent] += 1
            end
          rescue StandardError => e
            @stats[:failed] += 1
            raise TransportError, "Syslog send failed: #{e.message}"
          end

          # Send a batch of alerts, one per syslog message.
          #
          # @param alerts [Array<String>] pre-formatted syslog messages
          def send_batch(alerts)
            alerts.each { |alert| send_alert(alert) }
          end

          # Check if the syslog server is reachable.
          #
          # @return [Hash] connection status
          def health_check
            case @config[:protocol]
            when :udp
              { status: 'ok', protocol: 'udp', note: 'UDP is connectionless; cannot verify' }
            when :tcp
              ensure_tcp_connection
              { status: 'ok', protocol: 'tcp', host: @config[:host], port: @config[:port] }
            end
          rescue StandardError => e
            { status: 'error', error: e.message }
          end

          # Close open connections.
          def close
            @mutex.synchronize do
              @socket&.close rescue nil
              @socket = nil
            end
          end

          private

          def validate_config!
            unless %i[udp tcp].include?(@config[:protocol])
              raise ConfigError, "Protocol must be :udp or :tcp, got #{@config[:protocol]}"
            end

            if @config[:tls] && @config[:protocol] != :tcp
              raise ConfigError, 'TLS is only supported with TCP protocol'
            end
          end

          def send_udp(message)
            payload = message.bytesize > MAX_UDP_PAYLOAD ? message.byteslice(0, MAX_UDP_PAYLOAD) : message
            socket = udp_socket
            socket.send(payload, 0, @config[:host], @config[:port])
            @stats[:bytes_sent] += payload.bytesize
          end

          def send_tcp(message)
            retries = 0
            begin
              ensure_tcp_connection
              framed = frame_message(message)
              @socket.write(framed)
              @stats[:bytes_sent] += framed.bytesize
            rescue IOError, Errno::ECONNRESET, Errno::EPIPE, Errno::ENOTCONN => e
              @socket&.close rescue nil
              @socket = nil
              retries += 1
              if retries <= MAX_RETRIES
                @stats[:reconnects] += 1
                sleep(RECONNECT_DELAY)
                retry
              end
              raise TransportError, "TCP send failed after #{MAX_RETRIES} retries: #{e.message}"
            end
          end

          def frame_message(message)
            case @config[:framing]
            when :octet_counting
              "#{message.bytesize} #{message}"
            when :newline
              "#{message}\n"
            else
              "#{message}\n"
            end
          end

          def udp_socket
            @socket ||= UDPSocket.new
          end

          def ensure_tcp_connection
            return if @socket && !@socket.closed?

            Timeout.timeout(TCP_CONNECT_TIMEOUT) do
              if @config[:tls]
                @socket = create_tls_socket
              else
                @socket = TCPSocket.new(@config[:host], @config[:port])
              end
            end

            configure_tcp_options(@socket) unless @config[:tls]
          end

          def create_tls_socket
            require 'openssl'

            tcp = TCPSocket.new(@config[:host], @config[:port])
            configure_tcp_options(tcp)

            ctx = OpenSSL::SSL::SSLContext.new
            ctx.verify_mode = @config[:tls_verify] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

            if @config[:tls_cert] && @config[:tls_key]
              ctx.cert = OpenSSL::X509::Certificate.new(File.read(@config[:tls_cert]))
              ctx.key = OpenSSL::PKey::RSA.new(File.read(@config[:tls_key]))
            end

            ctx.ca_file = @config[:tls_ca] if @config[:tls_ca]

            ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
            ssl.hostname = @config[:host]
            ssl.connect
            ssl
          end

          def configure_tcp_options(socket)
            if @config[:tcp_keepalive] && socket.respond_to?(:setsockopt)
              socket.setsockopt(Socket::SOL_SOCKET, Socket::SO_KEEPALIVE, true)
            end
            socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, true) if socket.respond_to?(:setsockopt)
          end
        end

        class TransportError < StandardError; end
        class ConfigError < StandardError; end
      end
    end
  end
end
