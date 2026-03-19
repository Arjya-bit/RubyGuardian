# frozen_string_literal: true

# =============================================================================
# RubyGuardian - LoLRuby Phase 1c
# Technique: Service Enumeration
# LoLRuby ID: LR-R-002, LR-R-003
# MITRE ATT&CK: T1046 - Network Service Discovery
# =============================================================================
#
# EDUCATIONAL PURPOSE ONLY
# Demonstrates service fingerprinting using Ruby's socket and HTTP libraries.
# Service enumeration goes beyond port scanning to identify specific software
# versions and configurations running on discovered services.
#
# DETECTION METHODS:
# - Watch for Ruby processes making probe requests (OPTIONS, HEAD, malformed)
# - IDS signatures for version-probing request patterns
# - Monitor for sequential connections with varying protocol handshakes
# - Anomaly detection on Ruby process network behavior
# =============================================================================

require 'socket'
require 'net/http'
require 'net/smtp'
require 'openssl'
require 'timeout'
require 'json'
require 'logger'

module RubyGuardian
  module LoLRuby
    module Reconnaissance
      class ServiceEnum
        # Protocol-specific probe strings
        # Educational: These are the initial bytes that trigger service responses
        PROBES = {
          http:   "HEAD / HTTP/1.0\r\nHost: %{host}\r\n\r\n",
          ftp:    nil,  # FTP sends banner on connect
          ssh:    nil,  # SSH sends banner on connect
          smtp:   nil,  # SMTP sends banner on connect
          mysql:  nil,  # MySQL sends greeting on connect
          redis:  "PING\r\n",
          mongo:  nil,  # MongoDB wire protocol
          pop3:   nil,  # POP3 sends banner on connect
          imap:   nil,  # IMAP sends banner on connect
        }.freeze

        # Signature patterns for service identification
        SIGNATURES = {
          /^SSH-(\S+)/                     => ->(m) { { service: 'SSH', version: m[1] } },
          /^220.*FTP/i                     => ->(m) { { service: 'FTP', banner: m[0] } },
          /^220.*SMTP/i                    => ->(m) { { service: 'SMTP', banner: m[0] } },
          /^220.*ESMTP/i                   => ->(m) { { service: 'ESMTP', banner: m[0] } },
          /^\+OK.*POP3/i                   => ->(m) { { service: 'POP3', banner: m[0] } },
          /^\* OK.*IMAP/i                  => ->(m) { { service: 'IMAP', banner: m[0] } },
          /^HTTP\/(\d\.\d)\s+(\d+)/        => ->(m) { { service: 'HTTP', http_version: m[1], status: m[2] } },
          /\+PONG/                         => ->(m) { { service: 'Redis' } },
          /^ERR/                           => ->(m) { { service: 'Redis', auth_required: true } },
          /mysql_native_password/          => ->(m) { { service: 'MySQL' } },
          /MariaDB/i                       => ->(m) { { service: 'MariaDB' } },
          /PostgreSQL/i                    => ->(m) { { service: 'PostgreSQL' } },
          /MongoDB/i                       => ->(m) { { service: 'MongoDB' } },
          /elasticsearch/i                 => ->(m) { { service: 'Elasticsearch' } },
          /Apache/i                        => ->(m) { { service: 'Apache HTTP', banner: m[0] } },
          /nginx/i                         => ->(m) { { service: 'Nginx', banner: m[0] } },
        }.freeze

        attr_reader :results, :logger

        def initialize(timeout: 3, log_output: $stdout)
          @timeout = timeout
          @results = []
          @logger = Logger.new(log_output)
          @logger.progname = 'LoLRuby::ServiceEnum'
        end

        def describe
          puts <<~DESC
            LoLRuby Technique: Service Enumeration (LR-R-002/003)
            MITRE ATT&CK: T1046 - Network Service Discovery

            Ruby Methods Used:
              - TCPSocket.new + recv — Banner grabbing
              - Net::HTTP — HTTP service fingerprinting
              - OpenSSL::SSL::SSLSocket — TLS certificate inspection

            Concept:
              After discovering open ports, service enumeration identifies the
              specific software and version running. This uses protocol-specific
              probes and banner pattern matching — all via Ruby stdlib.

            Detection:
              - Unusual protocol probes from Ruby processes
              - Sequential probing across multiple service types
              - TLS certificate enumeration requests
          DESC
        end

        # Enumerate a single service by connecting, sending probes, and matching
        # Educational: Each protocol has distinct banner/handshake behavior
        def enumerate_service(host, port)
          @logger.info("Enumerating service at #{host}:#{port}")

          result = {
            host: host,
            port: port,
            timestamp: Time.now.iso8601,
            raw_banner: nil,
            service: nil,
            details: {}
          }

          # Step 1: Grab initial banner (many services send data on connect)
          banner = grab_banner(host, port)
          result[:raw_banner] = banner

          # Step 2: Try to identify the service from the banner
          if banner
            identified = identify_service(banner)
            result.merge!(identified) if identified
          end

          # Step 3: If HTTP detected or common HTTP port, do HTTP fingerprinting
          if result[:service] =~ /HTTP/i || [80, 443, 8080, 8443, 3000, 8000].include?(port)
            http_info = http_enumerate(host, port)
            result[:details][:http] = http_info if http_info
          end

          # Step 4: Check for TLS/SSL
          tls_info = tls_enumerate(host, port)
          result[:details][:tls] = tls_info if tls_info

          @results << result
          result
        end

        # Enumerate all open ports on a host
        def enumerate_host(host, ports:)
          @logger.info("Full enumeration of #{host} on #{ports.length} ports")
          ports.map { |port| enumerate_service(host, port) }
        end

        # HTTP-specific deep enumeration
        # Educational: HTTP headers reveal extensive server information
        def http_enumerate(host, port)
          scheme = [443, 8443].include?(port) ? 'https' : 'http'
          info = {}

          begin
            uri = URI("#{scheme}://#{host}:#{port}/")
            http = Net::HTTP.new(uri.host, uri.port)
            http.use_ssl = (scheme == 'https')
            http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?
            http.open_timeout = @timeout
            http.read_timeout = @timeout

            # GET request for full response analysis
            response = http.get('/')
            info[:status] = response.code.to_i
            info[:server] = response['Server']
            info[:powered_by] = response['X-Powered-By']
            info[:content_type] = response['Content-Type']
            info[:framework] = detect_framework(response)
            info[:security_headers] = check_security_headers(response)

            # OPTIONS request for method enumeration
            begin
              options_resp = http.options('/')
              info[:allowed_methods] = options_resp['Allow']
            rescue StandardError
              # OPTIONS may not be supported
            end

            # Check for common paths that reveal technology
            tech_paths = {
              '/robots.txt' => :robots,
              '/sitemap.xml' => :sitemap,
              '/server-info' => :server_info,
              '/wp-login.php' => :wordpress,
              '/administrator/' => :joomla,
            }

            tech_paths.each do |path, key|
              begin
                resp = http.head(path)
                info[key] = true if resp.code.to_i == 200
              rescue StandardError
                next
              end
            end

            @logger.info("HTTP enum #{host}:#{port}: #{info[:server]}")
          rescue StandardError => e
            @logger.debug("HTTP enum failed #{host}:#{port}: #{e.message}")
            return nil
          end

          info
        end

        # TLS certificate enumeration
        # Educational: TLS certificates reveal hostnames, organization, validity
        def tls_enumerate(host, port)
          begin
            tcp = TCPSocket.new(host, port)
            ctx = OpenSSL::SSL::SSLContext.new
            ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

            ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
            ssl.hostname = host
            ssl.connect

            cert = ssl.peer_cert
            return nil unless cert

            info = {
              subject: cert.subject.to_s,
              issuer: cert.issuer.to_s,
              serial: cert.serial.to_s,
              not_before: cert.not_before.iso8601,
              not_after: cert.not_after.iso8601,
              version: ssl.ssl_version,
              cipher: ssl.cipher[0],
              san: extract_san(cert)
            }

            ssl.close
            tcp.close

            @logger.info("TLS cert for #{host}:#{port}: #{info[:subject]}")
            info
          rescue StandardError => e
            @logger.debug("TLS enum failed #{host}:#{port}: #{e.message}")
            nil
          end
        end

        # Generate enumeration report
        def report(format: :json)
          case format
          when :json
            JSON.pretty_generate({
              scan_time: Time.now.iso8601,
              results: @results
            })
          when :text
            lines = @results.map do |r|
              "#{r[:host]}:#{r[:port]} - #{r[:service] || 'Unknown'} " \
              "#{r[:raw_banner] ? '(banner: ' + r[:raw_banner][0..50] + ')' : ''}"
            end
            lines.join("\n")
          end
        end

        private

        def grab_banner(host, port)
          banner = nil
          Timeout.timeout(@timeout) do
            sock = TCPSocket.new(host, port)

            # Some services need a probe before they respond
            if port == 80 || port == 8080
              sock.write(PROBES[:http] % { host: host })
            elsif PROBES[:redis] && port == 6379
              sock.write(PROBES[:redis])
            end

            # Try to read banner data
            ready = IO.select([sock], nil, nil, @timeout)
            banner = sock.recv(4096).strip if ready
            sock.close
          end
          banner
        rescue StandardError => e
          @logger.debug("Banner grab error #{host}:#{port}: #{e.message}")
          nil
        end

        def identify_service(banner)
          SIGNATURES.each do |pattern, handler|
            match = banner.match(pattern)
            return handler.call(match) if match
          end
          nil
        end

        def detect_framework(response)
          frameworks = []
          body = response.body || ''
          headers = response.to_hash

          frameworks << 'Rails' if headers['x-runtime'] || body.include?('csrf-token')
          frameworks << 'Express' if headers['x-powered-by']&.include?('Express')
          frameworks << 'Django' if body.include?('csrfmiddlewaretoken')
          frameworks << 'PHP' if headers['x-powered-by']&.include?('PHP')
          frameworks << 'ASP.NET' if headers['x-aspnet-version']
          frameworks << 'WordPress' if body.include?('wp-content')

          frameworks.empty? ? nil : frameworks
        end

        def check_security_headers(response)
          headers = {}
          security_headers = %w[
            Strict-Transport-Security Content-Security-Policy
            X-Frame-Options X-Content-Type-Options X-XSS-Protection
            Referrer-Policy Permissions-Policy
          ]

          security_headers.each do |header|
            value = response[header]
            headers[header] = value ? { present: true, value: value } : { present: false }
          end
          headers
        end

        def extract_san(cert)
          san = cert.extensions.find { |ext| ext.oid == 'subjectAltName' }
          return [] unless san

          san.value.split(',').map(&:strip).map { |s| s.sub(/^DNS:/, '') }
        end
      end
    end
  end
end
