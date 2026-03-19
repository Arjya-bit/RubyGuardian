# frozen_string_literal: true

# =============================================================================
# RubyGuardian - LoLRuby Phase 1c
# Technique: Network Port Scanning
# LoLRuby ID: LR-R-001
# MITRE ATT&CK: T1046 - Network Service Discovery
# =============================================================================
#
# EDUCATIONAL PURPOSE ONLY
# This module demonstrates how Ruby's standard library (TCPSocket, Net::HTTP)
# can be used for network reconnaissance without any external tools.
#
# DETECTION METHODS:
# - Monitor for rapid sequential TCP connection attempts from Ruby processes
# - Alert on ruby/irb processes making connections to multiple ports
# - Network flow analysis: short-lived connections to many ports = scan pattern
# - Host-based: audit TCPSocket usage in Ruby scripts via static analysis
# - Syslog: watch for connection refused (RST) patterns from Ruby PIDs
#
# WHY THIS MATTERS:
# Attackers with Ruby access can perform full network scans using only stdlib,
# bypassing security tools that only watch for known scanning binaries (nmap, etc.)
# =============================================================================

require 'socket'
require 'net/http'
require 'timeout'
require 'uri'
require 'json'
require 'logger'

module RubyGuardian
  module LoLRuby
    module Reconnaissance
      class NetworkScan
        # Common service ports for targeted scanning
        COMMON_PORTS = {
          21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP',
          53 => 'DNS', 80 => 'HTTP', 110 => 'POP3', 111 => 'RPCBind',
          135 => 'MSRPC', 139 => 'NetBIOS', 143 => 'IMAP', 443 => 'HTTPS',
          445 => 'SMB', 993 => 'IMAPS', 995 => 'POP3S', 1433 => 'MSSQL',
          1521 => 'Oracle', 3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL',
          5900 => 'VNC', 6379 => 'Redis', 8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt',
          9200 => 'Elasticsearch', 27017 => 'MongoDB'
        }.freeze

        attr_reader :results, :logger

        def initialize(timeout: 1, threads: 10, log_output: $stdout)
          @timeout = timeout
          @threads = threads
          @results = []
          @logger = Logger.new(log_output)
          @logger.progname = 'LoLRuby::NetworkScan'
        end

        # Describe this technique for educational purposes
        def describe
          puts <<~DESC
            LoLRuby Technique: Network Port Scanning (LR-R-001)
            MITRE ATT&CK: T1046 - Network Service Discovery

            Ruby Methods Used:
              - TCPSocket.new(host, port) — Full TCP connect scan
              - Socket.tcp(host, port, connect_timeout:) — Timeout-aware connect
              - Net::HTTP.get_response(uri) — HTTP service detection

            Why It Works:
              Ruby's Socket library provides low-level TCP/UDP access. A full
              connect scan requires no special privileges (unlike SYN scans).
              Ruby's threading model allows concurrent scanning.

            Detection:
              - Monitor ruby processes for rapid outbound TCP connections
              - Network IDS rules for sequential port access patterns
              - Process command line auditing for 'TCPSocket' or 'socket'
          DESC
        end

        # TCP connect scan on a single host
        # Educational: This is the simplest scanning technique — full TCP handshake
        def tcp_connect_scan(host, ports: COMMON_PORTS.keys)
          @logger.info("Starting TCP connect scan on #{host} (#{ports.length} ports)")
          open_ports = []
          mutex = Mutex.new

          # Use thread pool for concurrent scanning
          port_queue = Queue.new
          ports.each { |p| port_queue << p }

          workers = @threads.times.map do
            Thread.new do
              until port_queue.empty?
                port = begin
                  port_queue.pop(true)
                rescue ThreadError
                  break
                end
                next unless port

                result = scan_port(host, port)
                if result[:state] == :open
                  mutex.synchronize do
                    open_ports << result
                    @results << result
                  end
                end
              end
            end
          end

          workers.each(&:join)
          @logger.info("Scan complete: #{open_ports.length} open ports found")
          open_ports
        end

        # Scan a range of hosts on specific ports
        # Educational: Demonstrates subnet scanning using Ruby's IPAddr
        def sweep_scan(cidr, ports: [22, 80, 443])
          require 'ipaddr'
          network = IPAddr.new(cidr)
          hosts = []
          network.to_range.each { |ip| hosts << ip.to_s }

          # Skip network and broadcast addresses for /24+
          hosts = hosts[1..-2] if hosts.length > 2

          @logger.info("Sweep scan: #{hosts.length} hosts, #{ports.length} ports each")

          results = {}
          hosts.each do |host|
            open = tcp_connect_scan(host, ports: ports)
            results[host] = open unless open.empty?
          end
          results
        end

        # HTTP service enumeration using Net::HTTP
        # Educational: HTTP fingerprinting reveals server software and technology stack
        def http_fingerprint(host, ports: [80, 443, 8080, 8443])
          fingerprints = []

          ports.each do |port|
            scheme = [443, 8443].include?(port) ? 'https' : 'http'
            uri = URI("#{scheme}://#{host}:#{port}/")

            begin
              http = Net::HTTP.new(uri.host, uri.port)
              http.use_ssl = (scheme == 'https')
              http.verify_mode = OpenSSL::SSL::VERIFY_NONE if http.use_ssl?
              http.open_timeout = @timeout
              http.read_timeout = @timeout

              response = http.get('/')

              fingerprint = {
                host: host,
                port: port,
                scheme: scheme,
                status: response.code.to_i,
                server: response['Server'],
                powered_by: response['X-Powered-By'],
                content_type: response['Content-Type'],
                headers: response.to_hash,
                title: extract_title(response.body)
              }

              fingerprints << fingerprint
              @results << fingerprint
              @logger.info("HTTP service found: #{host}:#{port} (#{response['Server']})")
            rescue StandardError => e
              @logger.debug("No HTTP service at #{host}:#{port}: #{e.message}")
            end
          end

          fingerprints
        end

        # Banner grabbing — read the initial data sent by a service
        # Educational: Many services send identification banners upon connection
        def banner_grab(host, port, wait_time: 2)
          banner = nil
          begin
            Timeout.timeout(@timeout + wait_time) do
              sock = TCPSocket.new(host, port)
              sock.setsockopt(Socket::SOL_SOCKET, Socket::SO_RCVTIMEO,
                              [wait_time, 0].pack('l_2'))
              banner = sock.recv(1024).strip
              sock.close
            end
          rescue StandardError => e
            @logger.debug("Banner grab failed #{host}:#{port}: #{e.message}")
          end

          if banner && !banner.empty?
            @logger.info("Banner #{host}:#{port}: #{banner[0..80]}")
            { host: host, port: port, banner: banner }
          end
        end

        # Generate a report of all scan results
        def report(format: :text)
          case format
          when :text
            generate_text_report
          when :json
            JSON.pretty_generate({
              scan_time: Time.now.iso8601,
              total_results: @results.length,
              results: @results
            })
          else
            raise ArgumentError, "Unknown format: #{format}"
          end
        end

        private

        def scan_port(host, port)
          begin
            Timeout.timeout(@timeout) do
              sock = TCPSocket.new(host, port)
              sock.close
              service = COMMON_PORTS[port] || 'Unknown'
              @logger.debug("OPEN #{host}:#{port} (#{service})")
              return { host: host, port: port, state: :open, service: service }
            end
          rescue Errno::ECONNREFUSED
            return { host: host, port: port, state: :closed }
          rescue Errno::EHOSTUNREACH
            return { host: host, port: port, state: :unreachable }
          rescue Timeout::Error
            return { host: host, port: port, state: :filtered }
          rescue StandardError => e
            return { host: host, port: port, state: :error, error: e.message }
          end
        end

        def extract_title(html)
          return nil unless html
          match = html.match(/<title[^>]*>([^<]+)<\/title>/i)
          match ? match[1].strip : nil
        end

        def generate_text_report
          lines = ["=" * 60]
          lines << "LoLRuby Network Scan Report"
          lines << "Generated: #{Time.now}"
          lines << "=" * 60

          open_results = @results.select { |r| r[:state] == :open rescue true }
          grouped = open_results.group_by { |r| r[:host] }

          grouped.each do |host, results|
            lines << "\nHost: #{host}"
            lines << "-" * 40
            results.each do |r|
              if r[:port]
                lines << "  Port #{r[:port]}/tcp  #{r[:state]}  #{r[:service]}"
                lines << "    Banner: #{r[:banner][0..60]}" if r[:banner]
                lines << "    Server: #{r[:server]}" if r[:server]
              end
            end
          end

          lines << "\n" + "=" * 60
          lines << "Total: #{open_results.length} results"
          lines.join("\n")
        end
      end
    end
  end
end
