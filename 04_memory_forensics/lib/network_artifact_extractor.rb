# frozen_string_literal: true

require 'json'
require 'yaml'
require 'ipaddr'
require 'uri'
require 'resolv'
require 'set'

module RubyGuardian
  module MemoryForensics
    # NetworkArtifactExtractor recovers network-related artifacts from memory dumps,
    # including URLs, IP addresses, DNS queries, socket structures, HTTP request/response
    # data, and TLS session information.
    class NetworkArtifactExtractor
      # Network artifact structures
      URLArtifact = Struct.new(
        :url, :scheme, :host, :port, :path, :query,
        :address, :context, keyword_init: true
      )

      IPArtifact = Struct.new(
        :ip, :version, :port, :address, :is_private,
        :context, :geo_info, keyword_init: true
      )

      DNSArtifact = Struct.new(
        :query_name, :query_type, :response_ips, :ttl,
        :address, :timestamp, keyword_init: true
      )

      SocketArtifact = Struct.new(
        :family, :sock_type, :protocol, :local_addr, :local_port,
        :remote_addr, :remote_port, :state, :address, keyword_init: true
      )

      HTTPArtifact = Struct.new(
        :method, :url, :headers, :body_preview,
        :status_code, :is_request, :address, keyword_init: true
      )

      TLSArtifact = Struct.new(
        :version, :cipher_suite, :server_name, :certificate_subject,
        :certificate_issuer, :session_id, :address, keyword_init: true
      )

      ExtractionResult = Struct.new(
        :urls, :ips, :dns_entries, :sockets, :http_artifacts,
        :tls_artifacts, :summary, keyword_init: true
      )

      # Regex patterns for network artifacts
      PATTERNS = {
        url: /(?:https?|ftp|ssh|telnet|ldap):\/\/[^\s"'<>\x00-\x1f]{4,500}/i,
        ipv4: /\b((?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?))\b/,
        ipv4_port: /\b((?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)):(\d{1,5})\b/,
        ipv6: /(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}/,
        domain: /\b([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|xyz|top|info|biz|cc|tk|ml|ga|cf|gq|ru|cn|pw|onion)\b/,
        http_request: /(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP\/[12]\.\d/,
        http_response: /HTTP\/[12]\.\d\s+(\d{3})\s+[^\r\n]+/,
        http_header: /^([A-Z][a-zA-Z-]+):\s*(.+?)[\r\n]/m,
        email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/,
        dns_query: /\x00{0,2}[\x01-\x3f][a-zA-Z0-9-]+(?:[\x01-\x3f][a-zA-Z0-9-]+)+\x00/,
        user_agent: /(?:Mozilla|curl|wget|python-requests|Ruby|HTTParty|Faraday|Net::HTTP)\/[\d.]+[^\r\n]*/i,
        tls_sni: /\x00\x00(.{1,2})([\x01-\x3f][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/
      }.freeze

      # Socket state constants (Linux)
      TCP_STATES = {
        0x01 => 'ESTABLISHED', 0x02 => 'SYN_SENT', 0x03 => 'SYN_RECV',
        0x04 => 'FIN_WAIT1', 0x05 => 'FIN_WAIT2', 0x06 => 'TIME_WAIT',
        0x07 => 'CLOSE', 0x08 => 'CLOSE_WAIT', 0x09 => 'LAST_ACK',
        0x0A => 'LISTEN', 0x0B => 'CLOSING'
      }.freeze

      # Private IP ranges
      PRIVATE_RANGES = [
        IPAddr.new('10.0.0.0/8'),
        IPAddr.new('172.16.0.0/12'),
        IPAddr.new('192.168.0.0/16'),
        IPAddr.new('127.0.0.0/8'),
        IPAddr.new('169.254.0.0/16')
      ].freeze

      attr_reader :dump_parser, :config

      def initialize(dump_parser, config: nil)
        @dump_parser = dump_parser
        @config = load_config(config)
        @seen_urls = Set.new
        @seen_ips = Set.new
      end

      # Run full network artifact extraction
      def extract
        urls = extract_urls
        ips = extract_ip_addresses
        dns = extract_dns_entries
        sockets = extract_socket_structures
        http = extract_http_artifacts
        tls = extract_tls_artifacts

        ExtractionResult.new(
          urls: urls,
          ips: ips,
          dns_entries: dns,
          sockets: sockets,
          http_artifacts: http,
          tls_artifacts: tls,
          summary: build_summary(urls, ips, dns, sockets, http, tls)
        )
      end

      # Extract URLs from memory
      def extract_urls
        urls = []
        @seen_urls.clear

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          text = safe_encode(region.data)
          text.scan(PATTERNS[:url]) do |match_str|
            url_str = $~.to_s
            next if @seen_urls.include?(url_str)

            @seen_urls.add(url_str)
            begin
              uri = URI.parse(url_str)
              pos = $~.begin(0)
              context = extract_context(text, pos, 50)

              urls << URLArtifact.new(
                url: url_str,
                scheme: uri.scheme,
                host: uri.host,
                port: uri.port,
                path: uri.path,
                query: uri.query,
                address: region.start_addr + pos,
                context: context
              )
            rescue URI::InvalidURIError
              next
            end
          end
        end

        urls
      end

      # Extract IP addresses from memory
      def extract_ip_addresses
        ips = []
        @seen_ips.clear

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          text = safe_encode(region.data)

          # IPv4 with optional port
          text.scan(PATTERNS[:ipv4_port]) do |ip_str, port_str|
            next if @seen_ips.include?("#{ip_str}:#{port_str}")

            @seen_ips.add("#{ip_str}:#{port_str}")
            next unless valid_ip?(ip_str)

            port = port_str.to_i
            next if port > 65535

            pos = $~.begin(0)
            ips << build_ip_artifact(ip_str, 4, port, region.start_addr + pos,
                                     extract_context(text, pos, 40))
          end

          # IPv4 without port (avoid duplicates from ip:port matches)
          text.scan(PATTERNS[:ipv4]) do |ip_str|
            ip = ip_str.is_a?(Array) ? ip_str.first : ip_str
            next if @seen_ips.include?(ip)

            @seen_ips.add(ip)
            next unless valid_ip?(ip)

            pos = $~.begin(0)
            ips << build_ip_artifact(ip, 4, nil, region.start_addr + pos,
                                     extract_context(text, pos, 40))
          end

          # IPv6
          text.scan(PATTERNS[:ipv6]) do |match|
            ip_str = $~.to_s
            next if @seen_ips.include?(ip_str)

            @seen_ips.add(ip_str)
            pos = $~.begin(0)
            ips << build_ip_artifact(ip_str, 6, nil, region.start_addr + pos,
                                     extract_context(text, pos, 40))
          end
        end

        ips
      end

      # Extract DNS query/response artifacts from memory
      def extract_dns_entries
        entries = []
        return entries unless @config.dig('analysis', 'network', 'extract_dns_cache') != false

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          # Look for DNS wire format queries
          offset = 0
          data = region.data

          while offset + 12 < data.bytesize
            # DNS header: ID (2) + flags (2) + counts (8)
            flags = data[offset + 2, 2]&.unpack1('n')
            if flags && (flags & 0x8000) != 0 # Response flag
              qr = (flags >> 15) & 1
              if qr == 1
                entry = parse_dns_response(data, offset, region.start_addr)
                entries << entry if entry
              end
            end
            offset += 1
          end

          # Also look for DNS names as strings
          text = safe_encode(data)
          text.scan(PATTERNS[:domain]) do
            domain = $~.to_s
            pos = $~.begin(0)
            entries << DNSArtifact.new(
              query_name: domain,
              query_type: 'A',
              response_ips: [],
              ttl: nil,
              address: region.start_addr + pos,
              timestamp: nil
            )
          end
        end

        # Deduplicate by query name
        entries.uniq { |e| e.query_name }
      end

      # Extract socket structure artifacts
      def extract_socket_structures
        sockets = []
        return sockets unless @config.dig('analysis', 'network', 'extract_sockets') != false

        # Look for sockaddr_in structures: AF_INET (2) + port (2) + ip (4)
        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          data = region.data
          offset = 0

          while offset + 16 <= data.bytesize
            family = data[offset, 2].unpack1('v')

            if family == 2 # AF_INET
              port = data[offset + 2, 2].unpack1('n')
              ip_bytes = data[offset + 4, 4]

              if port > 0 && port <= 65535 && ip_bytes
                ip = ip_bytes.unpack('C4').join('.')
                if valid_ip?(ip) && ip != '0.0.0.0'
                  sockets << SocketArtifact.new(
                    family: :AF_INET,
                    sock_type: nil,
                    protocol: nil,
                    local_addr: nil,
                    local_port: nil,
                    remote_addr: ip,
                    remote_port: port,
                    state: nil,
                    address: region.start_addr + offset
                  )
                end
              end
            elsif family == 10 # AF_INET6
              port = data[offset + 2, 2].unpack1('n')
              ip_bytes = data[offset + 8, 16]

              if port > 0 && port <= 65535 && ip_bytes && ip_bytes.bytesize == 16
                ip = ip_bytes.unpack('n8').map { |w| w.to_s(16) }.join(':')
                sockets << SocketArtifact.new(
                  family: :AF_INET6,
                  sock_type: nil,
                  protocol: nil,
                  local_addr: nil,
                  local_port: nil,
                  remote_addr: ip,
                  remote_port: port,
                  state: nil,
                  address: region.start_addr + offset
                )
              end
            end

            offset += 2
          end
        end

        # Deduplicate
        sockets.uniq { |s| "#{s.remote_addr}:#{s.remote_port}" }
      end

      # Extract HTTP request/response artifacts
      def extract_http_artifacts
        artifacts = []
        return artifacts unless @config.dig('analysis', 'network', 'extract_http') != false

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          text = safe_encode(region.data)

          # HTTP Requests
          text.scan(PATTERNS[:http_request]) do
            pos = $~.begin(0)
            request_text = text[pos, [2048, text.length - pos].min]
            lines = request_text.split(/\r?\n/)
            method, path = lines.first.split(' ')

            headers = {}
            lines[1..].each do |line|
              break if line.strip.empty?

              key, value = line.split(':', 2)
              headers[key.strip] = value&.strip if key && value
            end

            artifacts << HTTPArtifact.new(
              method: method,
              url: path,
              headers: headers,
              body_preview: nil,
              status_code: nil,
              is_request: true,
              address: region.start_addr + pos
            )
          end

          # HTTP Responses
          text.scan(PATTERNS[:http_response]) do
            pos = $~.begin(0)
            response_text = text[pos, [4096, text.length - pos].min]
            status_match = response_text.match(/HTTP\/[\d.]+\s+(\d{3})/)
            status = status_match ? status_match[1].to_i : nil

            headers = {}
            lines = response_text.split(/\r?\n/)
            body_start = nil
            lines[1..].each_with_index do |line, idx|
              if line.strip.empty?
                body_start = idx + 2
                break
              end
              key, value = line.split(':', 2)
              headers[key.strip] = value&.strip if key && value
            end

            body_preview = body_start ? lines[body_start..]&.first(3)&.join("\n") : nil

            artifacts << HTTPArtifact.new(
              method: nil,
              url: nil,
              headers: headers,
              body_preview: body_preview&.slice(0, 500),
              status_code: status,
              is_request: false,
              address: region.start_addr + pos
            )
          end
        end

        artifacts
      end

      # Extract TLS/SSL session artifacts
      def extract_tls_artifacts
        artifacts = []
        return artifacts unless @config.dig('analysis', 'network', 'extract_tls') != false

        @dump_parser.regions.each do |region|
          next unless region.permissions.include?('r')

          data = region.data

          # Look for TLS record headers: ContentType(1) + Version(2) + Length(2)
          offset = 0
          while offset + 5 < data.bytesize
            content_type = data.getbyte(offset)
            version_major = data.getbyte(offset + 1)
            version_minor = data.getbyte(offset + 2)
            length = data[offset + 3, 2]&.unpack1('n')

            # Valid TLS record
            if content_type && content_type.between?(20, 23) &&
               version_major == 3 && version_minor.between?(0, 4) &&
               length && length > 0 && length < 16_384

              version = case version_minor
                        when 0 then 'SSL 3.0'
                        when 1 then 'TLS 1.0'
                        when 2 then 'TLS 1.1'
                        when 3 then 'TLS 1.2'
                        when 4 then 'TLS 1.3'
                        end

              # Try to extract SNI from ClientHello
              sni = nil
              if content_type == 22 && offset + 5 + length <= data.bytesize
                handshake = data[offset + 5, length]
                sni = extract_sni(handshake) if handshake
              end

              artifacts << TLSArtifact.new(
                version: version,
                cipher_suite: nil,
                server_name: sni,
                certificate_subject: nil,
                certificate_issuer: nil,
                session_id: nil,
                address: region.start_addr + offset
              )

              offset += 5 + length
            else
              offset += 1
            end
          end
        end

        # Deduplicate
        artifacts.uniq { |a| "#{a.version}:#{a.server_name}:#{a.address}" }
      end

      # Identify suspicious network artifacts
      def find_suspicious
        result = extract
        suspicious = []

        # Suspicious URLs
        result.urls.each do |url|
          reasons = []
          reasons << 'Uses non-standard port' if url.port && ![80, 443, 8080, 8443].include?(url.port)
          reasons << 'Contains IP address instead of domain' if url.host&.match?(/\A\d+\.\d+\.\d+\.\d+\z/)
          reasons << 'Contains encoded characters' if url.url.include?('%')
          reasons << 'Points to .onion domain' if url.host&.end_with?('.onion')

          suspicious << { type: :url, artifact: url, reasons: reasons } unless reasons.empty?
        end

        # Suspicious IPs (external, non-standard ports)
        result.ips.each do |ip|
          next if ip.is_private

          reasons = []
          reasons << "External IP with port #{ip.port}" if ip.port && ![80, 443, 53, 22].include?(ip.port)
          suspicious << { type: :ip, artifact: ip, reasons: reasons } unless reasons.empty?
        end

        # Suspicious HTTP (unusual methods, suspicious paths)
        result.http_artifacts.each do |http|
          reasons = []
          reasons << "Unusual HTTP method: #{http.method}" if http.method && !%w[GET POST PUT DELETE].include?(http.method)
          reasons << 'Suspicious User-Agent' if http.headers&.key?('User-Agent') &&
                                                 http.headers['User-Agent']&.match?(/python|curl|wget|bot/i)

          suspicious << { type: :http, artifact: http, reasons: reasons } unless reasons.empty?
        end

        suspicious
      end

      private

      def build_ip_artifact(ip_str, version, port, address, context)
        is_private = private_ip?(ip_str)
        IPArtifact.new(
          ip: ip_str, version: version, port: port,
          address: address, is_private: is_private,
          context: context, geo_info: nil
        )
      end

      def valid_ip?(ip_str)
        octets = ip_str.split('.')
        return false unless octets.size == 4

        octets.all? { |o| o.match?(/\A\d{1,3}\z/) && o.to_i.between?(0, 255) }
      rescue StandardError
        false
      end

      def private_ip?(ip_str)
        addr = IPAddr.new(ip_str)
        PRIVATE_RANGES.any? { |range| range.include?(addr) }
      rescue IPAddr::InvalidAddressError
        false
      end

      def parse_dns_response(data, offset, base_addr)
        return nil if offset + 12 > data.bytesize

        # Skip header (12 bytes) and try to parse question section
        pos = offset + 12
        name_parts = []

        # Parse DNS name (label format)
        100.times do # Safety limit
          break if pos >= data.bytesize

          label_len = data.getbyte(pos)
          break if label_len.nil? || label_len == 0

          # Compression pointer
          if (label_len & 0xC0) == 0xC0
            pos += 2
            break
          end

          break if label_len > 63 || pos + 1 + label_len > data.bytesize

          name_parts << data[pos + 1, label_len]
          pos += 1 + label_len
        end

        return nil if name_parts.empty?

        query_name = name_parts.join('.')
        return nil unless query_name.match?(/\A[a-zA-Z0-9.-]+\z/)

        DNSArtifact.new(
          query_name: query_name,
          query_type: 'A',
          response_ips: [],
          ttl: nil,
          address: base_addr + offset,
          timestamp: nil
        )
      rescue StandardError
        nil
      end

      def extract_sni(handshake_data)
        return nil if handshake_data.bytesize < 44

        # ClientHello starts at byte 0: HandshakeType(1) + Length(3) + Version(2) + Random(32) + ...
        pos = 38 # Skip to session ID length
        return nil if pos >= handshake_data.bytesize

        session_id_len = handshake_data.getbyte(pos)
        return nil unless session_id_len

        pos += 1 + session_id_len
        return nil if pos + 2 > handshake_data.bytesize

        # Skip cipher suites
        cipher_suites_len = handshake_data[pos, 2].unpack1('n')
        pos += 2 + cipher_suites_len
        return nil if pos + 1 > handshake_data.bytesize

        # Skip compression methods
        compression_len = handshake_data.getbyte(pos)
        pos += 1 + compression_len
        return nil if pos + 2 > handshake_data.bytesize

        # Extensions
        extensions_len = handshake_data[pos, 2].unpack1('n')
        pos += 2
        ext_end = pos + extensions_len

        while pos + 4 < ext_end && pos < handshake_data.bytesize
          ext_type = handshake_data[pos, 2].unpack1('n')
          ext_len = handshake_data[pos + 2, 2].unpack1('n')
          pos += 4

          if ext_type == 0 # SNI extension
            # Parse SNI
            return nil if pos + 5 > handshake_data.bytesize

            sni_list_len = handshake_data[pos, 2].unpack1('n')
            sni_type = handshake_data.getbyte(pos + 2)
            sni_len = handshake_data[pos + 3, 2].unpack1('n')

            if sni_type == 0 && sni_len > 0 && pos + 5 + sni_len <= handshake_data.bytesize
              sni = handshake_data[pos + 5, sni_len]
              return sni if sni.match?(/\A[a-zA-Z0-9.-]+\z/)
            end
          end

          pos += ext_len
        end

        nil
      rescue StandardError
        nil
      end

      def extract_context(text, position, length)
        start = [position - length, 0].max
        finish = [position + length, text.length].min
        text[start...finish].gsub(/[^[:print:]]/, '.')
      end

      def safe_encode(data)
        data.encode('UTF-8', 'binary', invalid: :replace, undef: :replace, replace: '.')
      rescue StandardError
        ''
      end

      def build_summary(urls, ips, dns, sockets, http, tls)
        external_ips = ips.reject(&:is_private)
        {
          total_urls: urls.size,
          total_ips: ips.size,
          external_ips: external_ips.size,
          internal_ips: ips.size - external_ips.size,
          dns_entries: dns.size,
          sockets: sockets.size,
          http_requests: http.count(&:is_request),
          http_responses: http.count { |h| !h.is_request },
          tls_sessions: tls.size,
          unique_hosts: (urls.map(&:host) + ips.map(&:ip)).compact.uniq.size
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
