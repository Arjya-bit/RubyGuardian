# frozen_string_literal: true

require 'net/http'
require 'socket'
require 'resolv'
require 'uri'
require 'json'
require 'base64'

module RubyGuardian
  module Shared
    # Network utility methods shared across attack modules
    # All methods respect network isolation settings
    module NetworkUtils
      ALLOWED_HOSTS = %w[127.0.0.1 localhost].freeze
      DEFAULT_TIMEOUT = 10

      module_function

      # Perform an HTTP GET request
      def http_get(url, headers: {}, timeout: DEFAULT_TIMEOUT)
        validate_url!(url)
        uri = URI.parse(url)

        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = timeout
        http.read_timeout = timeout
        http.use_ssl = uri.scheme == 'https'

        request = Net::HTTP::Get.new(uri.request_uri)
        headers.each { |k, v| request[k] = v }

        http.request(request)
      end

      # Perform an HTTP POST request
      def http_post(url, body:, content_type: 'application/json', headers: {}, timeout: DEFAULT_TIMEOUT)
        validate_url!(url)
        uri = URI.parse(url)

        http = Net::HTTP.new(uri.host, uri.port)
        http.open_timeout = timeout
        http.read_timeout = timeout
        http.use_ssl = uri.scheme == 'https'

        request = Net::HTTP::Post.new(uri.request_uri)
        request['Content-Type'] = content_type
        headers.each { |k, v| request[k] = v }
        request.body = body.is_a?(String) ? body : JSON.generate(body)

        http.request(request)
      end

      # Open a TCP connection
      def tcp_connect(host, port, timeout: DEFAULT_TIMEOUT)
        validate_host!(host)
        socket = Socket.tcp(host, port, connect_timeout: timeout)
        yield socket if block_given?
        socket
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT => e
        raise ConnectionError, "TCP connection to #{host}:#{port} failed: #{e.message}"
      ensure
        socket&.close if block_given?
      end

      # Check if a port is open
      def port_open?(host, port, timeout: 3)
        validate_host!(host)
        Socket.tcp(host, port, connect_timeout: timeout) { true }
      rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, SocketError
        false
      end

      # Perform DNS resolution
      def resolve_hostname(hostname)
        Resolv.getaddresses(hostname)
      rescue Resolv::ResolvError
        []
      end

      # Encode data for DNS exfiltration (educational)
      def encode_for_dns(data, chunk_size: 63)
        encoded = Base64.urlsafe_encode64(data, padding: false)
        encoded.scan(/.{1,#{chunk_size}}/)
      end

      # Generate a beacon check-in payload
      def build_beacon_payload(agent_id:, hostname:, username:, os_info:)
        {
          id: agent_id,
          hostname: hostname,
          username: username,
          os: os_info,
          timestamp: Time.now.utc.iso8601,
          pid: Process.pid
        }
      end

      # Validate URL is within allowed scope
      def validate_url!(url)
        uri = URI.parse(url)
        validate_host!(uri.host)
      end

      # Validate host is within allowed scope
      def validate_host!(host)
        return if ENV['RUBY_GUARDIAN_UNSAFE'] == 'true'
        return if ALLOWED_HOSTS.include?(host)
        return if host&.start_with?('172.17.', '172.18.', '10.0.')

        raise SecurityError,
              "Host '#{host}' not in allowed list. Set RUBY_GUARDIAN_UNSAFE=true to override (lab only)."
      end

      class ConnectionError < StandardError; end
    end
  end
end
