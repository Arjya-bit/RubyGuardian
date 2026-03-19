# frozen_string_literal: true

# RubyGuardian Honeypot - Fake Gem Server Rack Configuration
# This config.ru bootstraps the fake RubyGems/Geminabox server.
# All interactions are captured for threat intelligence purposes.
#
# HONEYPOT WARNING: This is a decoy service. All data is fabricated.
# Do not deploy on production infrastructure without proper isolation.

require "bundler/setup"
require_relative "gem_server"

# Configure Rack middleware stack for maximum capture fidelity
module RubyGuardian
  module Honeypot
    module GemServer
      # Middleware to capture raw request bodies before Sinatra parses them
      class RawBodyCapture
        def initialize(app)
          @app = app
        end

        def call(env)
          if env["rack.input"]
            body = env["rack.input"].read
            env["rack.input"].rewind
            env["honeypot.raw_body"] = body
            env["honeypot.body_size"] = body.bytesize
          end

          env["honeypot.received_at"] = Time.now.utc.iso8601(6)
          env["honeypot.request_id"] = generate_request_id

          @app.call(env)
        end

        private

        def generate_request_id
          "hp-gem-#{SecureRandom.uuid}"
        end
      end

      # Middleware to add realistic response headers mimicking Geminabox
      class RealisticHeaders
        GEMINABOX_HEADERS = {
          "X-Powered-By" => "Geminabox/3.0.0",
          "Server" => "thin 1.8.2 codename Ruby Thin",
          "X-Content-Type-Options" => "nosniff",
          "X-Request-Id" => nil,
          "Cache-Control" => "no-cache, no-store"
        }.freeze

        def initialize(app)
          @app = app
        end

        def call(env)
          status, headers, body = @app.call(env)

          GEMINABOX_HEADERS.each do |key, value|
            next if value.nil? && key == "X-Request-Id"
            headers[key] = value || env["honeypot.request_id"]
          end

          # Add realistic timing header
          if env["honeypot.received_at"]
            elapsed = Time.now.utc - Time.parse(env["honeypot.received_at"])
            headers["X-Runtime"] = format("%.6f", elapsed + rand(0.01..0.05))
          end

          [status, headers, body]
        end
      end

      # Middleware for session tracking across requests
      class SessionTracker
        SESSION_COOKIE = "geminabox_session"

        def initialize(app, options = {})
          @app = app
          @session_ttl = options.fetch(:session_ttl, 3600)
        end

        def call(env)
          request = Rack::Request.new(env)
          session_id = request.cookies[SESSION_COOKIE]

          if session_id.nil? || session_id.empty?
            session_id = SecureRandom.hex(16)
            env["honeypot.new_session"] = true
          end

          env["honeypot.session_id"] = session_id

          status, headers, body = @app.call(env)

          if env["honeypot.new_session"]
            Rack::Utils.set_cookie_header!(headers, SESSION_COOKIE, {
              value: session_id,
              path: "/",
              max_age: @session_ttl,
              httponly: true
            })
          end

          [status, headers, body]
        end
      end

      # Middleware to rate-limit outbound responses (safety measure)
      class ResponseRateLimiter
        def initialize(app, options = {})
          @app = app
          @max_requests_per_minute = options.fetch(:max_rpm, 300)
          @request_counts = {}
          @mutex = Mutex.new
        end

        def call(env)
          client_ip = env["REMOTE_ADDR"]
          now = Time.now.to_i
          minute_key = "#{client_ip}:#{now / 60}"

          count = @mutex.synchronize do
            cleanup_old_entries(now)
            @request_counts[minute_key] = (@request_counts[minute_key] || 0) + 1
          end

          if count > @max_requests_per_minute
            return [429, {
              "Content-Type" => "text/plain",
              "Retry-After" => "60"
            }, ["Rate limit exceeded. Please slow down."]]
          end

          @app.call(env)
        end

        private

        def cleanup_old_entries(now)
          current_minute = now / 60
          @request_counts.delete_if do |key, _|
            minute = key.split(":").last.to_i
            (current_minute - minute) > 2
          end
        end
      end

      # Middleware to log connection metadata for forensics
      class ConnectionLogger
        def initialize(app, options = {})
          @app = app
          @log_path = options.fetch(:log_path, "/var/log/rubyguardian/honeypot")
        end

        def call(env)
          connection_info = {
            timestamp: Time.now.utc.iso8601(6),
            request_id: env["honeypot.request_id"],
            remote_addr: env["REMOTE_ADDR"],
            remote_host: env["REMOTE_HOST"],
            server_port: env["SERVER_PORT"],
            http_version: env["HTTP_VERSION"],
            tls: env["HTTPS"] == "on" || env["rack.url_scheme"] == "https",
            user_agent: env["HTTP_USER_AGENT"],
            method: env["REQUEST_METHOD"],
            path: env["PATH_INFO"],
            query: env["QUERY_STRING"]
          }

          status, headers, body = @app.call(env)

          connection_info[:response_status] = status
          connection_info[:response_size] = headers["Content-Length"]

          write_log(connection_info)

          [status, headers, body]
        end

        private

        def write_log(data)
          log_file = File.join(@log_path, "gem_server_connections_#{Date.today.iso8601}.jsonl")
          File.open(log_file, "a") do |f|
            f.flock(File::LOCK_EX)
            f.puts(JSON.generate(data))
          end
        rescue StandardError
          # Silently fail - don't crash the honeypot due to logging issues
        end
      end
    end
  end
end

# Build the Rack application stack
log_path = ENV.fetch("HONEYPOT_LOG_DIR", "/var/log/rubyguardian/honeypot")

use RubyGuardian::Honeypot::GemServer::ResponseRateLimiter, max_rpm: 300
use RubyGuardian::Honeypot::GemServer::ConnectionLogger, log_path: log_path
use RubyGuardian::Honeypot::GemServer::SessionTracker, session_ttl: 3600
use RubyGuardian::Honeypot::GemServer::RealisticHeaders
use RubyGuardian::Honeypot::GemServer::RawBodyCapture

# Enable request logging via Rack::CommonLogger
use Rack::CommonLogger, $stderr

run RubyGuardian::Honeypot::FakeGemServer
