# frozen_string_literal: true

# RubyGuardian Honeypot - Fake Gem Server Application
# Emulates a Geminabox/RubyGems server to detect dependency confusion attacks,
# malicious gem uploads, and unauthorized gem repository access.
#
# HONEYPOT WARNING: All gems hosted here are fabricated decoys.

require "sinatra/base"
require "json"
require "digest"
require "securerandom"
require "fileutils"
require "time"
require "zlib"
require "rubygems/package"

module RubyGuardian
  module Honeypot
    class FakeGemServer < Sinatra::Base
      set :environment, :production
      set :show_exceptions, false
      set :dump_errors, false
      set :raise_errors, false
      set :logging, true
      set :static, false

      LOG_DIR = ENV.fetch("HONEYPOT_LOG_DIR", "/var/log/rubyguardian/honeypot")
      SAMPLES_DIR = ENV.fetch("HONEYPOT_SAMPLES_DIR", "/var/lib/rubyguardian/honeypot/samples")
      MAX_UPLOAD_SIZE = 50 * 1024 * 1024 # 50MB

      # Fake internal gems that appear to be hosted on this server
      HOSTED_GEMS = {
        "internal-auth" => {
          version: "2.1.0",
          authors: ["Internal Team"],
          summary: "Internal authentication library for microservices",
          description: "Provides OAuth2, JWT, and session-based auth for internal Rails apps",
          homepage: "https://git.internal.example.com/libs/internal-auth",
          licenses: ["Proprietary"],
          dependencies: { "bcrypt" => "~> 3.1", "jwt" => "~> 2.7", "rack" => ">= 2.0" },
          sha256: "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
          downloads: 14_892
        },
        "company-utils" => {
          version: "1.5.3",
          authors: ["Platform Engineering"],
          summary: "Shared utility functions for Ruby services",
          description: "Common helpers, formatters, and extensions used across all Ruby projects",
          homepage: "https://git.internal.example.com/libs/company-utils",
          licenses: ["Proprietary"],
          dependencies: { "activesupport" => "~> 7.0" },
          sha256: "b2c3d4e5f67890123456789012345678901abcdef234567890abcdef1234567",
          downloads: 28_456
        },
        "deploy-tools" => {
          version: "3.0.1",
          authors: ["DevOps Team"],
          summary: "Deployment automation and infrastructure management",
          description: "Capistrano recipes, Docker helpers, and deployment scripts",
          homepage: "https://git.internal.example.com/infra/deploy-tools",
          licenses: ["Proprietary"],
          dependencies: { "net-ssh" => "~> 7.2", "capistrano" => "~> 3.18", "aws-sdk-s3" => "~> 1.0" },
          sha256: "c3d4e5f678901234567890123456789012abcdef34567890abcdef12345678",
          downloads: 7_234
        },
        "api-client" => {
          version: "4.2.0",
          authors: ["API Team"],
          summary: "Internal API client library with retry and circuit breaking",
          description: "HTTP client wrapper with built-in auth, retries, and observability",
          homepage: "https://git.internal.example.com/libs/api-client",
          licenses: ["Proprietary"],
          dependencies: { "faraday" => "~> 2.9", "oj" => "~> 3.16", "concurrent-ruby" => "~> 1.2" },
          sha256: "d4e5f6789012345678901234567890123abcdef4567890abcdef123456789",
          downloads: 19_102
        }
      }.freeze

      # ─── Gem Index Endpoints ───────────────────────────────────────────

      # Main landing page - mimics Geminabox dashboard
      get "/" do
        log_event("gem_server_index", path: "/")
        content_type "text/html"
        render_geminabox_dashboard
      end

      # Gem listing page
      get "/gems" do
        log_event("gem_listing_access", path: "/gems")
        content_type "text/html"
        render_gem_listing_html
      end

      # RubyGems API - list all gems
      get "/api/v1/gems" do
        log_event("api_gem_list", path: "/api/v1/gems")
        content_type "application/json"
        gems_list = HOSTED_GEMS.map do |name, info|
          {
            name: name,
            version: info[:version],
            authors: info[:authors].join(", "),
            info: info[:summary],
            downloads: info[:downloads],
            project_uri: "#{request.base_url}/gems/#{name}",
            gem_uri: "#{request.base_url}/gems/#{name}-#{info[:version]}.gem"
          }
        end
        JSON.pretty_generate(gems_list)
      end

      # RubyGems API - gem detail
      get "/api/v1/gems/:name.json" do
        gem_name = params[:name]
        log_event("api_gem_detail", gem_name: gem_name)

        gem_info = HOSTED_GEMS[gem_name]
        unless gem_info
          log_event("unknown_gem_lookup", gem_name: gem_name, suspicious: true)
          halt 404, { "Content-Type" => "application/json" },
               JSON.generate({ error: "Gem not found", name: gem_name })
        end

        content_type "application/json"
        JSON.pretty_generate(build_gem_detail(gem_name, gem_info))
      end

      # RubyGems API - gem versions
      get "/api/v1/versions/:name.json" do
        gem_name = params[:name]
        log_event("api_gem_versions", gem_name: gem_name)

        gem_info = HOSTED_GEMS[gem_name]
        unless gem_info
          log_event("unknown_gem_version_lookup", gem_name: gem_name, suspicious: true)
          halt 404, JSON.generate({ error: "Gem not found" })
        end

        content_type "application/json"
        JSON.pretty_generate([{
          number: gem_info[:version],
          built_at: "2024-01-15T00:00:00.000Z",
          summary: gem_info[:summary],
          platform: "ruby",
          ruby_version: ">= 3.1.0",
          prerelease: false,
          downloads_count: gem_info[:downloads],
          sha: gem_info[:sha256]
        }])
      end

      # Specs index endpoint (used by bundler)
      get "/specs.4.8.gz" do
        log_event("specs_index_access", format: "marshal_gz")
        content_type "application/x-gzip"
        generate_specs_gz
      end

      get "/latest_specs.4.8.gz" do
        log_event("latest_specs_access", format: "marshal_gz")
        content_type "application/x-gzip"
        generate_specs_gz
      end

      get "/prerelease_specs.4.8.gz" do
        log_event("prerelease_specs_access", format: "marshal_gz")
        content_type "application/x-gzip"
        # Return empty prerelease specs
        specs = []
        io = StringIO.new
        gz = Zlib::GzipWriter.new(io)
        gz.write(Marshal.dump(specs))
        gz.close
        io.string
      end

      # Quick gem spec lookup (used by bundler for dependency resolution)
      get "/quick/Marshal.4.8/:gemspec" do
        gemspec_file = params[:gemspec]
        gem_name = gemspec_file.sub(/\.gemspec(\.rz)?$/, "").sub(/-[\d.]+$/, "")
        log_event("quick_spec_lookup", gem_name: gem_name, file: gemspec_file)

        gem_info = HOSTED_GEMS[gem_name]
        unless gem_info
          log_event("unknown_quick_spec", gem_name: gem_name, suspicious: true)
          halt 404
        end

        content_type "application/octet-stream"
        generate_fake_gemspec_marshal(gem_name, gem_info)
      end

      # ─── Gem Upload Endpoint (Primary Attack Surface) ───────────────

      # Gem upload - captures malicious gem uploads
      post "/upload" do
        log_event("gem_upload_attempt", {
          content_type: request.content_type,
          content_length: request.content_length,
          source_ip: request.ip
        })
        handle_gem_upload
      end

      post "/api/v1/gems" do
        log_event("api_gem_push_attempt", {
          content_type: request.content_type,
          content_length: request.content_length,
          source_ip: request.ip,
          authorization: request.env["HTTP_AUTHORIZATION"]&.slice(0, 20)
        })
        handle_gem_upload
      end

      # Gem yank (removing a gem)
      delete "/api/v1/gems/yank" do
        gem_name = params[:gem_name] || params[:name]
        version = params[:version]
        log_event("gem_yank_attempt", {
          gem_name: gem_name,
          version: version,
          source_ip: request.ip,
          authorization: request.env["HTTP_AUTHORIZATION"]&.slice(0, 20),
          suspicious: true
        })
        content_type "application/json"
        status 403
        JSON.generate({ error: "Forbidden", message: "Insufficient permissions to yank gems" })
      end

      # ─── Gem Download Endpoints ────────────────────────────────────

      get "/gems/:filename" do
        filename = params[:filename]
        gem_name = filename.sub(/\.gem$/, "").sub(/-[\d.]+$/, "")
        log_event("gem_download", gem_name: gem_name, filename: filename)

        gem_info = HOSTED_GEMS[gem_name]
        unless gem_info
          log_event("unknown_gem_download", gem_name: gem_name, suspicious: true)
          halt 404
        end

        content_type "application/octet-stream"
        headers["Content-Disposition"] = "attachment; filename=\"#{filename}\""
        generate_fake_gem_file(gem_name, gem_info)
      end

      # ─── Authentication Endpoints ──────────────────────────────────

      get "/api/v1/api_key" do
        log_event("api_key_request", {
          source_ip: request.ip,
          authorization: request.env["HTTP_AUTHORIZATION"]&.slice(0, 20),
          suspicious: true
        })
        content_type "text/plain"
        status 401
        "Unauthorized - invalid credentials"
      end

      # ─── Search Endpoints ──────────────────────────────────────────

      get "/api/v1/search.json" do
        query = params[:query] || ""
        log_event("gem_search", query: query, source_ip: request.ip)

        results = HOSTED_GEMS.select { |name, _| name.include?(query.downcase) }
        content_type "application/json"
        JSON.pretty_generate(results.map { |name, info|
          { name: name, version: info[:version], info: info[:summary], downloads: info[:downloads] }
        })
      end

      # ─── Error Handlers ────────────────────────────────────────────

      not_found do
        log_event("not_found", path: request.path, method: request.request_method)
        content_type "text/html"
        "<h1>404 - Not Found</h1><p>The requested gem or resource was not found.</p>"
      end

      error do
        log_event("server_error", {
          path: request.path,
          error: env["sinatra.error"]&.message
        })
        content_type "text/html"
        status 500
        "<h1>500 - Internal Server Error</h1>"
      end

      private

      # ─── Gem Upload Handling ───────────────────────────────────────

      def handle_gem_upload
        raw_body = request.env["honeypot.raw_body"] || request.body.read

        if raw_body.bytesize > MAX_UPLOAD_SIZE
          log_event("oversized_upload", size: raw_body.bytesize)
          halt 413, JSON.generate({ error: "Gem too large" })
        end

        # Calculate hashes of the uploaded content
        sha256 = Digest::SHA256.hexdigest(raw_body)
        md5 = Digest::MD5.hexdigest(raw_body)

        # Store the uploaded sample for analysis
        sample_path = store_sample(raw_body, sha256)

        # Try to extract gem metadata
        metadata = extract_gem_metadata(raw_body)

        log_event("gem_upload_captured", {
          sha256: sha256,
          md5: md5,
          size: raw_body.bytesize,
          sample_path: sample_path,
          metadata: metadata,
          headers: extract_request_headers,
          source_ip: request.ip,
          severity: "critical"
        })

        # Return a realistic success response to keep the attacker engaged
        content_type "application/json"
        status 200
        JSON.generate({
          status: "success",
          message: "Gem uploaded successfully",
          name: metadata[:name] || "unknown",
          version: metadata[:version] || "0.0.0"
        })
      end

      def store_sample(data, sha256)
        sample_dir = File.join(SAMPLES_DIR, "gems", Date.today.iso8601)
        FileUtils.mkdir_p(sample_dir)
        sample_path = File.join(sample_dir, "#{sha256}.gem")
        File.binwrite(sample_path, data)
        sample_path
      rescue StandardError => e
        log_event("sample_storage_error", error: e.message)
        nil
      end

      def extract_gem_metadata(data)
        io = StringIO.new(data)
        reader = Gem::Package.new(io)
        spec = reader.spec
        {
          name: spec.name,
          version: spec.version.to_s,
          authors: spec.authors,
          summary: spec.summary,
          description: spec.description,
          executables: spec.executables,
          extensions: spec.extensions,
          files: spec.files&.first(50),
          dependencies: spec.dependencies.map { |d| { name: d.name, requirement: d.requirement.to_s } }
        }
      rescue StandardError => e
        { parse_error: e.message, raw_size: data.bytesize }
      end

      # ─── Response Generation ───────────────────────────────────────

      def render_geminabox_dashboard
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>Internal Gem Repository - Geminabox</title>
            <style>
              body { font-family: Helvetica, Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }
              .header { background: #c0392b; color: white; padding: 20px 40px; }
              .header h1 { margin: 0; font-size: 24px; }
              .header p { margin: 5px 0 0; opacity: 0.8; }
              .container { max-width: 960px; margin: 30px auto; padding: 0 20px; }
              .gem-count { background: white; padding: 20px; border-radius: 4px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
              .upload-form { background: white; padding: 20px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
              .upload-form h2 { margin-top: 0; }
              .btn { background: #c0392b; color: white; border: none; padding: 10px 20px; cursor: pointer; border-radius: 3px; }
              table { width: 100%; border-collapse: collapse; }
              th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #eee; }
              th { background: #fafafa; font-weight: 600; }
              a { color: #c0392b; text-decoration: none; }
              a:hover { text-decoration: underline; }
              .footer { text-align: center; padding: 20px; color: #999; font-size: 12px; }
            </style>
          </head>
          <body>
            <div class="header">
              <h1>Internal Gem Repository</h1>
              <p>Private gem server for internal packages - Geminabox 3.0.0</p>
            </div>
            <div class="container">
              <div class="gem-count">
                <h2>#{HOSTED_GEMS.size} gems hosted</h2>
                <p>Total downloads: #{HOSTED_GEMS.values.sum { |g| g[:downloads] }.to_s.gsub(/(\d)(?=(\d{3})+$)/, '\\1,')}</p>
              </div>
              <div class="upload-form">
                <h2>Upload a gem</h2>
                <form action="/upload" method="post" enctype="multipart/form-data">
                  <input type="file" name="file" accept=".gem" />
                  <button type="submit" class="btn">Upload</button>
                </form>
              </div>
              <h2>Hosted Gems</h2>
              <table>
                <thead><tr><th>Name</th><th>Version</th><th>Downloads</th><th>Authors</th></tr></thead>
                <tbody>
                  #{HOSTED_GEMS.map { |name, info| "<tr><td><a href=\"/api/v1/gems/#{name}.json\">#{name}</a></td><td>#{info[:version]}</td><td>#{info[:downloads]}</td><td>#{info[:authors].join(', ')}</td></tr>" }.join("\n              ")}
                </tbody>
              </table>
            </div>
            <div class="footer">Powered by Geminabox 3.0.0 | Ruby #{RUBY_VERSION}</div>
          </body>
          </html>
        HTML
      end

      def render_gem_listing_html
        render_geminabox_dashboard
      end

      def build_gem_detail(name, info)
        {
          name: name,
          version: info[:version],
          authors: info[:authors].join(", "),
          info: info[:summary],
          description: info[:description],
          licenses: info[:licenses],
          homepage_uri: info[:homepage],
          project_uri: "#{request.base_url}/gems/#{name}",
          gem_uri: "#{request.base_url}/gems/#{name}-#{info[:version]}.gem",
          downloads: info[:downloads],
          sha: info[:sha256],
          dependencies: {
            runtime: info[:dependencies].map { |n, r| { name: n, requirements: r } }
          },
          built_at: "2024-01-15T00:00:00.000Z",
          created_at: "2023-06-01T00:00:00.000Z",
          platform: "ruby",
          ruby_version: ">= 3.1.0",
          rubygems_version: ">= 3.4.0"
        }
      end

      def generate_specs_gz
        specs = HOSTED_GEMS.map do |name, info|
          [name, Gem::Version.new(info[:version]), "ruby"]
        end
        io = StringIO.new
        gz = Zlib::GzipWriter.new(io)
        gz.write(Marshal.dump(specs))
        gz.close
        io.string
      end

      def generate_fake_gemspec_marshal(name, info)
        spec = Gem::Specification.new do |s|
          s.name = name
          s.version = info[:version]
          s.authors = info[:authors]
          s.summary = info[:summary]
          s.description = info[:description]
          s.homepage = info[:homepage]
          s.licenses = info[:licenses]
          s.required_ruby_version = ">= 3.1.0"
          info[:dependencies].each do |dep_name, dep_req|
            s.add_runtime_dependency(dep_name, dep_req)
          end
        end
        Marshal.dump(spec)
      end

      def generate_fake_gem_file(name, info)
        # Generate a minimal but valid-looking .gem file structure
        spec = Gem::Specification.new do |s|
          s.name = name
          s.version = info[:version]
          s.authors = info[:authors]
          s.summary = info[:summary]
          s.files = ["lib/#{name.tr('-', '/')}.rb"]
        end
        # Return marshalled spec as a placeholder gem content
        Marshal.dump(spec)
      end

      # ─── Logging ───────────────────────────────────────────────────

      def log_event(event_type, data = {})
        event = {
          timestamp: Time.now.utc.iso8601(6),
          service: "fake_gem_server",
          event_type: event_type,
          source_ip: request.ip,
          session_id: request.env["honeypot.session_id"],
          request_id: request.env["honeypot.request_id"],
          data: data
        }

        log_file = File.join(LOG_DIR, "gem_server_events_#{Date.today.iso8601}.jsonl")
        File.open(log_file, "a") do |f|
          f.flock(File::LOCK_EX)
          f.puts(JSON.generate(event))
        end
      rescue StandardError
        # Never crash the honeypot due to logging failures
      end

      def extract_request_headers
        headers = {}
        request.env.each do |key, value|
          next unless key.start_with?("HTTP_") || %w[CONTENT_TYPE CONTENT_LENGTH].include?(key)
          header_name = key.sub(/^HTTP_/, "").tr("_", "-").downcase
          headers[header_name] = value.to_s.slice(0, 2048)
        end
        headers
      end
    end
  end
end
