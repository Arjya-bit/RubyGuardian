# frozen_string_literal: true

# RubyGuardian Honeypot - Fake CI Runner
# Emulates a GitLab CI runner with exposed secrets, build logs, and artifacts.
# Designed to detect lateral movement and credential harvesting by attackers.
#
# HONEYPOT WARNING: All credentials, tokens, and secrets are fabricated canaries.
# Any use of these credentials triggers an alert.

require "sinatra/base"
require "json"
require "securerandom"
require "digest"
require "time"
require "yaml"
require "fileutils"

module RubyGuardian
  module Honeypot
    class FakeCIRunner < Sinatra::Base
      set :environment, :production
      set :show_exceptions, false
      set :dump_errors, false
      set :logging, true

      LOG_DIR = ENV.fetch("HONEYPOT_LOG_DIR", "/var/log/rubyguardian/honeypot")
      CONFIG_PATH = ENV.fetch("CI_RUNNER_CONFIG", File.join(__dir__, "config.yml"))

      # Fake environment variables that appear leaked
      FAKE_ENV_VARS = {
        "CI" => "true",
        "CI_SERVER" => "yes",
        "GITLAB_CI" => "true",
        "CI_SERVER_URL" => "https://gitlab.internal.example.com",
        "CI_PROJECT_NAME" => "internal-webapp",
        "CI_PROJECT_NAMESPACE" => "engineering/backend",
        "CI_PROJECT_PATH" => "engineering/backend/internal-webapp",
        "CI_PIPELINE_ID" => "847291",
        "CI_PIPELINE_URL" => "https://gitlab.internal.example.com/engineering/backend/internal-webapp/-/pipelines/847291",
        "CI_COMMIT_SHA" => "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "CI_COMMIT_BRANCH" => "main",
        "CI_RUNNER_ID" => "runner-01",
        "CI_RUNNER_DESCRIPTION" => "shared-runner-01.ci.internal",
        "CI_RUNNER_VERSION" => "16.8.0",
        "CI_REGISTRY" => "registry.internal.example.com",
        "CI_REGISTRY_IMAGE" => "registry.internal.example.com/engineering/backend/internal-webapp",
        "RAILS_ENV" => "production",
        "RACK_ENV" => "production",
        "DATABASE_URL" => "postgres://deploy:D3pl0y$ecret@db.internal:5432/webapp_prod",
        "REDIS_URL" => "redis://cache.internal:6379/0",
        "SECRET_KEY_BASE" => "f4k3s3cr3tk3yb4s3th4t1sv3ryl0ng4ndc0mpl3x123456789",
        "AWS_ACCESS_KEY_ID" => "AKIAFAKE1234567890AB",
        "AWS_SECRET_ACCESS_KEY" => "fAkEsEcReTkEy1234567890abcdefghijklmnop",
        "AWS_DEFAULT_REGION" => "us-east-1",
        "GITHUB_TOKEN" => "ghp_fake1234567890abcdefghijklmnopqrstuv",
        "DOCKER_REGISTRY_PASSWORD" => "d0ck3r_r3g1stry_p4ssw0rd",
        "SLACK_BOT_TOKEN" => "xoxb-fake-1234567890-abcdefghijklmnop",
        "SENTRY_DSN" => "https://fake123@sentry.internal.example.com/42",
        "STRIPE_SECRET_KEY" => "sk_test_PLACEHOLDER_NOT_A_REAL_KEY_000000",
        "SENDGRID_API_KEY" => "SG.PLACEHOLDER_NOT_A_REAL_KEY_0000000000000"
      }.freeze

      # Fake build jobs with realistic-looking logs
      FAKE_JOBS = [
        {
          id: 4_291_001,
          name: "rspec",
          stage: "test",
          status: "success",
          duration: 245.7,
          started_at: "2024-02-15T10:30:00Z",
          finished_at: "2024-02-15T10:34:05Z",
          runner: "shared-runner-01",
          commit_sha: "a1b2c3d4"
        },
        {
          id: 4_291_002,
          name: "rubocop",
          stage: "lint",
          status: "success",
          duration: 32.1,
          started_at: "2024-02-15T10:30:00Z",
          finished_at: "2024-02-15T10:30:32Z",
          runner: "shared-runner-01",
          commit_sha: "a1b2c3d4"
        },
        {
          id: 4_291_003,
          name: "deploy:production",
          stage: "deploy",
          status: "success",
          duration: 89.3,
          started_at: "2024-02-15T10:35:00Z",
          finished_at: "2024-02-15T10:36:29Z",
          runner: "deploy-runner-01",
          commit_sha: "a1b2c3d4"
        },
        {
          id: 4_291_004,
          name: "security_scan",
          stage: "test",
          status: "failed",
          duration: 120.0,
          started_at: "2024-02-15T10:30:00Z",
          finished_at: "2024-02-15T10:32:00Z",
          runner: "shared-runner-01",
          commit_sha: "a1b2c3d4"
        }
      ].freeze

      # Fake project variables (secrets)
      FAKE_PROJECT_VARIABLES = [
        { key: "DEPLOY_SSH_KEY", value: "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYDATA1234567890abcdef\n-----END RSA PRIVATE KEY-----", protected: true, masked: true, environment_scope: "production" },
        { key: "DATABASE_PASSWORD", value: "D3pl0y$ecret", protected: true, masked: true, environment_scope: "*" },
        { key: "API_SECRET", value: "super_secret_api_key_12345", protected: false, masked: false, environment_scope: "*" },
        { key: "DOCKER_AUTH_CONFIG", value: '{"auths":{"registry.internal.example.com":{"auth":"ZGVwbG95OmQwY2szci1wNHNz"}}}', protected: true, masked: true, environment_scope: "*" },
        { key: "K8S_TOKEN", value: "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.fake_k8s_token_data", protected: true, masked: true, environment_scope: "production" },
        { key: "VAULT_TOKEN", value: "hvs.PLACEHOLDER-NOT-REAL-TOKEN", protected: true, masked: true, environment_scope: "*" }
      ].freeze

      before do
        log_request
        set_realistic_headers
      end

      # ─── Runner Status API ─────────────────────────────────────────

      get "/api/v4/runners" do
        log_event("runners_list_access")
        content_type "application/json"
        JSON.pretty_generate([
          {
            id: 1,
            description: "shared-runner-01.ci.internal",
            ip_address: "172.20.1.10",
            active: true,
            is_shared: true,
            runner_type: "instance_type",
            name: "shared-runner-01",
            online: true,
            status: "online",
            tag_list: %w[ruby docker linux],
            version: "16.8.0",
            architecture: "amd64",
            platform: "linux",
            contacted_at: Time.now.utc.iso8601,
            projects: [
              { id: 42, name: "internal-webapp", path_with_namespace: "engineering/backend/internal-webapp" },
              { id: 43, name: "api-gateway", path_with_namespace: "engineering/backend/api-gateway" }
            ]
          },
          {
            id: 2,
            description: "deploy-runner-01.ci.internal",
            ip_address: "172.20.1.11",
            active: true,
            is_shared: false,
            runner_type: "project_type",
            name: "deploy-runner-01",
            online: true,
            status: "online",
            tag_list: %w[deploy production],
            version: "16.8.0"
          }
        ])
      end

      get "/api/v4/runners/:id" do
        runner_id = params[:id]
        log_event("runner_detail_access", runner_id: runner_id)
        content_type "application/json"
        JSON.pretty_generate({
          id: runner_id.to_i,
          description: "shared-runner-#{runner_id}.ci.internal",
          active: true,
          version: "16.8.0",
          ip_address: "172.20.1.#{10 + runner_id.to_i}",
          tag_list: %w[ruby docker linux],
          status: "online"
        })
      end

      # ─── Job Listing API ───────────────────────────────────────────

      get "/api/v4/jobs" do
        log_event("jobs_list_access")
        content_type "application/json"
        JSON.pretty_generate(FAKE_JOBS)
      end

      get "/api/v4/jobs/:id" do
        job_id = params[:id].to_i
        log_event("job_detail_access", job_id: job_id)
        job = FAKE_JOBS.find { |j| j[:id] == job_id } || FAKE_JOBS.first
        content_type "application/json"
        JSON.pretty_generate(job)
      end

      # ─── Build Logs (with deliberately leaked secrets) ─────────────

      get "/builds/:id/log" do
        build_id = params[:id]
        log_event("build_log_access", build_id: build_id, severity: "high")
        content_type "text/plain"
        generate_fake_build_log(build_id)
      end

      get "/api/v4/jobs/:id/trace" do
        job_id = params[:id]
        log_event("job_trace_access", job_id: job_id, severity: "high")
        content_type "text/plain"
        generate_fake_build_log(job_id)
      end

      # ─── Build Artifacts ───────────────────────────────────────────

      get "/api/v4/jobs/:id/artifacts" do
        job_id = params[:id]
        log_event("artifact_download", job_id: job_id, severity: "high")
        content_type "application/gzip"
        headers["Content-Disposition"] = "attachment; filename=\"artifacts_#{job_id}.tar.gz\""
        generate_fake_artifact
      end

      # ─── Project Variables (Secrets) ───────────────────────────────

      get "/api/v4/projects/:id/variables" do
        project_id = params[:id]
        log_event("project_variables_access", {
          project_id: project_id,
          severity: "critical",
          suspicious: true
        })
        content_type "application/json"
        JSON.pretty_generate(FAKE_PROJECT_VARIABLES)
      end

      get "/api/v4/projects/:project_id/variables/:key" do
        log_event("specific_variable_access", {
          project_id: params[:project_id],
          variable_key: params[:key],
          severity: "critical"
        })
        variable = FAKE_PROJECT_VARIABLES.find { |v| v[:key] == params[:key] }
        halt 404, JSON.generate({ message: "404 Variable Not Found" }) unless variable
        content_type "application/json"
        JSON.pretty_generate(variable)
      end

      # ─── Environment Variables Endpoint ────────────────────────────

      get "/api/v4/runners/:id/env" do
        log_event("runner_env_access", runner_id: params[:id], severity: "critical")
        content_type "application/json"
        JSON.pretty_generate(FAKE_ENV_VARS)
      end

      # Simulates /proc/self/environ access
      get "/proc/self/environ" do
        log_event("proc_environ_access", severity: "critical", suspicious: true)
        content_type "text/plain"
        FAKE_ENV_VARS.map { |k, v| "#{k}=#{v}" }.join("\x00")
      end

      # ─── Pipeline API ─────────────────────────────────────────────

      get "/api/v4/projects/:id/pipelines" do
        log_event("pipeline_list_access", project_id: params[:id])
        content_type "application/json"
        JSON.pretty_generate([
          { id: 847_291, status: "success", ref: "main", sha: "a1b2c3d4", created_at: "2024-02-15T10:29:00Z" },
          { id: 847_290, status: "failed", ref: "feature/api-v2", sha: "e5f6a7b8", created_at: "2024-02-15T09:15:00Z" },
          { id: 847_289, status: "success", ref: "main", sha: "c9d0e1f2", created_at: "2024-02-14T16:45:00Z" }
        ])
      end

      # ─── Health and Status ─────────────────────────────────────────

      get "/health" do
        content_type "application/json"
        JSON.generate({ status: "ok", version: "16.8.0", uptime: rand(86_400..604_800) })
      end

      get "/" do
        log_event("root_access")
        content_type "text/html"
        render_runner_dashboard
      end

      not_found do
        log_event("not_found", path: request.path)
        content_type "application/json"
        JSON.generate({ message: "404 Not Found" })
      end

      private

      # ─── Build Log Generation ──────────────────────────────────────

      def generate_fake_build_log(build_id)
        <<~LOG
          Running with gitlab-runner 16.8.0 (abc12345)
            on shared-runner-01.ci.internal #{SecureRandom.hex(8)}
          Preparing the "docker" executor
          Using Docker executor with image ruby:3.2.2-alpine ...
          Pulling docker image ruby:3.2.2-alpine ...
          Using docker image sha256:#{SecureRandom.hex(32)} for ruby:3.2.2-alpine ...
          Preparing environment
          Running on runner-#{SecureRandom.hex(4)}-project-42-concurrent-0 via shared-runner-01...
          Getting source from Git repository
          Fetching changes with git depth set to 20...
          Initialized empty Git repository in /builds/engineering/backend/internal-webapp/.git/
          Created fresh repository.
          Checking out a1b2c3d4 as main...
          Skipping Git submodules setup
          Restoring cache
          Checking cache for ruby-gems-#{Digest::SHA256.hexdigest("cache")[0..7]}...
          Successfully extracted cache
          Executing "step_script" stage of the job script
          $ bundle install --deployment --without development
          Fetching gem metadata from https://rubygems.org/........
          Using bundler 2.5.6
          Installing rake 13.1.0
          Installing concurrent-ruby 1.2.3
          Bundle complete! 47 Gemfile dependencies, 189 gems now installed.
          $ echo "Setting up environment..."
          Setting up environment...
          $ export DATABASE_URL=#{FAKE_ENV_VARS['DATABASE_URL']}
          $ export REDIS_URL=#{FAKE_ENV_VARS['REDIS_URL']}
          $ export SECRET_KEY_BASE=#{FAKE_ENV_VARS['SECRET_KEY_BASE']}
          $ export AWS_ACCESS_KEY_ID=#{FAKE_ENV_VARS['AWS_ACCESS_KEY_ID']}
          $ export AWS_SECRET_ACCESS_KEY=#{FAKE_ENV_VARS['AWS_SECRET_ACCESS_KEY']}
          $ bundle exec rake db:migrate
          == 20240201120000 CreateUsers: migrating ==================
          -- create_table(:users)
             -> 0.0024s
          == 20240201120000 CreateUsers: migrated (0.0025s) =========
          $ bundle exec rspec --format documentation
          .........................................................
          Finished in 12.34 seconds (files took 3.45 seconds to load)
          142 examples, 0 failures
          $ echo "Deploying to production..."
          Deploying to production...
          $ cap production deploy
          INFO [#{SecureRandom.hex(4)}] Running /usr/bin/env mkdir -p /opt/webapp/releases/20240215103000 as deploy@app-01.internal
          INFO [#{SecureRandom.hex(4)}] Finished in 0.542 seconds
          INFO [#{SecureRandom.hex(4)}] Running /usr/bin/env bundle exec puma -C /opt/webapp/shared/puma.rb --daemon as deploy@app-01.internal
          INFO Deploy complete! Build #{build_id} successful.
          Saving cache for successful job
          Creating cache ruby-gems-#{Digest::SHA256.hexdigest("cache")[0..7]}...
          Archive is up to date!
          Cleaning up project directory and file based variables
          Job succeeded
        LOG
      end

      def generate_fake_artifact
        # Generate a minimal tar.gz-like binary blob
        content = "CANARY_ARTIFACT_#{SecureRandom.hex(16)}"
        io = StringIO.new
        gz = Zlib::GzipWriter.new(io)
        gz.write(content)
        gz.close
        io.string
      rescue StandardError
        "FAKE_ARTIFACT_DATA"
      end

      # ─── Dashboard Rendering ───────────────────────────────────────

      def render_runner_dashboard
        <<~HTML
          <!DOCTYPE html>
          <html>
          <head>
            <title>GitLab Runner - shared-runner-01</title>
            <style>
              body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #fafafa; margin: 0; }
              .header { background: #292961; color: white; padding: 16px 24px; }
              .header h1 { margin: 0; font-size: 20px; }
              .container { max-width: 800px; margin: 24px auto; padding: 0 16px; }
              .card { background: white; border: 1px solid #ddd; border-radius: 4px; padding: 16px; margin-bottom: 16px; }
              .card h2 { margin-top: 0; font-size: 16px; }
              .status { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; }
              .status.online { background: #d4edda; color: #155724; }
              table { width: 100%; border-collapse: collapse; }
              th, td { text-align: left; padding: 8px; border-bottom: 1px solid #eee; font-size: 14px; }
              th { font-weight: 600; color: #666; }
              code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
            </style>
          </head>
          <body>
            <div class="header">
              <h1>GitLab Runner Administration</h1>
            </div>
            <div class="container">
              <div class="card">
                <h2>Runner: shared-runner-01 <span class="status online">online</span></h2>
                <table>
                  <tr><th>Version</th><td>16.8.0</td></tr>
                  <tr><th>Architecture</th><td>amd64</td></tr>
                  <tr><th>Platform</th><td>linux</td></tr>
                  <tr><th>Executor</th><td>docker</td></tr>
                  <tr><th>IP Address</th><td>172.20.1.10</td></tr>
                  <tr><th>Tags</th><td><code>ruby</code> <code>docker</code> <code>linux</code></td></tr>
                </table>
              </div>
              <div class="card">
                <h2>Recent Jobs</h2>
                <table>
                  <thead><tr><th>ID</th><th>Name</th><th>Stage</th><th>Status</th><th>Duration</th></tr></thead>
                  <tbody>
                    #{FAKE_JOBS.map { |j| "<tr><td>#{j[:id]}</td><td>#{j[:name]}</td><td>#{j[:stage]}</td><td>#{j[:status]}</td><td>#{j[:duration]}s</td></tr>" }.join}
                  </tbody>
                </table>
              </div>
            </div>
          </body>
          </html>
        HTML
      end

      # ─── Logging ───────────────────────────────────────────────────

      def log_request
        data = {
          timestamp: Time.now.utc.iso8601(6),
          service: "fake_ci_runner",
          source_ip: request.ip,
          method: request.request_method,
          path: request.path,
          user_agent: request.user_agent,
          headers: extract_headers
        }
        write_log("ci_runner_requests", data)
      end

      def log_event(event_type, data = {})
        event = {
          timestamp: Time.now.utc.iso8601(6),
          service: "fake_ci_runner",
          event_type: event_type,
          source_ip: request.ip,
          request_id: request.env["honeypot.request_id"],
          data: data
        }
        write_log("ci_runner_events", event)
      end

      def set_realistic_headers
        response.headers["Server"] = "nginx/1.24.0"
        response.headers["X-Request-Id"] = SecureRandom.uuid
        response.headers["X-Runtime"] = format("%.3f", rand(0.01..0.2))
        response.headers["X-GitLab-Runner-Version"] = "16.8.0"
      end

      def extract_headers
        headers = {}
        request.env.each do |key, value|
          next unless key.start_with?("HTTP_") || %w[CONTENT_TYPE CONTENT_LENGTH].include?(key)
          headers[key.sub(/^HTTP_/, "").tr("_", "-").downcase] = value.to_s.slice(0, 1024)
        end
        headers
      end

      def write_log(log_type, data)
        log_file = File.join(LOG_DIR, "#{log_type}_#{Date.today.iso8601}.jsonl")
        File.open(log_file, "a") do |f|
          f.flock(File::LOCK_EX)
          f.puts(JSON.generate(data))
        end
      rescue StandardError
        # Silent fail
      end
    end
  end
end
