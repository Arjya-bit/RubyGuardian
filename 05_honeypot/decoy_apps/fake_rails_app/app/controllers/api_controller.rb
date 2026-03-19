# frozen_string_literal: true

# RubyGuardian Honeypot - Fake API Controller
# Simulates vulnerable REST API endpoints with intentional weaknesses:
# SQL injection, command injection, SSRF, deserialization, and path traversal.
# All interactions are captured for threat intelligence analysis.
#
# HONEYPOT WARNING: This is a decoy controller. All data is fabricated.

class ApiController < ApplicationController
  # Deliberately skip authentication for some endpoints (appears misconfigured)
  before_action :check_api_token, except: %i[health status]
  skip_before_action :verify_authenticity_token, raise: false

  FAKE_USERS = [
    { id: 1, email: "admin@example.com", name: "Admin User", role: "admin", api_key: "rg_live_sk_51ABC123fake456DEF789", created_at: "2023-01-15" },
    { id: 2, email: "deploy@example.com", name: "Deploy Bot", role: "deployer", api_key: "rg_live_sk_deploy_key_fake_123", created_at: "2023-02-20" },
    { id: 3, email: "developer@example.com", name: "Dev User", role: "developer", api_key: "rg_live_sk_dev_key_fake_456", created_at: "2023-03-10" },
    { id: 4, email: "manager@example.com", name: "Manager User", role: "manager", api_key: "rg_live_sk_mgr_key_fake_789", created_at: "2023-06-01" },
    { id: 5, email: "support@example.com", name: "Support User", role: "support", api_key: "rg_live_sk_sup_key_fake_012", created_at: "2023-08-15" }
  ].freeze

  # ─── User Endpoints ───────────────────────────────────────────────

  # GET /api/v1/users - List all users (deliberately leaks data)
  def index
    log_capture_event("api_users_list", {
      params: filtered_params,
      severity: "medium"
    })

    page = (params[:page] || 1).to_i
    per_page = (params[:per_page] || 25).to_i

    render json: {
      users: FAKE_USERS,
      meta: { page: page, per_page: per_page, total: FAKE_USERS.size, total_pages: 1 }
    }
  end

  # GET /api/v1/users/:id - Show user (SQL injection bait)
  def show
    user_id = params[:id]

    # Detect SQL injection attempts in the ID parameter
    if sql_injection_detected?(user_id)
      log_capture_event("sql_injection_attempt", {
        parameter: "id",
        value: user_id.to_s.slice(0, 5000),
        endpoint: "/api/v1/users/:id",
        severity: "critical",
        attack_type: "sql_injection"
      })
      # Return a realistic SQL error to keep attacker engaged
      render json: simulate_sql_error(user_id), status: 500
      return
    end

    user = FAKE_USERS.find { |u| u[:id] == user_id.to_i }
    if user
      render json: user
    else
      render json: { error: "User not found", id: user_id }, status: 404
    end
  end

  # POST /api/v1/users - Create user
  def create
    log_capture_event("api_user_create_attempt", {
      params: filtered_params,
      severity: "high"
    })
    render json: {
      id: rand(100..999),
      message: "User created successfully",
      user: params.permit(:email, :name, :role).to_h
    }, status: 201
  end

  # PUT /api/v1/users/:id - Update user
  def update
    log_capture_event("api_user_update_attempt", {
      user_id: params[:id],
      params: filtered_params,
      severity: "high"
    })
    render json: { message: "User updated successfully", id: params[:id] }
  end

  # DELETE /api/v1/users/:id - Delete user
  def destroy
    log_capture_event("api_user_delete_attempt", {
      user_id: params[:id],
      severity: "critical"
    })
    render json: { message: "User deleted", id: params[:id] }
  end

  # ─── Code Execution Endpoints (Primary Attack Surface) ────────────

  # POST /api/v1/exec - Fake command execution endpoint
  def exec
    command = params[:cmd] || params[:command] || request.raw_post
    log_capture_event("command_injection_attempt", {
      command: command.to_s.slice(0, 10_000),
      endpoint: "/api/v1/exec",
      severity: "critical",
      attack_type: "command_injection"
    })

    render json: {
      status: "executed",
      command: command.to_s.slice(0, 200),
      output: simulate_command_output(command.to_s),
      exit_code: 0,
      execution_time: format("%.3f", rand(0.01..2.0))
    }
  end

  # POST /api/v1/eval - Fake eval endpoint
  def evaluate
    code = params[:code] || params[:expression] || request.raw_post
    log_capture_event("eval_injection_attempt", {
      code: code.to_s.slice(0, 10_000),
      endpoint: "/api/v1/eval",
      severity: "critical",
      attack_type: "code_injection"
    })

    render json: {
      status: "evaluated",
      expression: code.to_s.slice(0, 200),
      result: simulate_eval_result(code.to_s),
      type: "String"
    }
  end

  # ─── Search Endpoint (SQL Injection Bait) ──────────────────────────

  # GET /api/v1/search?q=...
  def search
    query = params[:q] || params[:query] || ""

    if sql_injection_detected?(query)
      log_capture_event("sql_injection_via_search", {
        query: query.to_s.slice(0, 5000),
        severity: "critical",
        attack_type: "sql_injection"
      })
      render json: simulate_sql_error(query), status: 500
      return
    end

    log_capture_event("api_search", query: query)
    results = FAKE_USERS.select { |u| u[:name].to_s.downcase.include?(query.to_s.downcase) }
    render json: { query: query, results: results, count: results.size }
  end

  # ─── File Access Endpoint (Path Traversal Bait) ───────────────────

  # GET /api/v1/files?path=...
  def files
    file_path = params[:path] || params[:file] || ""

    if path_traversal_detected?(file_path)
      log_capture_event("path_traversal_attempt", {
        path: file_path.to_s.slice(0, 2000),
        severity: "critical",
        attack_type: "path_traversal"
      })
      render json: {
        error: "File read error",
        path: file_path,
        content: simulate_file_content(file_path)
      }
      return
    end

    log_capture_event("api_file_access", path: file_path)
    render json: {
      path: file_path,
      content: "File not found or access denied",
      exists: false
    }, status: 404
  end

  # ─── Import/Export (Deserialization Bait) ──────────────────────────

  # POST /api/v1/import
  def import_data
    data = params[:data] || request.raw_post
    format = params[:format] || "json"

    log_capture_event("deserialization_attempt", {
      format: format,
      data_size: data.to_s.bytesize,
      data_preview: data.to_s.slice(0, 5000),
      severity: "critical",
      attack_type: "deserialization"
    })

    # Check for Marshal/YAML deserialization attacks
    if data.to_s.match?(/Marshal|YAML\.load|ObjectSpace|ERB|Gem::/)
      log_capture_event("unsafe_deserialization_payload", {
        payload: data.to_s.slice(0, 10_000),
        format: format,
        severity: "critical"
      })
    end

    render json: {
      status: "imported",
      records_processed: rand(1..50),
      format: format
    }
  end

  # POST /api/v1/export
  def export_data
    log_capture_event("api_export", params: filtered_params)
    render json: {
      status: "exported",
      download_url: "/api/v1/files?path=exports/data_#{Date.today.iso8601}.csv",
      expires_at: (Time.now + 3600).iso8601
    }
  end

  # ─── SSRF Endpoint ────────────────────────────────────────────────

  # GET /api/v1/fetch?url=...
  def fetch_url
    url = params[:url] || ""

    log_capture_event("ssrf_attempt", {
      url: url.to_s.slice(0, 5000),
      severity: "critical",
      attack_type: "ssrf"
    })

    # Simulate fetching the URL
    render json: {
      url: url,
      status_code: 200,
      content_type: "text/html",
      body: simulate_ssrf_response(url),
      response_time_ms: rand(50..2000)
    }
  end

  # ─── Configuration Endpoint ───────────────────────────────────────

  # GET /api/v1/config
  def config
    log_capture_event("api_config_accessed", severity: "high")
    render json: {
      app_name: "Internal Admin Portal",
      version: "2.4.1",
      environment: "production",
      rails_version: "7.0.8",
      ruby_version: RUBY_VERSION,
      database: {
        adapter: "postgresql",
        host: "db.internal",
        database: "webapp_prod"
      },
      redis_url: "redis://cache.internal:6379/0",
      features: {
        api_v2: true,
        debug_mode: true,
        admin_console: true
      }
    }
  end

  # ─── Health Check ─────────────────────────────────────────────────

  def health
    render json: {
      status: "ok",
      version: "2.4.1",
      uptime: rand(86_400..2_592_000),
      database: "connected",
      redis: "connected",
      timestamp: Time.now.utc.iso8601
    }
  end

  def status
    render json: { status: "operational", api_version: "v2" }
  end

  # ─── Webhook Endpoint ─────────────────────────────────────────────

  def webhook
    log_capture_event("webhook_received", {
      content_type: request.content_type,
      body_size: request.content_length,
      body_preview: request.raw_post.to_s.slice(0, 5000),
      headers: extract_headers,
      severity: "medium"
    })
    render json: { received: true, processed: true }
  end

  private

  # ─── Authentication (Deliberately Weak) ───────────────────────────

  def check_api_token
    token = extract_api_token
    return if token.nil? && request.path.match?(/health|status/)

    log_capture_event("api_auth_attempt", {
      token_preview: token&.slice(0, 10),
      auth_method: detect_auth_method,
      severity: "medium"
    })

    # Accept any token - this is a honeypot
    return if token.present?

    render json: {
      error: "Unauthorized",
      message: "Missing or invalid API token. Include via Authorization header or api_key parameter."
    }, status: 401
  end

  def extract_api_token
    # Check multiple auth methods (all are logged)
    params[:api_key] ||
      params[:token] ||
      request.headers["Authorization"]&.sub(/^Bearer\s+/i, "") ||
      request.headers["X-Api-Key"] ||
      request.cookies["api_token"]
  end

  def detect_auth_method
    if params[:api_key] then "query_param"
    elsif params[:token] then "token_param"
    elsif request.headers["Authorization"] then "bearer"
    elsif request.headers["X-Api-Key"] then "x_api_key"
    elsif request.cookies["api_token"] then "cookie"
    else "none"
    end
  end

  # ─── Attack Detection Helpers ──────────────────────────────────────

  def sql_injection_detected?(input)
    patterns = [
      /'\s*(OR|AND)\s+/i,
      /UNION\s+(ALL\s+)?SELECT/i,
      /;\s*(DROP|DELETE|UPDATE|INSERT|ALTER)\s/i,
      /--\s*$/,
      /\/\*.*\*\//,
      /SLEEP\s*\(/i,
      /BENCHMARK\s*\(/i,
      /WAITFOR\s+DELAY/i,
      /0x[0-9a-fA-F]+/,
      /LOAD_FILE\s*\(/i,
      /INTO\s+(OUT|DUMP)FILE/i
    ]
    patterns.any? { |p| input.to_s.match?(p) }
  end

  def path_traversal_detected?(input)
    patterns = [
      /\.\.\//,
      /\.\.\\/, # rubocop:disable Style/RegexpLiteral
      /%2e%2e/i,
      /%252e/i,
      /\/etc\/(passwd|shadow|hosts)/,
      /\/proc\/self/,
      /\/root\//,
      /\/var\/run\/secrets/
    ]
    patterns.any? { |p| input.to_s.match?(p) }
  end

  # ─── Simulated Responses ──────────────────────────────────────────

  def simulate_sql_error(input)
    {
      error: "PG::SyntaxError",
      message: "ERROR: syntax error at or near \"#{input.to_s.slice(0, 100)}\"",
      detail: "LINE 1: SELECT * FROM users WHERE id = '#{input}'",
      hint: nil,
      query: "SELECT \"users\".* FROM \"users\" WHERE \"users\".\"id\" = $1",
      binds: [input.to_s.slice(0, 200)],
      backtrace: [
        "app/models/user.rb:42:in `find_by_id'",
        "app/controllers/api_controller.rb:38:in `show'",
        "actionpack (7.0.8) lib/action_controller/metal/basic_implicit_render.rb:6",
        "actionpack (7.0.8) lib/abstract_controller/base.rb:228:in `process'",
        "puma (6.4.0) lib/puma/request.rb:94:in `handle_request'"
      ]
    }
  end

  def simulate_command_output(command)
    case command
    when /id\b/
      "uid=1000(webapp) gid=1000(webapp) groups=1000(webapp),27(sudo)"
    when /whoami/
      "webapp"
    when /uname/
      "Linux app-01.internal 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
    when /cat.*passwd/
      "root:x:0:0:root:/root:/bin/bash\nwebapp:x:1000:1000::/opt/webapp:/bin/bash"
    when /ls/
      "app  config  db  Gemfile  Gemfile.lock  lib  log  public  tmp"
    when /env/
      "RAILS_ENV=production\nRACK_ENV=production\nHOME=/opt/webapp"
    when /curl|wget/
      "curl: command not found"
    else
      "sh: #{command.slice(0, 50)}: command not found"
    end
  end

  def simulate_eval_result(code)
    case code
    when /User|ActiveRecord/i
      "#<User id: 1, email: \"admin@example.com\", role: \"admin\">"
    when /ENV/i
      "{\"RAILS_ENV\"=>\"production\"}"
    when /File/i
      "Errno::EACCES: Permission denied"
    else
      code.slice(0, 100).inspect
    end
  end

  def simulate_file_content(path)
    case path
    when /passwd/
      "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
    when /shadow/
      "Permission denied"
    when /ssh/
      "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYDATA..."
    when /environ/
      "RAILS_ENV=production\000DATABASE_URL=postgres://deploy:D3pl0y$ecret@db.internal:5432/webapp_prod"
    when /\.env/
      "SECRET_KEY_BASE=f4k3s3cr3tk3yb4s3..."
    else
      "No such file or directory"
    end
  end

  def simulate_ssrf_response(url)
    case url
    when /169\.254\.169\.254/
      '{"Code":"Success","Type":"AWS:EC2","AccessKeyId":"AKIAFAKE1234567890AB"}'
    when /localhost|127\.0\.0\.1/
      "<html><body><h1>Internal Service</h1></body></html>"
    when /metadata/i
      '{"instance_id":"i-fake1234567890"}'
    else
      "<html><body>Response from #{url}</body></html>"
    end
  end
end
