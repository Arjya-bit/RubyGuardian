# frozen_string_literal: true

# RubyGuardian Honeypot - Base Application Controller
# All requests are logged and forwarded to the honeypot capture engine.
# The controller simulates a real Rails application while capturing
# every interaction for threat intelligence.

class ApplicationController < ActionController::Base
  # Deliberately skip CSRF protection (appears misconfigured)
  skip_before_action :verify_authenticity_token, raise: false

  before_action :log_to_honeypot
  before_action :set_realistic_headers

  # Catch-all route handler for unmapped paths
  def catch_all
    path = params[:path] || request.path
    log_capture_event("catch_all", path: path, method: request.method)

    # Return different responses based on what the attacker is looking for
    case path
    when /\.(php|asp|aspx|jsp|cgi)$/
      render_fake_error("Not Found", status: 404)
    when /\.(sql|bak|backup|dump|old|orig|save|swp|tmp)$/
      log_capture_event("sensitive_file_probe", path: path)
      render_fake_error("Forbidden", status: 403)
    when /\.(git|svn|hg|bzr)/
      log_capture_event("vcs_probe", path: path)
      render_fake_error("Forbidden", status: 403)
    when /api/
      render json: { error: "endpoint_not_found", message: "No route matches #{path}" }, status: 404
    else
      render_fake_error("Not Found", status: 404)
    end
  end

  protected

  # Log every request to the honeypot capture engine
  def log_to_honeypot
    capture_data = {
      timestamp: Time.now.utc.iso8601(6),
      request_id: request.request_id,
      remote_ip: request.remote_ip,
      method: request.method,
      path: request.fullpath,
      host: request.host,
      port: request.port,
      scheme: request.scheme,
      user_agent: request.user_agent,
      referer: request.referer,
      content_type: request.content_type,
      content_length: request.content_length,
      headers: extract_headers,
      params: filtered_params,
      cookies: request.cookies.keys,
      session_id: session.id&.to_s&.slice(0, 8),
      ssl: request.ssl?
    }

    # Write to capture log
    write_capture_log("request", capture_data)

    # Check for known attack patterns in the request
    detect_attack_patterns(capture_data)
  end

  # Set response headers that make the app look realistic
  def set_realistic_headers
    response.headers["X-Request-Id"] = request.request_id
    response.headers["X-Runtime"] = format("%.6f", rand(0.01..0.5))
    response.headers["X-Powered-By"] = "Phusion Passenger 6.0.18"
    response.headers["Server"] = "nginx/1.24.0 + Phusion Passenger 6.0.18"
    response.headers["X-Content-Type-Options"] = "nosniff"
    # Deliberately omit security headers that would normally be present
  end

  # Extract relevant HTTP headers
  def extract_headers
    headers = {}
    request.headers.each do |key, value|
      next unless key.start_with?("HTTP_") || %w[CONTENT_TYPE CONTENT_LENGTH].include?(key)

      header_name = key.sub(/^HTTP_/, "").tr("_", "-").downcase
      headers[header_name] = value.to_s.slice(0, 2048)
    end
    headers
  end

  # Filter sensitive parameter values for logging
  def filtered_params
    params.to_unsafe_h.except("controller", "action").transform_values do |v|
      v.is_a?(String) && v.length > 10_000 ? "#{v.slice(0, 10_000)}...[truncated]" : v
    end
  rescue StandardError
    { raw: request.raw_post.to_s.slice(0, 50_000) }
  end

  # Detect common attack patterns in incoming requests
  def detect_attack_patterns(data)
    patterns = {
      sql_injection: /('|\bOR\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|--|\/\*)/i,
      xss: /(<script|javascript:|onerror=|onload=|<iframe|<svg)/i,
      command_injection: /(;|\||`|\$\(|%0a|%0d|\bwget\b|\bcurl\b|\bnc\b)/i,
      path_traversal: /(\.\.\/|\.\.\\|%2e%2e|%252e)/i,
      code_injection: /(\beval\b|\bexec\b|\bsystem\b|\brequire\b|\bload\b|\b__send__\b)/i,
      deserialization: /(\bMarshal\b|\bYAML\.load\b|\bJSON\.parse\b.*\bclass\b)/i,
      ssrf: /(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.|172\.(1[6-9]|2|3[01])\.)/i
    }

    fullpath = data[:path].to_s
    body = request.raw_post.to_s
    all_params = data[:params].to_s

    check_target = "#{fullpath} #{body} #{all_params}"

    patterns.each do |attack_type, pattern|
      if check_target.match?(pattern)
        log_capture_event("attack_detected",
          type: attack_type,
          source_ip: data[:remote_ip],
          path: data[:path],
          evidence: check_target.match(pattern)&.to_s&.slice(0, 500)
        )
      end
    end
  end

  # Log a capture event to the honeypot engine
  def log_capture_event(event_type, data = {})
    event = {
      timestamp: Time.now.utc.iso8601(6),
      event_type: event_type,
      source_ip: request.remote_ip,
      request_id: request.request_id,
      data: data
    }

    write_capture_log("event", event)
  end

  # Write data to the capture log file
  def write_capture_log(log_type, data)
    log_dir = ENV.fetch("HONEYPOT_LOG_DIR", "/var/log/rubyguardian/honeypot")
    log_file = File.join(log_dir, "#{log_type}_#{Date.today.iso8601}.jsonl")

    File.open(log_file, "a") do |f|
      f.flock(File::LOCK_EX)
      f.puts(JSON.generate(data))
    end
  rescue StandardError => e
    Rails.logger.error("Honeypot capture error: #{e.message}")
  end

  # Render a fake Rails error page
  def render_fake_error(message, status: 500)
    respond_to do |format|
      format.html do
        render inline: fake_error_html(message, status), status: status, layout: false
      end
      format.json do
        render json: { error: message, status: status }, status: status
      end
      format.any do
        head status
      end
    end
  end

  # Generate a realistic Rails error page
  def fake_error_html(message, status)
    <<~HTML
      <!DOCTYPE html>
      <html>
      <head>
        <title>#{message} (#{status})</title>
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <style>
          body { background-color: #EFEFEF; color: #2E2F30; font-family: arial, sans-serif; margin: 0; }
          .rails-default-error-page { width: 500px; margin: 100px auto; }
          h1 { font-size: 26px; color: #c00; }
          p { font-size: 14px; line-height: 1.6; }
          .debug { background: #fff; border: 1px solid #ddd; padding: 15px; margin: 20px 0; font-family: monospace; font-size: 12px; overflow-x: auto; }
        </style>
      </head>
      <body>
        <div class="rails-default-error-page">
          <h1>#{message}</h1>
          <p>Rails.root: /opt/webapp/current</p>
          <div class="debug">
            <p>Application: InternalAdminPortal::Application</p>
            <p>Rails version: 7.0.8</p>
            <p>Ruby version: ruby 3.2.2 (2023-03-30) [x86_64-linux]</p>
            <p>Environment: production</p>
            <p>Rack: 3.0.8</p>
          </div>
        </div>
      </body>
      </html>
    HTML
  end
end
