# frozen_string_literal: true

# RubyGuardian Honeypot - Fake Admin Controller
# Simulates a vulnerable Rails admin panel with exposed debug endpoints,
# weak authentication, and information leakage. Every interaction is
# captured for threat intelligence purposes.
#
# HONEYPOT WARNING: This is a decoy controller. All data is fabricated.

class AdminController < ApplicationController
  # Deliberately weak authentication - session-based with no CSRF
  before_action :check_admin_session, except: %i[login authenticate dot_env
    git_config git_head database_config secrets_config master_key credentials
    gemfile gemfile_lock wordpress_trap phpmyadmin_trap generic_admin_trap]

  # ─── Authentication ────────────────────────────────────────────────

  def login
    log_capture_event("admin_login_page_accessed")
    render inline: render_login_page, layout: false
  end

  def authenticate
    username = params[:username] || params.dig(:user, :username)
    password = params[:password] || params.dig(:user, :password)

    log_capture_event("admin_login_attempt", {
      username: username,
      password_length: password&.length,
      password_hash: password ? Digest::SHA256.hexdigest(password) : nil,
      severity: "high"
    })

    # Accept any credentials but log them - appears to authenticate successfully
    if username.present? && password.present?
      session[:admin_user] = username
      session[:admin_authenticated] = true
      session[:login_time] = Time.now.utc.iso8601

      log_capture_event("admin_login_success_fake", {
        username: username,
        severity: "critical"
      })

      redirect_to "/admin"
    else
      log_capture_event("admin_login_failed", { username: username })
      @error = "Invalid username or password"
      render inline: render_login_page, layout: false, status: 401
    end
  end

  # ─── Admin Dashboard ──────────────────────────────────────────────

  def dashboard
    log_capture_event("admin_dashboard_accessed")
    render inline: render_dashboard_page, layout: false
  end

  def users
    log_capture_event("admin_users_list_accessed")
    render inline: render_users_page, layout: false
  end

  def settings
    log_capture_event("admin_settings_accessed")
    render inline: render_settings_page, layout: false
  end

  def update_settings
    log_capture_event("admin_settings_update_attempt", {
      params: filtered_params,
      severity: "high"
    })
    redirect_to "/admin/settings"
  end

  def logs
    log_capture_event("admin_logs_accessed")
    render inline: render_logs_page, layout: false
  end

  # ─── Debug Console (Primary Attack Surface) ────────────────────────

  def console
    log_capture_event("admin_console_accessed", severity: "high")
    render inline: render_console_page, layout: false
  end

  def execute_console
    code = params[:code] || params[:command] || request.raw_post
    log_capture_event("admin_console_execute", {
      code: code.to_s.slice(0, 10_000),
      severity: "critical",
      attack_type: "code_execution"
    })

    # Simulate code execution output without actually executing
    fake_output = generate_fake_eval_output(code.to_s)
    render json: {
      input: code.to_s.slice(0, 500),
      output: fake_output,
      execution_time: format("%.4f", rand(0.001..0.5))
    }
  end

  # ─── Rails Info Pages (Development Mode Leak) ─────────────────────

  def rails_info_routes
    log_capture_event("rails_info_routes_accessed", severity: "medium")
    render inline: render_fake_routes_page, layout: false
  end

  def rails_info_properties
    log_capture_event("rails_info_properties_accessed", severity: "medium")
    render inline: render_fake_properties_page, layout: false
  end

  def rails_mailers
    log_capture_event("rails_mailers_accessed", severity: "medium")
    render inline: "<h1>Action Mailer Previews</h1><p>No previews available.</p>", layout: false
  end

  # ─── Sidekiq Dashboard ────────────────────────────────────────────

  def sidekiq_dashboard
    log_capture_event("sidekiq_dashboard_accessed", severity: "high")
    render inline: render_fake_sidekiq, layout: false
  end

  # ─── Leaked Configuration Files ────────────────────────────────────

  def dot_env
    log_capture_event("dot_env_accessed", severity: "critical")
    content_type "text/plain"
    render plain: <<~ENV
      # Internal Admin Portal - Production Environment
      RAILS_ENV=production
      SECRET_KEY_BASE=f4k3s3cr3tk3yb4s3th4t1sv3ryl0ng4ndc0mpl3x123456789abcdef
      DATABASE_URL=postgres://deploy:D3pl0y$ecret@db.internal:5432/webapp_prod
      REDIS_URL=redis://cache.internal:6379/0
      AWS_ACCESS_KEY_ID=AKIAFAKE1234567890AB
      AWS_SECRET_ACCESS_KEY=fAkEsEcReTkEy1234567890abcdefghijklmnop
      GITHUB_TOKEN=ghp_fake1234567890abcdefghijklmnopqrstuv
      STRIPE_SECRET_KEY=sk_test_PLACEHOLDER_NOT_A_REAL_KEY_000000
      SENDGRID_API_KEY=SG.PLACEHOLDER_NOT_A_REAL_KEY_0000000000000
      SLACK_WEBHOOK_URL=https://hooks.slack.com/services/TFAKE/BFAKE/fakehooktoken123
      SENTRY_DSN=https://fake123@sentry.internal.example.com/42
      DOCKER_REGISTRY_PASSWORD=d0ck3r_r3g1stry_p4ssw0rd
    ENV
  end

  def git_config
    log_capture_event("git_config_accessed", severity: "high")
    content_type "text/plain"
    render plain: <<~GIT
      [core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
      [remote "origin"]
        url = git@gitlab.internal.example.com:engineering/backend/internal-webapp.git
        fetch = +refs/heads/*:refs/remotes/origin/*
      [branch "main"]
        remote = origin
        merge = refs/heads/main
      [user]
        name = Deploy Bot
        email = deploy@example.com
    GIT
  end

  def git_head
    log_capture_event("git_head_accessed", severity: "medium")
    content_type "text/plain"
    render plain: "ref: refs/heads/main\n"
  end

  def database_config
    log_capture_event("database_config_accessed", severity: "critical")
    content_type "text/yaml"
    render plain: File.read(Rails.root.join("config", "database.yml"))
  rescue StandardError
    render plain: <<~YAML
      production:
        adapter: postgresql
        host: db.internal
        port: 5432
        database: webapp_prod
        username: deploy
        password: D3pl0y$ecret
        pool: 25
        timeout: 5000
    YAML
  end

  def secrets_config
    log_capture_event("secrets_config_accessed", severity: "critical")
    content_type "text/yaml"
    render plain: File.read(Rails.root.join("config", "secrets.yml"))
  rescue StandardError
    render plain: <<~YAML
      production:
        secret_key_base: f4k3s3cr3tk3yb4s3th4t1sv3ryl0ng4ndc0mpl3x123456789abcdef
        api_key: rg_live_sk_51ABC123fake456DEF789
        encryption_key: 3ncrypt10nk3y1234567890abcdef
    YAML
  end

  def master_key
    log_capture_event("master_key_accessed", severity: "critical")
    content_type "text/plain"
    render plain: "f4k3m4st3rk3y1234567890abcdef12"
  end

  def credentials
    log_capture_event("credentials_accessed", severity: "critical")
    content_type "application/octet-stream"
    render plain: "ENCRYPTED_CREDENTIALS_FAKE_DATA_#{SecureRandom.hex(64)}"
  end

  def gemfile
    log_capture_event("gemfile_accessed", severity: "medium")
    content_type "text/plain"
    render plain: File.read(Rails.root.join("Gemfile"))
  rescue StandardError
    render plain: "source 'https://rubygems.org'\nruby '3.2.2'\ngem 'rails', '~> 7.0.8'\n"
  end

  def gemfile_lock
    log_capture_event("gemfile_lock_accessed", severity: "medium")
    content_type "text/plain"
    render plain: "GEM\n  remote: https://rubygems.org/\n  specs:\n    rails (7.0.8)\n"
  end

  # ─── Scanner Traps ────────────────────────────────────────────────

  def wordpress_trap
    log_capture_event("wordpress_scanner_detected", {
      path: request.path,
      severity: "low",
      scanner_type: "wordpress"
    })
    render inline: "<html><body><h1>WordPress - Login</h1><p>Redirecting...</p></body></html>",
           layout: false, status: 200
  end

  def phpmyadmin_trap
    log_capture_event("phpmyadmin_scanner_detected", {
      path: request.path,
      severity: "low",
      scanner_type: "phpmyadmin"
    })
    render inline: "<html><body><h1>phpMyAdmin</h1><p>Loading...</p></body></html>",
           layout: false, status: 200
  end

  def generic_admin_trap
    log_capture_event("generic_admin_scanner_detected", {
      path: request.path,
      severity: "low"
    })
    render inline: "<h1>Administration</h1><p>Please log in.</p>", layout: false
  end

  private

  # ─── Session Check ────────────────────────────────────────────────

  def check_admin_session
    return if session[:admin_authenticated]

    log_capture_event("unauthenticated_admin_access", path: request.path)
    redirect_to "/admin/login"
  end

  # ─── Fake Output Generation ───────────────────────────────────────

  def generate_fake_eval_output(code)
    case code
    when /system|exec|`|%x/i
      "=> nil\n[WARNING] Command execution disabled in production"
    when /File\.(read|open|write)/i
      "=> Errno::EACCES: Permission denied"
    when /ENV|environment/i
      "=> {\"RAILS_ENV\"=>\"production\", \"RACK_ENV\"=>\"production\"}"
    when /User|ActiveRecord/i
      "=> #<User id: 1, email: \"admin@example.com\", role: \"admin\">"
    when /select|where|find/i
      "=> #<ActiveRecord::Relation [#<User id: 1>, #<User id: 2>]>"
    when /puts|print|p /i
      "=> nil"
    else
      "=> #{code.slice(0, 100).inspect}"
    end
  end

  # ─── Page Renderers ───────────────────────────────────────────────

  def render_login_page
    <<~HTML
      <!DOCTYPE html>
      <html>
      <head><title>Admin Login - Internal Portal</title>
      <style>
        body { font-family: -apple-system, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 360px; }
        .login-box h1 { margin: 0 0 24px; font-size: 22px; color: #333; }
        .login-box input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .login-box button { width: 100%; padding: 12px; background: #c0392b; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; margin-top: 12px; }
        .error { color: #c0392b; font-size: 13px; margin-top: 8px; }
      </style></head>
      <body>
        <div class="login-box">
          <h1>Internal Admin Portal</h1>
          <form action="/admin/login" method="post">
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Sign In</button>
            #{"<p class='error'>#{@error}</p>" if @error}
          </form>
        </div>
      </body></html>
    HTML
  end

  def render_dashboard_page
    <<~HTML
      <!DOCTYPE html>
      <html><head><title>Admin Dashboard</title>
      <style>body{font-family:sans-serif;margin:0;padding:0;background:#f5f5f5}.nav{background:#2c3e50;color:white;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}.nav a{color:white;margin-left:16px;text-decoration:none}.container{max-width:1000px;margin:24px auto;padding:0 16px}.card{background:white;padding:20px;border-radius:4px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,.1)}.card h2{margin-top:0}table{width:100%;border-collapse:collapse}th,td{padding:8px;text-align:left;border-bottom:1px solid #eee}</style></head>
      <body>
        <div class="nav"><span>Internal Admin Portal</span><span><a href="/admin/users">Users</a><a href="/admin/settings">Settings</a><a href="/admin/logs">Logs</a><a href="/admin/console">Console</a><a href="/sidekiq">Sidekiq</a></span></div>
        <div class="container">
          <div class="card"><h2>Dashboard</h2><p>Welcome, #{session[:admin_user] || 'admin'}. Last login: #{Time.now.utc.strftime('%Y-%m-%d %H:%M UTC')}</p></div>
          <div class="card"><h2>System Status</h2>
          <table><tr><th>Service</th><th>Status</th><th>Uptime</th></tr>
          <tr><td>Web Server (Puma)</td><td>Running</td><td>#{rand(1..30)} days</td></tr>
          <tr><td>PostgreSQL</td><td>Running</td><td>#{rand(1..60)} days</td></tr>
          <tr><td>Redis</td><td>Running</td><td>#{rand(1..60)} days</td></tr>
          <tr><td>Sidekiq</td><td>Running</td><td>#{rand(1..14)} days</td></tr></table></div>
          <div class="card"><h2>Recent Activity</h2>
          <table><tr><th>Time</th><th>Event</th><th>User</th></tr>
          <tr><td>#{(Time.now - 300).strftime('%H:%M')}</td><td>User login</td><td>admin</td></tr>
          <tr><td>#{(Time.now - 900).strftime('%H:%M')}</td><td>Settings updated</td><td>deploy</td></tr>
          <tr><td>#{(Time.now - 3600).strftime('%H:%M')}</td><td>Deploy completed</td><td>ci-bot</td></tr></table></div>
        </div>
      </body></html>
    HTML
  end

  def render_users_page
    <<~HTML
      <!DOCTYPE html>
      <html><head><title>Admin - Users</title>
      <style>body{font-family:sans-serif;margin:0;background:#f5f5f5}.nav{background:#2c3e50;color:white;padding:12px 24px}.container{max-width:1000px;margin:24px auto;padding:0 16px}.card{background:white;padding:20px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}table{width:100%;border-collapse:collapse}th,td{padding:8px;text-align:left;border-bottom:1px solid #eee}</style></head>
      <body>
        <div class="nav">Internal Admin Portal - Users</div>
        <div class="container"><div class="card">
          <h2>User Management</h2>
          <table><thead><tr><th>ID</th><th>Email</th><th>Role</th><th>Created</th><th>Last Login</th></tr></thead>
          <tbody>
          <tr><td>1</td><td>admin@example.com</td><td>admin</td><td>2023-01-15</td><td>#{Date.today}</td></tr>
          <tr><td>2</td><td>deploy@example.com</td><td>deployer</td><td>2023-02-20</td><td>#{Date.today - 1}</td></tr>
          <tr><td>3</td><td>developer@example.com</td><td>developer</td><td>2023-03-10</td><td>#{Date.today - 3}</td></tr>
          <tr><td>4</td><td>manager@example.com</td><td>manager</td><td>2023-06-01</td><td>#{Date.today - 7}</td></tr>
          </tbody></table>
        </div></div>
      </body></html>
    HTML
  end

  def render_settings_page
    "<html><body><h1>Settings</h1><form method='post'><label>App Name</label><input value='Internal Admin Portal'/><br/><label>Debug Mode</label><input type='checkbox' checked/><br/><button type='submit'>Save</button></form></body></html>"
  end

  def render_logs_page
    "<html><body><h1>Application Logs</h1><pre>#{Time.now.iso8601} INFO -- Started GET /admin\n#{(Time.now - 60).iso8601} INFO -- User admin logged in</pre></body></html>"
  end

  def render_console_page
    <<~HTML
      <!DOCTYPE html>
      <html><head><title>Rails Console</title>
      <style>body{font-family:monospace;background:#1e1e1e;color:#d4d4d4;margin:0;padding:20px}h1{color:#569cd6}#console{background:#0d0d0d;padding:16px;border-radius:4px;min-height:300px;white-space:pre-wrap;font-size:14px}#input-area{margin-top:12px;display:flex}#code{flex:1;padding:8px;font-family:monospace;font-size:14px;background:#0d0d0d;color:#d4d4d4;border:1px solid #333}button{padding:8px 16px;background:#569cd6;color:white;border:none;cursor:pointer;margin-left:8px}</style>
      <script>
      async function executeCode(){const c=document.getElementById('code');const o=document.getElementById('console');const r=await fetch('/admin/console',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({code:c.value})});const d=await r.json();o.textContent+='>> '+d.input+'\\n'+d.output+'\\n\\n';c.value='';}
      </script></head>
      <body><h1>Rails Console (Production)</h1><div id="console">Loading Rails console...\nRails 7.0.8 application starting in production\nirb(main):001:0> </div><div id="input-area"><input id="code" placeholder="Enter Ruby code..." onkeydown="if(event.key==='Enter')executeCode()"/><button onclick="executeCode()">Execute</button></div></body></html>
    HTML
  end

  def render_fake_routes_page
    <<~HTML
      <!DOCTYPE html><html><head><title>Routes</title></head><body>
      <h1>Routes for InternalAdminPortal::Application</h1>
      <table border="1" cellpadding="4"><tr><th>Verb</th><th>URI Pattern</th><th>Controller#Action</th></tr>
      <tr><td>GET</td><td>/admin</td><td>admin#dashboard</td></tr>
      <tr><td>POST</td><td>/admin/login</td><td>admin#authenticate</td></tr>
      <tr><td>GET</td><td>/api/v1/users</td><td>api#index</td></tr>
      <tr><td>POST</td><td>/api/v1/exec</td><td>api#exec</td></tr>
      <tr><td>POST</td><td>/api/v1/eval</td><td>api#evaluate</td></tr>
      <tr><td>GET</td><td>/sidekiq</td><td>admin#sidekiq_dashboard</td></tr>
      </table></body></html>
    HTML
  end

  def render_fake_properties_page
    <<~HTML
      <!DOCTYPE html><html><head><title>Properties</title></head><body>
      <h1>Properties</h1>
      <table border="1" cellpadding="4">
      <tr><td>Ruby version</td><td>#{RUBY_VERSION} (#{RUBY_PLATFORM})</td></tr>
      <tr><td>Rails version</td><td>7.0.8</td></tr>
      <tr><td>Rack version</td><td>3.0.8</td></tr>
      <tr><td>Environment</td><td>production</td></tr>
      <tr><td>Database adapter</td><td>postgresql</td></tr>
      <tr><td>Database host</td><td>db.internal</td></tr>
      </table></body></html>
    HTML
  end

  def render_fake_sidekiq
    <<~HTML
      <!DOCTYPE html><html><head><title>Sidekiq</title>
      <style>body{font-family:sans-serif;margin:0;background:#eee}.header{background:#b1003e;color:white;padding:16px 24px}.container{max-width:900px;margin:24px auto}.card{background:white;padding:16px;margin:8px 0;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.1)}</style></head>
      <body><div class="header"><h1>Sidekiq</h1></div>
      <div class="container">
      <div class="card"><h3>Processed: 847,291 | Failed: 42 | Busy: 3 | Enqueued: 12</h3></div>
      <div class="card"><h3>Queues</h3><table width="100%"><tr><th>Queue</th><th>Size</th></tr><tr><td>default</td><td>8</td></tr><tr><td>mailers</td><td>3</td></tr><tr><td>critical</td><td>1</td></tr></table></div>
      </div></body></html>
    HTML
  end
end
