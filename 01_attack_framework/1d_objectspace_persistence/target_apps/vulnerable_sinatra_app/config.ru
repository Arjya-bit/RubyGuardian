# frozen_string_literal: true
#
# RubyGuardian - Vulnerable Sinatra App Rack Configuration
# PURPOSE: Educational security research - demonstrates insecure server configuration
# WARNING: This configuration contains INTENTIONAL vulnerabilities.
#          NEVER deploy with these settings.

require_relative 'app'

# ==========================================================================
# VULNERABILITY: Verbose error pages enabled for all environments
# RISK: Stack traces, source code, and internal paths exposed to attackers
# ==========================================================================
use Rack::ShowExceptions
use Rack::ShowStatus

# ==========================================================================
# VULNERABILITY: Insecure session configuration
# RISK: Session hijacking, fixation, and cookie manipulation
# ==========================================================================
use Rack::Session::Cookie,
  key: 'vulnerable_sinatra_session',
  secret: 'short_weak_secret',      # WARNING: Weak, short secret
  expire_after: nil,                 # WARNING: No expiration
  httponly: false,                    # WARNING: JS can read cookies
  secure: false,                     # WARNING: Sent over plain HTTP
  same_site: :none                   # WARNING: Cross-site cookie sending

# ==========================================================================
# VULNERABILITY: Permissive CORS middleware
# RISK: Cross-origin attacks from any domain
# ==========================================================================
use Rack::Cors do
  allow do
    origins '*'
    resource '*', headers: :any, methods: :any
  end
end if defined?(Rack::Cors)

# ==========================================================================
# VULNERABILITY: Static file serving with directory traversal risk
# RISK: Access to files outside the intended public directory
# ==========================================================================
use Rack::Static,
  urls: ['/'],
  root: 'public',
  index: 'index.html',
  header_rules: [
    [:all, {
      'Cache-Control' => 'public, max-age=0',
      'Access-Control-Allow-Origin' => '*',
      'X-Content-Type-Options' => ''  # WARNING: MIME sniffing not prevented
    }]
  ]

# ==========================================================================
# VULNERABILITY: Request logging that may capture sensitive data
# RISK: Credentials and tokens written to log files
# ==========================================================================
use Rack::CommonLogger, $stdout

# ==========================================================================
# WARNING: No security middleware enabled
# Missing: Rack::Protection, Rack::Deflater, rate limiting
# ==========================================================================

# WARNING: No Rack::Protection suite enabled
# This would normally provide:
#   - CSRF protection
#   - XSS prevention headers
#   - Clickjacking protection
#   - IP spoofing detection
#   - Path traversal prevention

run Sinatra::Application
