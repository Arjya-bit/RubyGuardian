# frozen_string_literal: true
#
# RubyGuardian - Vulnerable Rails Application Configuration
# PURPOSE: Educational security research - demonstrates weak configurations
# WARNING: Every setting in this file is INTENTIONALLY insecure.
#          Do NOT use these configurations in any real application.

require_relative 'boot'
require 'rails/all'

Bundler.require(*Rails.groups)

module VulnerableRailsApp
  class Application < Rails::Application
    config.load_defaults 5.2

    # ========================================================================
    # VULNERABILITY: Permissive CORS - allows any origin
    # RISK: Cross-origin attacks, credential theft
    # ========================================================================
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins '*'
        resource '*',
          headers: :any,
          methods: [:get, :post, :put, :patch, :delete, :options, :head],
          credentials: false
      end
    end

    # ========================================================================
    # VULNERABILITY: XML and YAML deserialization enabled
    # RISK: Remote Code Execution via crafted XML/YAML payloads
    # CVE-2013-0156 style attacks become possible
    # ========================================================================
    config.middleware.use ActionDispatch::ParamsParser, {
      Mime[:xml]  => proc { |raw| Hash.from_xml(raw) },
      Mime[:yaml] => proc { |raw| YAML.unsafe_load(raw) }
    }

    # ========================================================================
    # VULNERABILITY: Weak session configuration
    # RISK: Session hijacking, fixation, and replay attacks
    # ========================================================================
    config.session_store :cookie_store,
      key: '_vulnerable_app_session',
      expire_after: nil,           # WARNING: Sessions never expire
      secure: false,               # WARNING: Cookies sent over HTTP
      httponly: false,              # WARNING: JavaScript can read cookies
      same_site: :none             # WARNING: Cookies sent cross-site

    # ========================================================================
    # VULNERABILITY: Secret key base is hardcoded
    # RISK: Cookie tampering, session forgery, RCE via deserialization
    # ========================================================================
    config.secret_key_base = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6'

    # ========================================================================
    # VULNERABILITY: Detailed error pages in all environments
    # RISK: Information disclosure of stack traces, source code, variables
    # ========================================================================
    config.consider_all_requests_local = true
    config.action_dispatch.show_exceptions = true
    config.action_dispatch.show_detailed_exceptions = true

    # ========================================================================
    # VULNERABILITY: Logging sensitive parameters
    # RISK: Credentials, tokens, PII exposed in log files
    # ========================================================================
    config.filter_parameters = []  # WARNING: Nothing is filtered

    # ========================================================================
    # VULNERABILITY: Mass assignment protection disabled
    # RISK: Privilege escalation, data manipulation
    # ========================================================================
    config.action_controller.permit_all_parameters = true

    # ========================================================================
    # VULNERABILITY: Forgery protection disabled
    # RISK: Cross-Site Request Forgery (CSRF) attacks
    # ========================================================================
    config.action_controller.allow_forgery_protection = false

    # ========================================================================
    # VULNERABILITY: Weak SSL/TLS configuration
    # RISK: Man-in-the-middle attacks, downgrade attacks
    # ========================================================================
    config.force_ssl = false

    # ========================================================================
    # VULNERABILITY: Directory listing and file serving enabled
    # RISK: Information disclosure, access to sensitive files
    # ========================================================================
    config.public_file_server.enabled = true
    config.public_file_server.headers = {
      'Cache-Control' => 'public, max-age=0',
      'Access-Control-Allow-Origin' => '*'
    }

    # ========================================================================
    # VULNERABILITY: Verbose logging at debug level
    # RISK: Sensitive data in logs, performance degradation
    # ========================================================================
    config.log_level = :debug
    config.log_tags = [:request_id, :remote_ip]

    # ========================================================================
    # VULNERABILITY: Autoloading in production (Rails 5 classic mode)
    # RISK: Thread safety issues, potential code injection
    # ========================================================================
    config.eager_load = false

    # ========================================================================
    # VULNERABILITY: Default content security policy is absent
    # RISK: XSS, clickjacking, data injection attacks
    # ========================================================================
    # No CSP headers configured - intentionally omitted
  end
end
