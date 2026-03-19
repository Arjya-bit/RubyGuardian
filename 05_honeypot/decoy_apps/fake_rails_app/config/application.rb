# frozen_string_literal: true

# RubyGuardian Honeypot - Fake Rails Application Configuration
# This file configures the decoy Rails application to appear as a
# realistic but vulnerable internal web application.

require_relative "boot"
require "rails/all"

Bundler.require(*Rails.groups)

module InternalAdminPortal
  class Application < Rails::Application
    config.load_defaults 7.0

    # Deliberately insecure settings to attract attackers
    config.consider_all_requests_local = true
    config.action_dispatch.show_exceptions = true
    config.action_dispatch.show_detailed_exceptions = true

    # Weak session configuration
    config.session_store :cookie_store,
      key: "_internal_admin_session",
      expire_after: 30.days

    # Deliberately weak secret key base (appears leaked)
    config.secret_key_base = "f4k3s3cr3tk3yb4s3th4t1sv3ryl0ng4ndc0mpl3x123456789abcdef"

    # CORS misconfiguration (deliberately weak)
    config.middleware.insert_before 0, Rack::Cors do
      allow do
        origins "*"
        resource "*",
          headers: :any,
          methods: [:get, :post, :put, :patch, :delete, :options, :head],
          credentials: false
      end
    end if defined?(Rack::Cors)

    # API-only mode for some endpoints
    config.api_only = false

    # Timezone and locale
    config.time_zone = "UTC"
    config.i18n.default_locale = :en

    # Logger configuration - logs all requests to honeypot capture engine
    config.log_level = :debug
    config.log_tags = [:request_id, :remote_ip]

    # Deliberately expose server tokens
    config.action_dispatch.default_headers = {
      "X-Frame-Options" => "",  # deliberately empty
      "X-Powered-By" => "Phusion Passenger 6.0.18",
      "Server" => "nginx/1.24.0 + Phusion Passenger 6.0.18"
    }

    # Database configuration (fake - points to honeypot capture DB)
    config.active_record.schema_format = :sql if defined?(ActiveRecord)

    # Honeypot integration hooks
    config.after_initialize do
      # Hook into request processing for capture
      ActiveSupport::Notifications.subscribe("process_action.action_controller") do |*args|
        event = ActiveSupport::Notifications::Event.new(*args)
        HoneypotCapture.log_request(event) if defined?(HoneypotCapture)
      end
    end
  end
end
