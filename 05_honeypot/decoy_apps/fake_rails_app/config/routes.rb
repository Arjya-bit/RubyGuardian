# frozen_string_literal: true

# RubyGuardian Honeypot - Fake Rails App Routes
# These routes deliberately expose common attack surfaces to attract
# and capture attacker interactions.

Rails.application.routes.draw do
  # Admin panel routes (primary attack surface)
  get  "admin",          to: "admin#dashboard"
  get  "admin/login",    to: "admin#login"
  post "admin/login",    to: "admin#authenticate"
  get  "admin/users",    to: "admin#users"
  get  "admin/settings", to: "admin#settings"
  post "admin/settings", to: "admin#update_settings"
  get  "admin/logs",     to: "admin#logs"
  get  "admin/console",  to: "admin#console"
  post "admin/console",  to: "admin#execute_console"

  # API routes (simulated vulnerable endpoints)
  namespace :api do
    namespace :v1 do
      resources :users, only: [:index, :show, :create, :update, :destroy]
      post "exec",    to: "api#exec"
      post "eval",    to: "api#evaluate"
      get  "search",  to: "api#search"
      get  "files",   to: "api#files"
      post "import",  to: "api#import_data"
      post "export",  to: "api#export_data"
      get  "fetch",   to: "api#fetch_url"
      get  "config",  to: "api#config"
      get  "health",  to: "api#health"
      post "webhook", to: "api#webhook"
    end

    namespace :v2 do
      get "status", to: "api#status"
    end
  end

  # Deliberately leaked development/debug routes
  get "rails/info/routes",     to: "admin#rails_info_routes"
  get "rails/info/properties", to: "admin#rails_info_properties"
  get "rails/mailers",         to: "admin#rails_mailers"

  # Sidekiq dashboard (exposed without auth)
  get "sidekiq",      to: "admin#sidekiq_dashboard"
  get "sidekiq/*any", to: "admin#sidekiq_dashboard"

  # Common files that attackers look for
  get ".env",                  to: "admin#dot_env"
  get ".git/config",           to: "admin#git_config"
  get ".git/HEAD",             to: "admin#git_head"
  get "config/database.yml",   to: "admin#database_config"
  get "config/secrets.yml",    to: "admin#secrets_config"
  get "config/master.key",     to: "admin#master_key"
  get "config/credentials.yml.enc", to: "admin#credentials"
  get "Gemfile",               to: "admin#gemfile"
  get "Gemfile.lock",          to: "admin#gemfile_lock"

  # WordPress and PHP honeypot endpoints (common scanner targets)
  get "wp-admin",        to: "admin#wordpress_trap"
  get "wp-admin/*any",   to: "admin#wordpress_trap"
  get "wp-login.php",    to: "admin#wordpress_trap"
  get "phpmyadmin",      to: "admin#phpmyadmin_trap"
  get "phpmyadmin/*any", to: "admin#phpmyadmin_trap"
  get "administrator",   to: "admin#generic_admin_trap"

  # Catch-all route to log all other requests
  match "*path", to: "application#catch_all", via: :all

  root "admin#dashboard"
end
