# frozen_string_literal: true

source 'https://rubygems.org'

ruby '>= 3.0.0'

# Core
gem 'rake', '~> 13.0'

# FFI for native API bindings
gem 'ffi', '~> 1.16'

# Web framework (C2 server, honeypot)
gem 'sinatra', '~> 4.0'
gem 'puma', '~> 6.4'
gem 'rack', '~> 3.0'

# Database
gem 'sqlite3', '~> 1.7'
gem 'sequel', '~> 5.75'

# HTTP client
gem 'faraday', '~> 2.8'
gem 'typhoeus', '~> 1.4'

# Networking
gem 'packetfu', '~> 2.0'

# Configuration
gem 'yaml', '~> 0.3'

# Logging
gem 'logger', '~> 1.6'

# CLI
gem 'thor', '~> 1.3'
gem 'tty-table', '~> 0.12'
gem 'tty-prompt', '~> 0.23'
gem 'pastel', '~> 0.8'

# Process management
gem 'daemons', '~> 1.4'

# Encoding/Crypto
gem 'base64', '~> 0.2'
gem 'openssl', '~> 3.2'

group :development, :test do
  gem 'rspec', '~> 3.13'
  gem 'rubocop', '~> 1.59'
  gem 'rubocop-rspec', '~> 2.25'
  gem 'simplecov', '~> 0.22'
  gem 'webmock', '~> 3.19'
  gem 'factory_bot', '~> 6.4'
  gem 'pry', '~> 0.14'
  gem 'rerun', '~> 0.14'
end
