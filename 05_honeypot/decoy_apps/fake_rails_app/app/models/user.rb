# frozen_string_literal: true

# RubyGuardian Honeypot - Fake User Model
# Simulates a User model with deliberately weak authentication,
# insecure password handling, and exploitable query methods.
# All database operations are intercepted and logged.
#
# HONEYPOT WARNING: This model does not connect to a real database.
# All data is fabricated and all queries are logged for threat intelligence.

module RubyGuardian
  module Honeypot
    module FakeRailsApp
      # Simulated User model that mimics ActiveRecord behavior
      # without requiring an actual database connection. All method
      # calls and queries are captured for analysis.
      class User
        LOG_DIR = ENV.fetch("HONEYPOT_LOG_DIR", "/var/log/rubyguardian/honeypot")

        # Simulate ActiveRecord attribute accessors
        ATTRIBUTES = %i[
          id email encrypted_password name role api_key
          reset_password_token reset_password_sent_at
          remember_created_at sign_in_count current_sign_in_at
          last_sign_in_at current_sign_in_ip last_sign_in_ip
          failed_attempts locked_at unlock_token
          created_at updated_at
        ].freeze

        attr_accessor(*ATTRIBUTES)

        # Fake user records that appear in the "database"
        SEED_USERS = [
          {
            id: 1, email: "admin@example.com", name: "Admin User",
            role: "admin", api_key: "rg_live_sk_51ABC123fake456DEF789",
            encrypted_password: "$2a$12$fakehash.admin.bcrypt.string.placeholder",
            sign_in_count: 847, current_sign_in_ip: "10.0.1.50",
            created_at: "2023-01-15T10:00:00Z", updated_at: "2024-02-15T09:30:00Z"
          },
          {
            id: 2, email: "deploy@example.com", name: "Deploy Bot",
            role: "deployer", api_key: "rg_live_sk_deploy_key_fake_123",
            encrypted_password: "$2a$12$fakehash.deploy.bcrypt.string.placeholder",
            sign_in_count: 12_450, current_sign_in_ip: "172.20.1.10",
            created_at: "2023-02-20T14:00:00Z", updated_at: "2024-02-15T10:35:00Z"
          },
          {
            id: 3, email: "developer@example.com", name: "Dev User",
            role: "developer", api_key: "rg_live_sk_dev_key_fake_456",
            encrypted_password: "$2a$12$fakehash.developer.bcrypt.string.placeholder",
            sign_in_count: 234, current_sign_in_ip: "192.168.1.100",
            created_at: "2023-03-10T09:00:00Z", updated_at: "2024-02-10T16:20:00Z"
          },
          {
            id: 4, email: "manager@example.com", name: "Manager User",
            role: "manager", api_key: "rg_live_sk_mgr_key_fake_789",
            encrypted_password: "$2a$12$fakehash.manager.bcrypt.string.placeholder",
            sign_in_count: 56, current_sign_in_ip: "10.0.2.25",
            created_at: "2023-06-01T11:00:00Z", updated_at: "2024-01-20T08:15:00Z"
          },
          {
            id: 5, email: "support@example.com", name: "Support User",
            role: "support", api_key: "rg_live_sk_sup_key_fake_012",
            encrypted_password: "$2a$12$fakehash.support.bcrypt.string.placeholder",
            sign_in_count: 189, current_sign_in_ip: "10.0.3.15",
            created_at: "2023-08-15T13:00:00Z", updated_at: "2024-02-12T11:45:00Z"
          }
        ].freeze

        # Deliberately weak password list used for "validation"
        COMMON_PASSWORDS = %w[
          password 123456 admin root qwerty letmein welcome
          monkey master dragon login passw0rd abc123
        ].freeze

        def initialize(attributes = {})
          attributes.each do |key, value|
            send(:"#{key}=", value) if respond_to?(:"#{key}=")
          end
        end

        # ─── Simulated ActiveRecord Finders ──────────────────────────

        # Simulate User.find(id) - logs the query for capture
        def self.find(id)
          log_query("find", { id: id })

          if injection_attempt?(id.to_s)
            log_event("sql_injection_via_find", {
              input: id.to_s.slice(0, 5000),
              method: "User.find",
              severity: "critical"
            })
          end

          record = SEED_USERS.find { |u| u[:id] == id.to_i }
          raise_record_not_found(id) unless record
          new(record)
        end

        # Simulate User.find_by(conditions)
        def self.find_by(conditions = {})
          log_query("find_by", conditions)

          conditions.each_value do |v|
            if injection_attempt?(v.to_s)
              log_event("sql_injection_via_find_by", {
                conditions: conditions.transform_values { |val| val.to_s.slice(0, 1000) },
                severity: "critical"
              })
            end
          end

          record = SEED_USERS.find do |u|
            conditions.all? { |k, v| u[k.to_sym].to_s == v.to_s }
          end
          record ? new(record) : nil
        end

        # Simulate User.where(conditions)
        def self.where(conditions = {})
          log_query("where", conditions)

          if conditions.is_a?(String)
            log_event("raw_sql_where_clause", {
              sql: conditions.slice(0, 5000),
              severity: "critical",
              attack_type: "sql_injection"
            })
          end

          results = SEED_USERS.select do |u|
            if conditions.is_a?(Hash)
              conditions.all? { |k, v| u[k.to_sym].to_s == v.to_s }
            else
              true # Return all for raw SQL (it's fake anyway)
            end
          end
          results.map { |r| new(r) }
        end

        # Simulate User.all
        def self.all
          log_query("all", {})
          SEED_USERS.map { |r| new(r) }
        end

        # Simulate User.count
        def self.count
          log_query("count", {})
          SEED_USERS.size
        end

        # ─── Deliberately Weak Authentication ───────────────────────

        # Authenticate with plaintext password comparison (intentionally insecure)
        def self.authenticate(email, password)
          log_event("authentication_attempt", {
            email: email,
            password_length: password&.length,
            password_hash: password ? Digest::SHA256.hexdigest(password) : nil,
            severity: "high"
          })

          user = find_by(email: email)
          return nil unless user

          # Deliberately weak: accept common passwords or any password > 6 chars
          if COMMON_PASSWORDS.include?(password) || (password && password.length >= 6)
            log_event("authentication_success_fake", {
              email: email,
              user_id: user.id,
              severity: "critical"
            })
            user
          else
            log_event("authentication_failure", { email: email })
            nil
          end
        end

        # Simulate password reset (captures tokens)
        def self.reset_password(email)
          log_event("password_reset_request", {
            email: email,
            severity: "medium"
          })
          token = SecureRandom.hex(20)
          log_event("password_reset_token_generated", {
            email: email,
            token: token,
            severity: "high"
          })
          { success: true, token: token }
        end

        # ─── Deliberately Insecure Methods ──────────────────────────

        # Simulate mass assignment vulnerability
        def update_attributes(attrs)
          self.class.log_event("mass_assignment_attempt", {
            user_id: id,
            attributes: attrs.transform_values { |v| v.to_s.slice(0, 500) },
            severity: "high"
          })
          attrs.each do |key, value|
            send(:"#{key}=", value) if respond_to?(:"#{key}=")
          end
          self
        end

        # Simulate insecure serialization
        def to_json_with_secrets
          self.class.log_event("user_serialization_with_secrets", {
            user_id: id,
            severity: "high"
          })
          {
            id: id,
            email: email,
            name: name,
            role: role,
            api_key: api_key,
            encrypted_password: encrypted_password,
            reset_password_token: reset_password_token
          }.to_json
        end

        # Simulate insecure token generation
        def generate_api_key
          key = "rg_live_sk_#{SecureRandom.hex(20)}"
          self.class.log_event("api_key_generated", {
            user_id: id,
            key_prefix: key.slice(0, 15),
            severity: "medium"
          })
          self.api_key = key
          key
        end

        # Simulate eval-based dynamic method (intentionally vulnerable)
        def self.dynamic_query(field, value)
          log_event("dynamic_query_attempt", {
            field: field.to_s.slice(0, 200),
            value: value.to_s.slice(0, 2000),
            severity: "critical",
            attack_type: "code_injection"
          })
          # Never actually eval - just log and return fake results
          all
        end

        # ─── Model Inspection (Information Leakage) ─────────────────

        def self.columns
          log_query("columns_inspection", {})
          ATTRIBUTES.map do |attr|
            OpenStruct.new(
              name: attr.to_s,
              type: column_type(attr),
              null: true,
              default: nil
            )
          end
        end

        def self.table_name
          "users"
        end

        def self.primary_key
          "id"
        end

        def self.connection
          log_event("database_connection_access", severity: "medium")
          OpenStruct.new(
            adapter_name: "PostgreSQL",
            database_version: "15.4",
            current_database: "webapp_prod",
            tables: %w[users sessions api_keys roles permissions audit_logs]
          )
        end

        # ─── Serialization ──────────────────────────────────────────

        def as_json(options = {})
          base = {
            id: id,
            email: email,
            name: name,
            role: role,
            created_at: created_at,
            updated_at: updated_at
          }
          # Deliberately include sensitive fields if requested
          if options[:include_sensitive]
            base[:api_key] = api_key
            base[:encrypted_password] = encrypted_password
          end
          base
        end

        def to_s
          "#<User id: #{id}, email: \"#{email}\", role: \"#{role}\">"
        end

        def inspect
          to_s
        end

        private

        def self.column_type(attr)
          case attr
          when :id then :integer
          when /_at$/ then :datetime
          when :sign_in_count, :failed_attempts then :integer
          else :string
          end
        end

        def self.injection_attempt?(input)
          patterns = [
            /'\s*(OR|AND)/i, /UNION\s+SELECT/i, /;\s*(DROP|DELETE)/i,
            /--\s*$/, /\/\*/, /SLEEP\s*\(/i, /BENCHMARK/i
          ]
          patterns.any? { |p| input.match?(p) }
        end

        def self.raise_record_not_found(id)
          raise StandardError, "Couldn't find User with 'id'=#{id}"
        end

        # ─── Logging ────────────────────────────────────────────────

        def self.log_query(method, params)
          log_event("user_query", {
            method: method,
            params: params.is_a?(Hash) ? params.transform_values { |v| v.to_s.slice(0, 1000) } : params.to_s.slice(0, 1000)
          })
        end

        def self.log_event(event_type, data = {})
          event = {
            timestamp: Time.now.utc.iso8601(6),
            service: "fake_rails_app",
            component: "user_model",
            event_type: event_type,
            data: data
          }
          log_file = File.join(LOG_DIR, "user_model_events_#{Date.today.iso8601}.jsonl")
          File.open(log_file, "a") do |f|
            f.flock(File::LOCK_EX)
            f.puts(JSON.generate(event))
          end
        rescue StandardError
          # Silent fail
        end
      end
    end
  end
end
