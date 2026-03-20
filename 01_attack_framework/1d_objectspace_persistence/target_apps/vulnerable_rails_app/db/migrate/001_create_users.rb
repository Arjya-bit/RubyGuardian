# frozen_string_literal: true
#
# RubyGuardian - Users Table Migration
# PURPOSE: Educational security research - demonstrates insecure schema design
# WARNING: This migration contains INTENTIONAL security anti-patterns.
#          Do NOT use this schema design in production.

class CreateUsers < ActiveRecord::Migration[5.2]
  def change
    create_table :users do |t|
      # Basic identity fields
      t.string :username
      t.string :email

      # ======================================================================
      # VULNERABILITY: Storing password digest alongside weak hash
      # RISK: Base64-encoded password is trivially reversible
      # ======================================================================
      t.string :password_digest    # WARNING: Stores Base64-encoded password (reversible)
      t.string :password_hash      # WARNING: Stores unsalted MD5 hash

      # ======================================================================
      # VULNERABILITY: Sensitive PII stored without encryption at rest
      # RISK: Database breach exposes all personal data in cleartext
      # ======================================================================
      t.string :ssn               # WARNING: Social Security Number in plaintext
      t.string :phone
      t.text   :address
      t.date   :date_of_birth

      # ======================================================================
      # VULNERABILITY: Role stored as mutable string column
      # RISK: Mass assignment can change role to 'admin'
      # ======================================================================
      t.string  :role, default: 'user'
      t.boolean :is_superuser, default: false

      # ======================================================================
      # VULNERABILITY: API token stored in plaintext
      # RISK: Database access reveals all valid API tokens
      # ======================================================================
      t.string :api_token

      # ======================================================================
      # VULNERABILITY: Password reset token without expiration enforcement
      # RISK: Reset tokens remain valid indefinitely
      # ======================================================================
      t.string   :reset_token
      t.datetime :reset_sent_at

      # Session and tracking
      t.string   :session_token
      t.datetime :last_login_at
      t.string   :last_login_ip
      t.integer  :login_count, default: 0

      # WARNING: No failed_login_count for lockout mechanism

      t.timestamps
    end

    # ======================================================================
    # VULNERABILITY: No unique index on username or email
    # RISK: Duplicate accounts, authentication bypass
    # ======================================================================
    add_index :users, :username    # WARNING: Not unique
    add_index :users, :email       # WARNING: Not unique
    add_index :users, :api_token
    add_index :users, :reset_token

    # ======================================================================
    # Insert default admin user with weak credentials
    # VULNERABILITY: Hardcoded credentials in migration
    # RISK: Known credentials if migration is accessible
    # ======================================================================
    reversible do |dir|
      dir.up do
        execute <<-SQL
          INSERT INTO users (
            username, email, password_digest, password_hash,
            role, is_superuser, api_token, created_at, updated_at
          ) VALUES (
            'admin',
            'admin@vulnerable-app.local',
            '#{Base64.encode64("admin123").strip}',
            '#{Digest::MD5.hexdigest("admin123")}',
            'admin',
            1,
            'default_admin_token_do_not_use',
            datetime('now'),
            datetime('now')
          );
        SQL
      end
    end
  end
end
