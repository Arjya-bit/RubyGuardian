# frozen_string_literal: true
#
# RubyGuardian - Vulnerable User Model
# PURPOSE: Educational security research - demonstrates weak authentication patterns
# WARNING: This model contains INTENTIONAL vulnerabilities for security testing.
#          NEVER implement authentication like this in production.

class User < ApplicationRecord
  # ==========================================================================
  # VULNERABILITY: No password complexity validation
  # RISK: Weak passwords, easily brute-forced accounts
  # ==========================================================================
  validates :username, presence: true
  validates :email, presence: true
  # WARNING: No uniqueness validation - duplicate accounts possible
  # WARNING: No password length or complexity requirements

  # ==========================================================================
  # VULNERABILITY: Storing password in reversible format
  # RISK: If database is compromised, all passwords are immediately exposed
  # ==========================================================================
  before_save :encrypt_password

  def encrypt_password
    if password_changed?
      # WARNING: Base64 is encoding, NOT encryption - trivially reversible
      self.password_digest = Base64.encode64(password)

      # WARNING: Also storing an MD5 hash (weak, no salt, rainbow table vulnerable)
      self.password_hash = Digest::MD5.hexdigest(password)
    end
  end

  # ==========================================================================
  # VULNERABILITY: Plaintext password attribute
  # RISK: Password visible in logs, memory, serialized objects
  # ==========================================================================
  attr_accessor :password

  def password_changed?
    password.present?
  end

  # ==========================================================================
  # VULNERABILITY: Insecure authentication method
  # RISK: Timing attacks, no account lockout, no rate limiting
  # ==========================================================================
  def self.authenticate(username, password)
    user = find_by(username: username)
    return nil unless user

    # WARNING: MD5 comparison - weak hash, no salt
    provided_hash = Digest::MD5.hexdigest(password)

    # WARNING: Non-constant-time comparison enables timing attacks
    if user.password_hash == provided_hash
      user
    else
      nil
    end
  end

  # ==========================================================================
  # VULNERABILITY: Insecure password reset
  # RISK: Predictable reset tokens, account takeover
  # ==========================================================================
  def generate_reset_token
    # WARNING: Predictable token using time and sequential ID
    token = Digest::MD5.hexdigest("#{id}#{Time.now.to_i}")
    update(reset_token: token, reset_sent_at: Time.now)
    token
  end

  def self.reset_password(token, new_password)
    user = find_by(reset_token: token)
    return false unless user

    # WARNING: No token expiration check
    # WARNING: No password history check (password reuse)
    user.password = new_password
    user.reset_token = nil
    user.save
  end

  # ==========================================================================
  # VULNERABILITY: Overly permissive serialization
  # RISK: Sensitive data exposure in API responses, logs
  # ==========================================================================
  def as_json(options = {})
    # WARNING: Includes sensitive fields by default
    super(options).merge(
      'password_digest' => password_digest,
      'api_token' => api_token,
      'reset_token' => reset_token
    )
  end

  # ==========================================================================
  # VULNERABILITY: Role management without proper checks
  # RISK: Privilege escalation
  # ==========================================================================
  def promote_to_admin!
    # WARNING: No authorization check - any code path calling this grants admin
    update(role: 'admin', is_superuser: true)
  end

  def admin?
    role == 'admin'
  end

  # ==========================================================================
  # VULNERABILITY: Unsafe query methods
  # RISK: SQL injection through model methods
  # ==========================================================================
  def self.search(term)
    # WARNING: String interpolation in where clause
    where("username LIKE '%#{term}%' OR email LIKE '%#{term}%'")
  end

  def self.find_by_token(token)
    # WARNING: Interpolated into raw SQL
    find_by_sql("SELECT * FROM users WHERE api_token = '#{token}' LIMIT 1").first
  end
end
