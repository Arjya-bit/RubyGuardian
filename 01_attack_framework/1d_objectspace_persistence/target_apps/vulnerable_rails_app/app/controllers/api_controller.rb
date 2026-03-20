# frozen_string_literal: true
#
# RubyGuardian - Vulnerable API Controller
# PURPOSE: Educational security research - demonstrates injection vulnerabilities
# WARNING: This controller contains INTENTIONAL vulnerabilities for security testing.
#          NEVER deploy code like this in production.

class ApiController < ApplicationController
  skip_before_action :verify_authenticity_token

  # ==========================================================================
  # VULNERABILITY: SQL Injection via string interpolation
  # RISK: Full database compromise - read, modify, delete any data
  # ==========================================================================
  def search_users
    query = params[:q]

    # WARNING: Direct string interpolation into SQL query
    @users = ActiveRecord::Base.connection.execute(
      "SELECT * FROM users WHERE username LIKE '%#{query}%' OR email LIKE '%#{query}%'"
    )

    render json: { users: @users.to_a }
  end

  # ==========================================================================
  # VULNERABILITY: SQL Injection via order clause
  # RISK: Data exfiltration through ORDER BY injection
  # ==========================================================================
  def list_records
    table = params[:table] || 'users'
    order = params[:order] || 'id'
    direction = params[:dir] || 'ASC'

    # WARNING: Table name, column, and direction are all user-controlled
    sql = "SELECT * FROM #{table} ORDER BY #{order} #{direction} LIMIT 100"
    @records = ActiveRecord::Base.connection.execute(sql)

    render json: { records: @records.to_a }
  end

  # ==========================================================================
  # VULNERABILITY: Command Injection via system/backtick calls
  # RISK: Arbitrary OS command execution, full server compromise
  # ==========================================================================
  def ping_host
    hostname = params[:host]

    # WARNING: Direct injection into system command
    result = `ping -c 3 #{hostname}`

    render json: { output: result }
  end

  # ==========================================================================
  # VULNERABILITY: Command Injection via Kernel.system
  # RISK: Arbitrary command execution with shell interpretation
  # ==========================================================================
  def check_dns
    domain = params[:domain]

    # WARNING: User input passed directly to system()
    output = IO.popen("nslookup #{domain}") { |io| io.read }

    render json: { dns_result: output }
  end

  # ==========================================================================
  # VULNERABILITY: Server-Side Request Forgery (SSRF)
  # RISK: Access internal services, cloud metadata, port scanning
  # ==========================================================================
  def fetch_url
    url = params[:url]

    # WARNING: No URL validation - can access internal network resources
    # e.g., http://169.254.169.254/latest/meta-data/ (AWS metadata)
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)

    render json: {
      status: response.code,
      headers: response.to_hash,
      body: response.body.truncate(10_000)
    }
  rescue => e
    render json: { error: e.message }, status: 500
  end

  # ==========================================================================
  # VULNERABILITY: Insecure Direct Object Reference (IDOR)
  # RISK: Access any user's data by guessing/enumerating IDs
  # ==========================================================================
  def user_profile
    # WARNING: No authorization check - sequential IDs are easily enumerated
    user = User.find(params[:id])

    # WARNING: Exposing all attributes including sensitive fields
    render json: user.as_json(
      only: [:id, :username, :email, :password_digest, :api_token,
             :role, :ssn, :phone, :address, :created_at]
    )
  end

  # ==========================================================================
  # VULNERABILITY: Regex Denial of Service (ReDoS)
  # RISK: Application-level DoS by sending crafted input
  # ==========================================================================
  def validate_input
    input = params[:data]

    # WARNING: Catastrophic backtracking possible with crafted input
    # e.g., "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!" triggers exponential time
    pattern = /^(a+)+$/
    match = pattern.match(input)

    render json: { valid: !match.nil? }
  end

  # ==========================================================================
  # VULNERABILITY: Information disclosure via error handling
  # RISK: Stack traces, internal paths, gem versions leaked to attacker
  # ==========================================================================
  def process_data
    data = JSON.parse(params[:payload])
    result = data.deep_transform_keys(&:to_sym)

    render json: { processed: result }
  rescue => e
    # WARNING: Full exception details sent to client
    render json: {
      error: e.class.name,
      message: e.message,
      backtrace: e.backtrace&.first(20),
      ruby_version: RUBY_VERSION,
      rails_version: Rails::VERSION::STRING
    }, status: 500
  end

  # ==========================================================================
  # VULNERABILITY: Weak authentication / API key in header
  # RISK: Credential brute-forcing, no rate limiting
  # ==========================================================================
  def authenticated_action
    api_key = request.headers['X-API-Key']

    # WARNING: Hardcoded API key, no rate limiting, no lockout
    unless api_key == 'super_secret_api_key_12345'
      render json: { error: 'Unauthorized' }, status: 401
      return
    end

    render json: { message: 'Authenticated successfully', data: 'sensitive_payload' }
  end
end
