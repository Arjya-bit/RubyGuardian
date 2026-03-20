# frozen_string_literal: true
#
# RubyGuardian - Vulnerable Admin Controller
# PURPOSE: Educational security research - demonstrates common controller vulnerabilities
# WARNING: This controller contains INTENTIONAL vulnerabilities for security testing.
#          NEVER deploy code like this in production.

class AdminController < ApplicationController
  # WARNING: No authentication before_action - any user can access admin functions
  # VULNERABILITY: Missing authorization checks
  skip_before_action :verify_authenticity_token

  # ==========================================================================
  # VULNERABILITY: Unsafe Deserialization (Remote Code Execution)
  # RISK: Attacker can execute arbitrary code by sending crafted YAML/Marshal data
  # REF: CVE-2013-0156, CVE-2019-5420
  # ==========================================================================
  def import_config
    # WARNING: YAML.unsafe_load allows arbitrary object instantiation
    config_data = YAML.unsafe_load(params[:config_yaml])
    @settings = config_data

    # WARNING: Marshal.load is equally dangerous with untrusted input
    if params[:marshal_data]
      binary_data = Base64.decode64(params[:marshal_data])
      @imported_objects = Marshal.load(binary_data)  # RCE vector
    end

    render json: { status: 'imported', settings: @settings }
  end

  # ==========================================================================
  # VULNERABILITY: eval() with user input (Remote Code Execution)
  # RISK: Complete server compromise - arbitrary Ruby code execution
  # ==========================================================================
  def execute_query
    # WARNING: Direct eval of user-supplied code
    query_expression = params[:expression]
    @result = eval(query_expression)  # CRITICAL: RCE vulnerability

    render json: { result: @result.to_s }
  rescue => e
    render json: { error: e.message }, status: 500
  end

  # ==========================================================================
  # VULNERABILITY: send() with user-controlled method name
  # RISK: Arbitrary method invocation, potential RCE
  # ==========================================================================
  def dynamic_action
    # WARNING: User controls which method gets called
    method_name = params[:action_name]
    method_args = params[:args]

    @output = self.send(method_name, *Array(method_args))
    render json: { output: @output }
  end

  # ==========================================================================
  # VULNERABILITY: Mass Assignment / Insecure Direct Object Reference
  # RISK: Privilege escalation, unauthorized data modification
  # ==========================================================================
  def update_user
    # WARNING: No authorization check - any user can update any other user
    user = User.find(params[:id])

    # WARNING: Updating with all params including role, admin flag, etc.
    user.update(params[:user].permit!)  # permit! allows ALL parameters

    # WARNING: Also vulnerable to IDOR - no check that current user owns this record
    render json: { user: user.as_json }
  end

  # ==========================================================================
  # VULNERABILITY: Insecure file operations
  # RISK: Arbitrary file read/write on the server
  # ==========================================================================
  def read_log
    # WARNING: Path traversal - user controls the file path
    log_path = params[:file] || 'production.log'
    file_path = File.join(Rails.root, 'log', log_path)

    # WARNING: No path sanitization - ../../etc/passwd is possible
    if File.exist?(file_path)
      @content = File.read(file_path)
      render plain: @content
    else
      render plain: "File not found: #{file_path}", status: 404
    end
  end

  # ==========================================================================
  # VULNERABILITY: Unsafe redirect (Open Redirect)
  # RISK: Phishing attacks, credential theft via redirect to malicious site
  # ==========================================================================
  def redirect_to_url
    # WARNING: No validation of redirect target
    target_url = params[:url]
    redirect_to target_url
  end

  # ==========================================================================
  # VULNERABILITY: Insecure token generation
  # RISK: Predictable tokens enable session hijacking, CSRF bypass
  # ==========================================================================
  def generate_api_token
    user = User.find(params[:user_id])

    # WARNING: Predictable token based on time and user ID
    token = Digest::MD5.hexdigest("#{user.id}-#{Time.now.to_i}")
    user.update(api_token: token)

    render json: { token: token }
  end

  # ==========================================================================
  # VULNERABILITY: Constant-time comparison not used
  # RISK: Timing attacks to brute-force secrets
  # ==========================================================================
  def verify_admin_secret
    provided_secret = params[:secret]
    actual_secret = ENV['ADMIN_SECRET'] || 'default_admin_secret'

    # WARNING: String == is vulnerable to timing attacks
    if provided_secret == actual_secret
      session[:admin] = true
      render json: { authenticated: true }
    else
      render json: { authenticated: false }, status: 401
    end
  end

  private

  # WARNING: No strong parameters - all params are trusted
  def admin_params
    params.permit!
  end
end
