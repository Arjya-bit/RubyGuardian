# frozen_string_literal: true
#
# RubyGuardian - Vulnerable Sinatra Application
# PURPOSE: Educational security research - demonstrates web application vulnerabilities
# WARNING: This application contains INTENTIONAL vulnerabilities for security testing.
#          NEVER deploy this application on a public network.

require 'sinatra'
require 'sinatra/reloader' if development?
require 'erb'
require 'json'
require 'sqlite3'
require 'yaml'
require 'open-uri'
require 'fileutils'

# WARNING: Hardcoded secret - predictable session cookies
set :session_secret, 'insecure_secret_key_for_testing'
set :sessions, true
set :show_exceptions, true  # WARNING: Leaks stack traces to users

# WARNING: No CSRF protection enabled
# WARNING: No security headers configured

DB = SQLite3::Database.new(':memory:')
DB.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, role TEXT)')
DB.execute("INSERT INTO users VALUES (1, 'admin', 'admin@test.com', 'admin')")
DB.execute("INSERT INTO users VALUES (2, 'guest', 'guest@test.com', 'user')")

# ==========================================================================
# VULNERABILITY: Server-Side Template Injection (SSTI)
# RISK: Remote Code Execution through template engine
# ==========================================================================
get '/' do
  @title = params[:title] || 'Welcome'
  erb :index
end

post '/render_template' do
  # WARNING: User input rendered directly as ERB template
  # Payload example: <%= system('whoami') %> or <%= `id` %>
  user_template = params[:template]
  erb_template = ERB.new(user_template)
  erb_template.result(binding)
end

# ==========================================================================
# VULNERABILITY: File Traversal / Local File Inclusion
# RISK: Read arbitrary files from the server filesystem
# ==========================================================================
get '/files' do
  # WARNING: No path sanitization - ../../etc/passwd works
  filename = params[:name]
  filepath = File.join(settings.root, 'public', filename)

  # WARNING: Attacker can escape the public directory
  if File.exist?(filepath)
    send_file filepath
  else
    status 404
    "File not found: #{filename}"  # WARNING: Reflects filename (XSS)
  end
end

get '/download' do
  # WARNING: Direct path traversal with no restrictions
  path = params[:path]
  content_type 'application/octet-stream'
  File.read(path)  # CRITICAL: Reads any file on the filesystem
end

# ==========================================================================
# VULNERABILITY: eval() with user input
# RISK: Arbitrary Ruby code execution
# ==========================================================================
get '/calc' do
  # WARNING: Math expression evaluated as Ruby code
  # Payload example: ?expr=system('cat /etc/passwd')
  expression = params[:expr]
  begin
    result = eval(expression)  # CRITICAL: RCE vulnerability
    "Result: #{result}"
  rescue => e
    "Error: #{e.message}"
  end
end

# ==========================================================================
# VULNERABILITY: SQL Injection
# RISK: Database compromise, data exfiltration
# ==========================================================================
get '/users/search' do
  query = params[:q]
  # WARNING: String interpolation in SQL query
  results = DB.execute("SELECT * FROM users WHERE name LIKE '%#{query}%'")
  content_type :json
  results.to_json
end

get '/users/:id' do
  # WARNING: Direct interpolation of URL parameter into SQL
  user = DB.execute("SELECT * FROM users WHERE id = #{params[:id]}").first
  if user
    content_type :json
    { id: user[0], name: user[1], email: user[2], role: user[3] }.to_json
  else
    status 404
    'User not found'
  end
end

# ==========================================================================
# VULNERABILITY: Unsafe deserialization
# RISK: Remote Code Execution via crafted YAML/Marshal payloads
# ==========================================================================
post '/import' do
  data_format = params[:format] || 'json'

  case data_format
  when 'yaml'
    # WARNING: YAML.unsafe_load allows arbitrary object instantiation
    data = YAML.unsafe_load(params[:data])
  when 'marshal'
    # WARNING: Marshal.load executes code during deserialization
    data = Marshal.load(Base64.decode64(params[:data]))
  else
    data = JSON.parse(params[:data])
  end

  content_type :json
  { imported: data }.to_json
rescue => e
  status 500
  { error: e.message, backtrace: e.backtrace.first(10) }.to_json
end

# ==========================================================================
# VULNERABILITY: Server-Side Request Forgery (SSRF)
# RISK: Access internal services, cloud metadata endpoints
# ==========================================================================
get '/proxy' do
  url = params[:url]
  # WARNING: No URL validation, can reach internal network
  content = URI.open(url).read  # Also vulnerable to command injection via pipe
  content_type 'text/html'
  content
end

# ==========================================================================
# VULNERABILITY: Command Injection
# RISK: Arbitrary OS command execution
# ==========================================================================
get '/ping' do
  host = params[:host]
  # WARNING: Shell metacharacters not sanitized
  output = `ping -c 2 #{host} 2>&1`
  "<pre>#{output}</pre>"
end

get '/admin' do
  # WARNING: No authentication check
  erb :admin
end
