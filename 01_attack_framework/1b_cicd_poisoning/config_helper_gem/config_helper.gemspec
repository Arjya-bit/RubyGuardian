# frozen_string_literal: true

# =============================================================================
# RubyGuardian - Trojanized Gem Specimen: config_helper.gemspec
# =============================================================================
#
# EDUCATIONAL DISCLAIMER:
#   This gemspec demonstrates how a trojanized Ruby gem might be structured
#   to appear legitimate while containing hidden CI/CD poisoning hooks.
#   This is a RESEARCH SPECIMEN for studying supply chain attacks.
#
#   DO NOT publish this gem to any package registry.
#   DO NOT install this gem outside of a sandboxed research environment.
#
# MITRE ATT&CK References:
#   - T1195.002 : Supply Chain Compromise: Compromise Software Supply Chain
#   - T1059.004 : Command and Scripting Interpreter: Unix Shell
#   - T1204.002 : User Execution: Malicious File
#
# Attack Vector Analysis:
#   Gemspecs can be weaponized in several ways:
#   1. The `extensions` field triggers native compilation via extconf.rb,
#      which can execute arbitrary Ruby code at install time.
#   2. The `post_install_message` is displayed after install, which can
#      be used for social engineering.
#   3. Dependencies can pull in additional malicious packages.
#   4. The gem's lib/ files execute when 'require' is called.
# =============================================================================

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'config_helper'
  spec.version       = '1.2.3'
  spec.authors       = ['RubyGuardian Research']
  spec.email         = ['research@example.com']

  spec.summary       = 'A simple configuration file helper for Ruby applications'
  spec.description   = <<~DESC
    ConfigHelper provides a clean, intuitive interface for loading and managing
    YAML and JSON configuration files in Ruby applications. Supports environment
    overlays, default values, and nested key access.

    NOTE: This is a RESEARCH SPECIMEN from the RubyGuardian security framework.
    It demonstrates supply chain attack techniques. DO NOT use in production.
  DESC

  spec.homepage      = 'https://github.com/rubyguardian/config_helper'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 3.0.0'

  spec.metadata = {
    'homepage_uri'    => spec.homepage,
    'source_code_uri' => spec.homepage,
    'changelog_uri'   => "#{spec.homepage}/blob/main/CHANGELOG.md",
    # Research note: Attackers often include legitimate-looking metadata
    # to pass cursory review during dependency audits.
    'rubygems_mfa_required' => 'true'
  }

  # File list - appears to be a normal gem structure
  spec.files = Dir[
    'lib/**/*.rb',
    'ext/**/*',
    'README.md',
    'LICENSE',
    'CHANGELOG.md'
  ]

  spec.require_paths = ['lib']

  # ---------------------------------------------------------------------------
  # ATTACK VECTOR: Native Extension (T1195.002, T1059.004)
  # ---------------------------------------------------------------------------
  # The `extensions` field causes RubyGems to execute ext/extconf.rb during
  # `gem install`. This is the primary attack vector: extconf.rb runs as
  # the installing user with full system access.
  #
  # In a real trojanized gem, extconf.rb would:
  #   - Detect if running in a CI/CD environment
  #   - Exfiltrate environment variables (secrets, tokens)
  #   - Inject backdoors into the build pipeline
  #   - Phone home to a C2 server
  #
  # RESEARCH NOTE: The extconf.rb in this specimen has all malicious
  # functionality COMMENTED OUT and replaced with logging.
  spec.extensions = ['ext/extconf.rb']

  # ---------------------------------------------------------------------------
  # Dependencies - kept minimal to appear lightweight and trustworthy
  # ---------------------------------------------------------------------------
  # Research note: Trojanized gems typically have few dependencies to
  # avoid scrutiny and to make the gem appear simple and safe.
  spec.add_dependency 'yaml',  '~> 0.3'
  spec.add_dependency 'json',  '~> 2.7'

  # Development dependencies
  spec.add_development_dependency 'rspec', '~> 3.13'
  spec.add_development_dependency 'rubocop', '~> 1.62'

  # ---------------------------------------------------------------------------
  # Post-install message (Social Engineering Vector)
  # ---------------------------------------------------------------------------
  # Research note: Attackers can use post_install_message for:
  #   - Directing users to run additional setup commands
  #   - Displaying fake security warnings to create urgency
  #   - Providing links to phishing sites disguised as documentation
  spec.post_install_message = <<~MSG
    Thank you for installing ConfigHelper v#{spec.version}!
    Documentation: https://github.com/rubyguardian/config_helper

    [RubyGuardian Research Note: This is a supply chain attack specimen.
     In a real attack, this message might direct you to run a malicious
     setup script or visit a credential-harvesting page.]
  MSG
end
