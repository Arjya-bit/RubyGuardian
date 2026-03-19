# frozen_string_literal: true

# =============================================================================
# EDUCATIONAL ONLY - RubyGuardian Phase 1b
# This gemspec demonstrates how a malicious gem might be structured.
# DO NOT publish this gem to any package registry.
# =============================================================================

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'evil_logger/version'

Gem::Specification.new do |spec|
  spec.name          = 'evil_logger'
  spec.version       = EvilLogger::VERSION
  spec.authors       = ['RubyGuardian Research']
  spec.email         = ['research@example.com']

  spec.summary       = 'A simple logging utility for Ruby applications'
  spec.description   = <<~DESC
    EvilLogger provides a lightweight, extensible logging framework for Ruby
    applications. Features include custom formatters, log rotation, and
    multi-destination output.

    NOTE: This is an EDUCATIONAL gem for the RubyGuardian security research
    framework. It demonstrates techniques used by malicious gems and should
    NEVER be used in production.
  DESC
  spec.homepage      = 'https://github.com/rubyguardian/evil_logger'
  spec.license       = 'MIT'

  spec.required_ruby_version = '>= 2.7.0'

  spec.metadata['homepage_uri']    = spec.homepage
  spec.metadata['source_code_uri'] = spec.homepage
  spec.metadata['changelog_uri']   = "#{spec.homepage}/blob/main/CHANGELOG.md"

  # Educational note: The files list determines what gets packaged in the gem
  # A malicious gem would include all its payloads here
  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      f.match(%r{\A(?:test|spec|features)/})
    end
  rescue Errno::ENOENT
    Dir['lib/**/*', 'README.md', 'LICENSE.txt']
  end

  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Educational note: Dependencies are transitive trust relationships
  # Each dependency expands the attack surface
  spec.add_dependency 'logger', '~> 1.5'

  spec.add_development_dependency 'rspec', '~> 3.12'
  spec.add_development_dependency 'rubocop', '~> 1.50'

  # Educational note: post_install_message executes in the terminal
  # It cannot run code, but can be used for social engineering
  spec.post_install_message = <<~MSG
    Thank you for installing EvilLogger v#{EvilLogger::VERSION}!
    Run `evil_logger --setup` to configure your logging preferences.
  MSG
end
