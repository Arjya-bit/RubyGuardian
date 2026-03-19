# Supply Chain Attack Theory

> **EDUCATIONAL MATERIAL - For authorized security research only**

## 1. Foundations

### What Is a Software Supply Chain?

A software supply chain encompasses every component, tool, process, and human involved in
creating, building, and distributing software. This includes:

- **Source code** (your code + third-party dependencies)
- **Build tools** (compilers, interpreters, bundlers)
- **CI/CD infrastructure** (GitHub Actions, Jenkins, CircleCI)
- **Package registries** (RubyGems.org, npm, PyPI)
- **Container registries** (Docker Hub, ECR, GCR)
- **Deployment infrastructure** (Kubernetes, cloud providers)

### Trust Boundaries

Every transition point in the supply chain is a trust boundary:

```
Developer Trust    ->  Source Trust     ->  Build Trust      ->  Distribution Trust
(Who wrote this?)     (Is this the       (Was this built     (Is this what was
                       real source?)      correctly?)          built?)
```

### The Transitive Trust Problem

When you add a gem to your Gemfile, you are implicitly trusting:

1. The gem author(s)
2. All maintainers with push access
3. All transitive dependencies (and their maintainers)
4. RubyGems.org infrastructure
5. The gem's build/release process
6. DNS resolution to rubygems.org
7. TLS certificate authorities

```ruby
# This single line creates a transitive trust chain of potentially
# hundreds of packages and dozens of maintainers
gem 'rails', '~> 7.0'

# Rails 7.0 depends on: actioncable, actionmailbox, actionmailer,
# actionpack, actiontext, actionview, activejob, activemodel,
# activerecord, activestorage, activesupport, railties
# Each of those has its own dependency tree...
```

## 2. Attack Taxonomy

### 2.1 Dependency Confusion

**Concept**: Exploit package manager resolution logic to substitute an internal package
with a malicious public package of the same name.

```
Internal gem server:  my-company-auth (v1.0.0)
Public RubyGems.org:  my-company-auth (v99.0.0)  <-- attacker publishes this

Bundler resolution may prefer the higher version from the public source
```

**Ruby-specific vectors**:
- Bundler source priority when multiple sources are configured
- `source` blocks in Gemfile can be overridden
- Private gem server misconfigurations

### 2.2 Typosquatting

**Concept**: Register package names that are common misspellings of popular packages.

```ruby
# Legitimate gems vs typosquatted names (educational examples)
gem 'devise'        # vs 'devize', 'deviise'
gem 'nokogiri'      # vs 'nokoguri', 'nokogirii'
gem 'sidekiq'       # vs 'sidekick', 'sidekiqq'
gem 'rails'         # vs 'raills', 'raiils'
```

### 2.3 Maintainer Compromise

**Concept**: Gain control of a legitimate maintainer's account through credential theft,
social engineering, or coercion.

**Attack flow**:
1. Identify target gem maintainer
2. Phish credentials or find leaked API keys
3. Push malicious gem version
4. Users auto-update to compromised version

### 2.4 Build System Compromise

**Concept**: Compromise the CI/CD pipeline to inject malicious code during the build process.

This is the primary focus of this module. Vectors include:

- **CI configuration injection**: Modifying workflow files
- **Build dependency substitution**: Replacing legitimate build tools
- **Environment variable manipulation**: Altering build behavior through env vars
- **Artifact tampering**: Modifying outputs after build but before distribution

### 2.5 Source Code Compromise

**Concept**: Inject malicious code into the source repository through compromised
developer credentials, malicious PRs, or compromised development tools.

## 3. The CI/CD Pipeline as Attack Vector

### Why Target CI/CD?

1. **Elevated privileges**: CI systems often have deployment credentials, cloud API keys,
   and signing keys
2. **Transient environments**: Evidence is destroyed when containers are torn down
3. **Trusted context**: Code running in CI is implicitly trusted
4. **Scale**: A single CI compromise can affect all users of the software
5. **Stealth**: CI logs are rarely audited for malicious activity

### CI/CD Attack Surfaces by Platform

#### GitHub Actions
- Workflow file injection via PR
- Action supply chain (compromised actions)
- Self-hosted runner escape
- Secret exfiltration via logs or network
- GITHUB_TOKEN permission abuse

#### Jenkins
- Script console access
- Plugin vulnerabilities
- Shared library injection
- Agent-to-controller escape
- Credential store access

#### GitLab CI
- `.gitlab-ci.yml` injection
- Shared runner abuse
- Registry token theft
- Variable exposure

## 4. Ruby-Specific Attack Vectors

### Gemfile Manipulation

```ruby
# The Gemfile is Ruby code - it can execute arbitrary operations
# This is a fundamental security concern

# Educational example: Gemfile that conditionally loads malicious code
source 'https://rubygems.org'

gem 'rails', '~> 7.0'

# An attacker could add conditional logic that only activates in CI
if ENV['CI']
  # This code executes during `bundle install` in CI
  # Educational note: this is why Gemfile changes should be reviewed carefully
end
```

### Extension Building (extconf.rb)

```ruby
# ext/extconf.rb runs during `gem install` with full system access
# This is a legitimate feature used by gems with C extensions (e.g., nokogiri)
# But it's also a powerful attack vector

require 'mkmf'

# Educational: extconf.rb can execute arbitrary system commands
# A malicious gem could use this to:
# - Download and execute additional payloads
# - Exfiltrate environment variables
# - Establish persistence
```

### Post-Install Hooks

```ruby
# Gem specifications support post-install messages and hooks
# These execute after gem installation

Gem::Specification.new do |spec|
  spec.extensions = ['ext/extconf.rb']  # Runs during install
  spec.post_install_message = "Thanks for installing!"
end
```

## 5. Detection Evasion Techniques

### Time-Based Activation
- Payload activates only after a delay (SolarWinds used 2 weeks)
- Avoids detection during initial testing/review

### Environment Detection
- Check for sandbox indicators before executing
- Only activate in production environments
- Detect CI vs local development

### Code Obfuscation
- Use Ruby metaprogramming to hide intent
- Dynamic method definition
- Encoded payloads decoded at runtime

### Anti-Analysis
- Detect debuggers and profilers
- Check for security scanning tools
- Modify behavior when being observed

## 6. Defensive Framework

### SLSA (Supply-chain Levels for Software Artifacts)

| Level | Requirements |
|-------|-------------|
| SLSA 1 | Build process documented; provenance generated |
| SLSA 2 | Hosted build platform; authenticated provenance |
| SLSA 3 | Hardened build platform; non-falsifiable provenance |
| SLSA 4 | Two-person review; hermetic, reproducible builds |

### Practical Defenses for Ruby Projects

1. **Lock dependencies**: Always commit `Gemfile.lock`
2. **Audit regularly**: Run `bundle audit` in CI
3. **Pin versions**: Use exact versions for critical dependencies
4. **Verify sources**: Use `source` blocks carefully in Gemfile
5. **Review dependency updates**: Don't auto-merge dependency PRs
6. **Monitor for new gems**: Watch for typosquatting of your internal gems
7. **Use Bundler's `frozen` mode**: Prevent Gemfile.lock modifications in CI
8. **Implement SBOM**: Generate Software Bill of Materials for your applications

## References

- Ohm, M. et al. "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks" (2020)
- Ladisa, P. et al. "A Taxonomy of Attacks on Open-Source Software Supply Chains" (2023)
- NIST SP 800-218: Secure Software Development Framework
- SLSA: Supply-chain Levels for Software Artifacts (https://slsa.dev)
