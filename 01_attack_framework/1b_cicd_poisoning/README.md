# Phase 1b: CI/CD Pipeline Poisoning

> **WARNING: This module is for EDUCATIONAL and AUTHORIZED SECURITY RESEARCH purposes only.**
> All techniques documented here must only be used in sandboxed, isolated environments.
> Unauthorized use of these techniques against production systems is illegal and unethical.

## Overview

CI/CD Pipeline Poisoning is a class of supply chain attacks that targets the software build
and deployment infrastructure. By compromising the pipeline itself, attackers can inject
malicious code into software artifacts that are then distributed to end users, often with
legitimate digital signatures.

This module provides a comprehensive educational framework for understanding, simulating,
and defending against CI/CD pipeline poisoning attacks in the Ruby/Rails ecosystem.

## Theory

### The CI/CD Attack Surface

Modern CI/CD pipelines present a large attack surface:

```
Developer Workstation -> Source Control -> CI Build -> Artifact Registry -> Deployment
     |                      |                |              |                  |
     v                      v                v              v                  v
  IDE plugins          Webhooks          Build deps     Package repos      Runtime deps
  Git hooks            Branch rules      Build scripts  Container images   Config mgmt
  Local gems           PR automation     Test fixtures  Gem servers        Env variables
```

Each stage introduces trust boundaries that an attacker can exploit:

1. **Dependency Confusion**: Publishing malicious packages with names matching internal packages
2. **Build Script Injection**: Modifying CI configuration to execute arbitrary code
3. **Environment Variable Manipulation**: Injecting secrets or altering build behavior
4. **Artifact Tampering**: Modifying built artifacts before deployment
5. **Credential Theft**: Extracting CI/CD secrets for lateral movement

### Kill Chain: CI/CD Pipeline Attack

```
1. Reconnaissance     -> Identify target's CI/CD platform, dependencies, build process
2. Initial Access     -> Compromise dependency, CI config, or developer credentials
3. Execution          -> Malicious code runs during build/test/deploy phase
4. Persistence        -> Inject backdoor into build artifacts or pipeline config
5. Exfiltration       -> Extract secrets, source code, or credentials from CI environment
6. Impact             -> Distribute compromised software to end users
```

## Real-World Examples

### SolarWinds (SUNBURST) - 2020

The SolarWinds attack is considered one of the most sophisticated supply chain attacks ever
discovered. Key characteristics:

- **Target**: SolarWinds Orion IT monitoring platform (~18,000 customers)
- **Method**: Attackers compromised the build system to inject malicious code into legitimate
  software updates
- **Technique**: Modified the build process to include a backdoor (SUNBURST) in the
  `SolarWinds.Orion.Core.BusinessLayer.dll` assembly
- **Stealth**: The malicious code was designed to blend in with legitimate code, used delays
  before activation, and checked for security tools before executing
- **Impact**: Affected multiple US government agencies and Fortune 500 companies

**Key Lessons:**
- Build system integrity is critical
- Code signing alone is insufficient if the build is compromised
- Dormancy periods make detection extremely difficult

### Codecov (2021)

- **Target**: Codecov's Bash Uploader script used by thousands of CI pipelines
- **Method**: Attackers modified the Bash Uploader script hosted on codecov.io
- **Technique**: The modified script exfiltrated environment variables (including CI secrets)
  to an attacker-controlled server
- **Duration**: The compromise persisted for approximately 2 months
- **Impact**: Exposed CI/CD secrets for thousands of organizations

**Key Lessons:**
- Third-party CI scripts should be pinned to specific hashes
- Environment variables in CI contain highly sensitive data
- Supply chain attacks can be extremely stealthy

### event-stream (2018)

- **Target**: Popular npm package `event-stream` (2M+ weekly downloads)
- **Method**: Social engineering to gain maintainer access, then injecting malicious dependency
- **Technique**: Added `flatmap-stream` dependency containing encrypted malicious payload
  targeting a specific Bitcoin wallet application (Copay)
- **Impact**: Targeted theft of cryptocurrency from Copay wallet users

### ua-parser-js (2021)

- **Target**: npm package `ua-parser-js` (7M+ weekly downloads)
- **Method**: Compromised maintainer npm account
- **Technique**: Published malicious versions that installed cryptominers and credential stealers
- **Impact**: Widespread due to package popularity

## Module Structure

```
1b_cicd_poisoning/
├── README.md                          # This file
├── docs/                              # Educational documentation
│   ├── supply_chain_attack_theory.md  # Theoretical foundations
│   ├── gemfile_injection_methods.md   # Gemfile/Bundler attack vectors
│   ├── fileless_payload_techniques.md # In-memory execution techniques
│   ├── brakeman_bypass_research.md    # Static analysis evasion
│   └── github_actions_attack_surface.md # GitHub Actions specific attacks
├── poisoned_gems/                     # Educational malicious gem examples
│   ├── evil_logger/                   # Gem with monkey-patching backdoor
│   └── config_helper/                 # Gem with post-install hook payload
├── pipeline_simulations/              # CI/CD attack simulations
│   ├── github_actions/                # GitHub Actions workflow examples
│   └── local_simulation/             # Docker-based local simulation
├── c2_server/                        # Educational C2 server
│   ├── server.rb                     # Main Sinatra application
│   ├── routes/                       # API endpoints
│   ├── models/                       # Data models
│   ├── payloads/                     # Stage 2 payloads
│   └── db/                           # Database schema
├── specs/                            # Test specifications
└── scripts/                          # Automation scripts
```

## Getting Started

### Prerequisites

- Ruby 3.0+ with Bundler
- Docker and Docker Compose
- Basic understanding of CI/CD concepts
- Familiarity with Ruby gem structure

### Running the Simulations

```bash
# 1. Build the educational poisoned gems (sandboxed)
./scripts/build_poisoned_gem.sh

# 2. Run the pipeline attack simulation (Docker-isolated)
./scripts/run_pipeline_attack.sh

# 3. Verify fileless execution techniques
./scripts/verify_fileless.sh
```

### Safety Controls

All simulations include the following safety measures:

1. **Network Isolation**: Docker containers with no external network access
2. **Sandboxed Execution**: All payloads check for `RUBYGUARDIAN_SANDBOX=true`
3. **No Persistence**: Containers are destroyed after each simulation
4. **Localhost Only**: C2 server binds to 127.0.0.1 only
5. **Obvious Indicators**: All malicious code includes clear educational markers

## Defensive Recommendations

1. **Pin Dependencies**: Use exact version constraints and lock files
2. **Verify Checksums**: Validate gem checksums against known-good values
3. **Audit Dependencies**: Regularly audit gem dependencies with `bundle audit`
4. **Restrict CI Permissions**: Use least-privilege for CI/CD service accounts
5. **Monitor Build Artifacts**: Compare build outputs against expected baselines
6. **Use Signed Commits**: Require GPG-signed commits for sensitive repositories
7. **Isolate Build Environments**: Use ephemeral, network-restricted build containers
8. **Review CI Configuration Changes**: Treat `.github/workflows/` changes as security-sensitive

## References

- [SLSA Framework](https://slsa.dev/)
- [CNCF Supply Chain Security Best Practices](https://github.com/cncf/tag-security)
- [OWASP CI/CD Security Risks](https://owasp.org/www-project-top-10-ci-cd-security-risks/)
- [Sigstore](https://www.sigstore.dev/)
- [NIST SP 800-218: Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
