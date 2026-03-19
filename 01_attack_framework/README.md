# Phase 1 — Multi-Vector Attack Framework (Red Team)

> **WARNING**: This module contains proof-of-concept attack implementations for
> educational and authorized security research purposes ONLY. See [DISCLAIMER.md](../DISCLAIMER.md).

## Overview

The attack framework implements four distinct Ruby-specific threat vectors that
collectively cover the full Cyber Kill Chain from initial access through
persistence and command-and-control.

## Attack Vectors

| Module | Technique | MITRE ATT&CK | Directory |
|--------|-----------|---------------|-----------|
| 1a | Process Hollowing via Ruby FFI | T1055.012 | `1a_process_hollowing/` |
| 1b | CI/CD Pipeline Poisoning | T1195.002 | `1b_cicd_poisoning/` |
| 1c | Living-off-the-Land Ruby | T1059.002 | `1c_lolruby/` |
| 1d | ObjectSpace Persistence | T1574 | `1d_objectspace_persistence/` |

## Safety Controls

All attack modules implement the following safety controls:

1. **Benign Payloads Only**: All PoCs use harmless operations (calculator spawn, `id` command)
2. **Network Isolation**: C2 communications restricted to localhost/Docker networks
3. **Explicit Confirmation**: Destructive operations require user confirmation
4. **Sandbox Detection**: Modules verify they're running in controlled environments
5. **Kill Switch**: All persistent payloads include a deactivation mechanism

## Quick Start

```bash
# Run in isolated Docker container
docker-compose run --rm attacker bash

# Execute specific demo
cd 01_attack_framework
bundle exec ruby 1a_process_hollowing/scripts/run_hollow_demo.rb
```

## Dependencies

See `Gemfile` for Ruby dependencies. All modules share common utilities from `shared/`.
