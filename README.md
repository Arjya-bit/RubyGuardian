# RubyGuardian — Ultimate Ruby Security Research Framework

[![Ruby](https://img.shields.io/badge/Ruby-3.x-red.svg)](https://www.ruby-lang.org/)
[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Mapped-orange.svg)](https://attack.mitre.org/)

> **DISCLAIMER**: This framework is designed exclusively for educational purposes, authorized security research, and controlled lab environments. See [DISCLAIMER.md](DISCLAIMER.md) for full legal and ethical guidelines.

## Overview

RubyGuardian is an end-to-end security research framework that unifies five interdependent components into a single, cohesive platform for studying Ruby-specific fileless malware techniques, detection mechanisms, and forensic analysis.

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    RubyGuardian Framework                        │
├─────────────┬─────────────┬──────────┬──────────┬──────────────┤
│  Attack     │  Detection  │    ML    │ Memory   │  Honeypot    │
│  Framework  │  Engine     │Classifier│Forensics │  System      │
│  (Red Team) │ (Blue Team) │          │          │              │
├─────────────┴─────────────┴──────────┴──────────┴──────────────┤
│              ELK Stack + Grafana + React Dashboard              │
├─────────────────────────────────────────────────────────────────┤
│           Docker / Vagrant / Kubernetes Infrastructure          │
└─────────────────────────────────────────────────────────────────┘
```

## Components

| # | Component | Directory | Description |
|---|-----------|-----------|-------------|
| 1 | **Attack Framework** | `01_attack_framework/` | Red team PoCs: process hollowing, CI/CD poisoning, LoLRuby, ObjectSpace persistence |
| 2 | **Detection Engine** | `02_detection_engine/` | Real-time behavioral monitoring with eBPF + rule engine |
| 3 | **ML Classifier** | `03_ml_classifier/` | Ensemble ML pipeline for Ruby malware classification |
| 4 | **Memory Forensics** | `04_memory_forensics/` | Volatility 3 plugins + GDB scripts for Ruby VM analysis |
| 5 | **Honeypot System** | `05_honeypot/` | Decoy apps + capture engine + sandbox |
| 6 | **Dashboard** | `06_dashboard/` | ELK Stack + Grafana + React UI |
| 7 | **Infrastructure** | `07_infrastructure/` | Docker, Vagrant, K8s, CI/CD |
| 8 | **Documentation** | `08_documentation/` | Research paper, thesis, guides |
| 9 | **Testing** | `09_testing/` | Unit, integration, adversarial tests |

## Quick Start

### Prerequisites

- Ruby 3.0+
- Python 3.11+
- Docker & Docker Compose
- Node.js 18+ (for dashboard)

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/RubyGuardian.git
cd RubyGuardian

# Copy environment template
cp .env.example .env

# Install Ruby dependencies
bundle install

# Install Python dependencies
pip install -r requirements.txt

# Start all services
docker-compose up -d

# Run the development environment
make dev
```

### Individual Components

```bash
# Attack Framework (in isolated container)
make attack-demo

# Detection Engine
make detection-start

# ML Classifier API
make classifier-api

# Memory Forensics
make forensics-analyze

# Honeypot
make honeypot-deploy

# Dashboard
make dashboard-start
```

## MITRE ATT&CK Mapping

| Technique | ATT&CK ID | Component |
|-----------|-----------|-----------|
| Process Hollowing | T1055.012 | `1a_process_hollowing/` |
| Supply Chain Compromise | T1195.002 | `1b_cicd_poisoning/` |
| Command & Scripting Interpreter | T1059.002 | `1c_lolruby/` |
| Hijack Execution Flow | T1574 | `1d_objectspace_persistence/` |
| Data Exfiltration | T1048 | `1c_lolruby/techniques/exfiltration/` |

## Technology Stack

| Category | Technologies |
|----------|-------------|
| Languages | Ruby 3.x, Python 3.11+, C, JavaScript/React |
| Attack Tooling | Ruby FFI/Fiddle, Sinatra, custom gems |
| Detection | auditd, eBPF/BCC, Sysmon, custom agent |
| ML | scikit-learn, XGBoost, PyTorch, SHAP |
| Forensics | Volatility 3, GDB, YARA |
| Infrastructure | Docker, Vagrant, Kubernetes, GitHub Actions |
| Visualization | Elasticsearch, Logstash, Kibana, Grafana, React + Recharts |

## Ethical Use

This project is strictly for:
- Academic research and education
- Authorized penetration testing
- Security tool development and testing
- CTF competitions and training

**Never** use these tools against systems you do not own or have explicit authorization to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.
