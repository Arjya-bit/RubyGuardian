# Changelog

All notable changes to the RubyGuardian project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-18

### Added
- Phase 1: Multi-Vector Attack Framework
  - Process hollowing via Ruby FFI (Windows + Linux)
  - CI/CD pipeline poisoning simulation with malicious gems
  - Living-off-the-Land Ruby (LoLRuby) technique catalog
  - ObjectSpace persistence evasion PoCs
  - Sinatra-based C2 server infrastructure
- Phase 2: Real-Time Behavioral Detection Engine
  - Monitoring agent with eBPF and auditd integration
  - YAML-based rule engine with correlation capabilities
  - Multi-channel alerting system (Email, Slack, Syslog, ELK)
- Phase 3: ML Classifier and Forensics
  - Feature extraction pipeline (static + behavioral)
  - Ensemble ML classifier (Random Forest, XGBoost, Neural Network)
  - FastAPI classification API
  - Custom Volatility 3 plugins for Ruby VM analysis
  - GDB automation scripts for heap inspection
  - YARA rules for Ruby malware indicators
- Phase 4: Dashboard and Infrastructure
  - ELK Stack configuration with custom dashboards
  - Grafana monitoring dashboards
  - React-based web UI with real-time threat visualization
  - Docker Compose orchestration for all services
  - Vagrant multi-VM lab environment
  - Kubernetes deployment manifests
  - Honeypot system with decoy Rails app, gem server, and CI runner
- Complete test suite (unit, integration, adversarial)
- Research paper template (IEEE format)
- Thesis template with all chapters
- Comprehensive documentation and guides
