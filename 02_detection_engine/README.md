# RubyGuardian Phase 2 - Real-Time Behavioral Detection Engine

## Overview

The RubyGuardian Detection Engine is a blue-team defense component that provides
real-time behavioral analysis and threat detection for Ruby runtime environments.
It monitors process behavior, system calls, memory patterns, network activity,
and ObjectSpace anomalies to detect attacks including process hollowing, fileless
execution, LOLRuby (Living Off the Land Ruby) techniques, and runtime tampering.

## Architecture

```
+-------------------+     +------------------+     +-------------------+
|   Agent Daemon    |---->|   Rule Engine    |---->| Alert Dispatcher  |
| (ruby_guardian_   |     | (correlation,    |     | (email, slack,    |
|  agent.rb)        |     |  chain detect,   |     |  syslog, ES,     |
|                   |     |  thresholds)     |     |  webhooks)        |
+-------------------+     +------------------+     +-------------------+
  |  |  |  |  |  |
  v  v  v  v  v  v
 Process  Syscall  Memory  Network  File  ObjectSpace
 Monitor  Tracer   Insp.   Monitor  Mon.  Scanner
  |         |
  v         v
 Native Extensions
 (eBPF bridge, ptrace helper)
```

## Components

### Agent (`agent/`)
- **ruby_guardian_agent.rb** - Main daemon entry point with signal handling
- **process_monitor.rb** - Monitors Ruby process behavior (fork, exec, spawn)
- **syscall_tracer.rb** - Traces system calls via ptrace/eBPF
- **memory_inspector.rb** - Inspects memory regions for anomalies
- **network_monitor.rb** - Monitors network connections for beaconing/exfil
- **file_monitor.rb** - Watches filesystem changes via inotify
- **objectspace_scanner.rb** - Scans ObjectSpace for tampered/injected objects
- **event_collector.rb** - Central event bus collecting all monitor events
- **heartbeat.rb** - Health monitoring and watchdog

### Native Extensions (`agent/native_extensions/`)
- **ebpf_bridge** - eBPF probes for syscall, memory, and network monitoring
- **ptrace_helper** - ptrace-based process inspection

### Rule Engine (`rule_engine/`)
- **engine.rb** - Main rule evaluation engine
- **rule_parser.rb** - Parses YAML signature definitions
- **rule_matcher.rb** - Matches events against rule patterns
- **correlation_engine.rb** - Correlates events across time windows
- **threshold_tracker.rb** - Tracks event frequency thresholds
- **chain_detector.rb** - Detects multi-stage attack chains
- **false_positive_filter.rb** - Reduces noise from known benign patterns

### Detection Rules (`rule_engine/rules/`)
- **syscall_sequence_rule.rb** - Detects suspicious syscall sequences
- **memory_anomaly_rule.rb** - Detects RWX regions, shellcode patterns
- **eval_detection_rule.rb** - Detects dynamic code execution abuse
- **network_beacon_rule.rb** - Detects C2 beaconing patterns
- **objectspace_tamper_rule.rb** - Detects ObjectSpace manipulation
- **composite_attack_rule.rb** - Combines multiple indicators

### Alerting (`alerting/`)
- **alert_dispatcher.rb** - Routes alerts to configured channels
- **Formatters** - JSON, syslog, human-readable output formats
- **Channels** - Email, Slack, syslog, Elasticsearch, webhook

## Quick Start

```bash
# Install dependencies
make setup

# Build native extensions
make build

# Run tests
make test

# Start the agent (development mode)
make run-dev

# Start the agent (production daemon)
make run-prod

# Install as systemd service
sudo make install-service
```

## Configuration

Edit `config/detection_config.yml` to configure:
- Monitoring targets and intervals
- Detection sensitivity levels
- Alert routing and thresholds
- False positive exclusions

Custom signatures can be added to `config/signatures/custom/`.

## Requirements

- Ruby >= 3.1
- Linux kernel >= 5.8 (for eBPF support)
- libelf-dev, libbpf-dev (for eBPF bridge)
- auditd or sysmon (optional, for audit integration)

## Deployment

### Docker
```bash
docker build -t ruby-guardian-agent -f agent/Dockerfile .
docker run --privileged --pid=host ruby-guardian-agent
```

### systemd
```bash
sudo cp agent/systemd/ruby-guardian-agent.service /etc/systemd/system/
sudo systemctl enable --now ruby-guardian-agent
```

## License

Internal security tool - see project root LICENSE.
