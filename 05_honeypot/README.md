# RubyGuardian Phase 5 - Honeypot & Threat Intelligence System

## Overview

Phase 5 implements a comprehensive honeypot and threat intelligence system designed to
attract, capture, and analyze attacks targeting Ruby/Rails ecosystems. The system deploys
realistic decoy applications that mimic vulnerable Ruby services, capturing attacker
techniques, payloads, and behavioral patterns for threat intelligence generation.

## Architecture

```
                          ┌─────────────────────────────┐
                          │     Threat Intelligence      │
                          │        Feed Ingestion        │
                          └──────────────┬──────────────┘
                                         │
┌─────────────┐    ┌─────────────────────▼──────────────────────┐
│  Attackers   │───▶│            Decoy Applications              │
│              │    │  ┌───────────┐ ┌──────────┐ ┌──────────┐  │
│              │    │  │ Fake Rails│ │Fake Gem  │ │ Fake CI  │  │
│              │    │  │   App     │ │ Server   │ │ Runner   │  │
│              │    │  └─────┬─────┘ └────┬─────┘ └────┬─────┘  │
└─────────────┘    └────────┼─────────────┼────────────┼────────┘
                            │             │            │
                   ┌────────▼─────────────▼────────────▼────────┐
                   │            Capture Engine                   │
                   │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │
                   │  │ Packet   │ │ Request  │ │  Eval    │   │
                   │  │ Logger   │ │ Logger   │ │  Trap    │   │
                   │  ├──────────┤ ├──────────┤ ├──────────┤   │
                   │  │ Exec     │ │ File     │ │Credential│   │
                   │  │ Trap     │ │ Trap     │ │  Trap    │   │
                   │  └──────────┘ └──────────┘ └──────────┘   │
                   └────────────────────┬───────────────────────┘
                                        │
                   ┌────────────────────▼───────────────────────┐
                   │              Sandbox                        │
                   │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │
                   │  │Container │ │ Resource │ │ Behavior │   │
                   │  │ Manager  │ │ Limiter  │ │ Recorder │   │
                   │  └──────────┘ └──────────┘ └──────────┘   │
                   └────────────────────┬───────────────────────┘
                                        │
                   ┌────────────────────▼───────────────────────┐
                   │              Analysis                       │
                   │  ┌──────────┐ ┌──────────┐ ┌──────────┐   │
                   │  │ Sample   │ │ Pattern  │ │   IP     │   │
                   │  │ Analyzer │ │ Matcher  │ │ Enricher │   │
                   │  └──────────┘ └──────────┘ └──────────┘   │
                   └────────────────────────────────────────────┘
```

## Components

### Decoy Applications

- **Fake Rails App**: Simulates a vulnerable Ruby on Rails application with exposed admin
  panels, weak API endpoints, and common misconfigurations that attract attackers.
- **Fake Gem Server**: Mimics a private RubyGems server to detect dependency confusion
  attacks and malicious gem upload attempts.
- **Fake CI Runner**: Emulates a CI/CD runner with planted fake secrets and credentials
  to detect lateral movement and credential harvesting.

### Capture Engine

- **Packet Logger**: Raw network packet capture and protocol analysis.
- **Request Logger**: HTTP/HTTPS request logging with full header and body capture.
- **Eval Trap**: Detects and logs `eval`, `instance_eval`, and dynamic code execution attempts.
- **Exec Trap**: Monitors system command execution attempts (`system`, backticks, `Open3`).
- **File Trap**: Tracks filesystem access patterns, reads/writes to sensitive paths.
- **Credential Trap**: Logs authentication attempts with planted fake credentials.
- **Sample Collector**: Collects and stores malicious payloads and samples for analysis.

### Sandbox

- **Executor**: Safe execution environment for analyzing captured malicious code.
- **Container Manager**: Docker container lifecycle management for isolated analysis.
- **Resource Limiter**: CPU, memory, network, and filesystem resource constraints.
- **Behavior Recorder**: Records all system calls, network activity, and file operations.

### Analysis

- **Sample Analyzer**: Static and dynamic analysis of captured malicious samples.
- **Pattern Matcher**: YARA-like rule matching and attack pattern classification.
- **IP Enricher**: Threat intelligence enrichment from external feeds and databases.
- **Daily Report Generator**: Automated daily threat intelligence reports.

## Setup

```bash
bundle install
```

### Configuration

1. Copy and customize configuration files in `config/`:
   - `honeypot_config.yml` - Main honeypot settings
   - `emulated_services.yml` - Service emulation parameters
   - `threat_feeds.yml` - External threat intelligence feed URLs

2. Build decoy containers:
   ```bash
   docker-compose build
   ```

3. Deploy honeypot services:
   ```bash
   ruby -r ./capture_engine/request_logger -e "RubyGuardian::Honeypot::RequestLogger.new.start"
   ```

## Running Tests

```bash
bundle exec rspec specs/
```

## Safety Warning

This system is designed to be deployed in isolated network segments. Never deploy honeypot
components on production networks without proper segmentation and monitoring. All captured
samples are potentially malicious and should be handled with appropriate caution.

## License

Part of the RubyGuardian security suite. Internal use only.
