# RubyGuardian Usage Guide

## Overview

RubyGuardian provides six integrated phases for studying Ruby security. This guide covers the practical workflows for each phase, including running attack demonstrations, operating the detection engine, training ML classifiers, performing memory forensics, managing honeypots, and using the dashboard.

**Important:** All attack techniques are for authorized security research only. Always operate within an isolated lab environment.

## Phase 1: Attack Framework

### 1a. Process Hollowing Demonstration

Process hollowing (MITRE ATT&CK T1055.012) replaces the memory of a legitimate process with malicious code.

```bash
# Run in an isolated Docker container (recommended)
make attack-demo

# Or run directly with dry-run mode (no actual process manipulation)
bundle exec ruby 01_attack_framework/1a_process_hollowing/scripts/run_hollow_demo.rb --dry-run
```

Configuration options in `ProcessHollower`:

```ruby
hollower = RubyGuardian::ProcessHollowing::ProcessHollower.new(
  target_binary: '/bin/sleep',
  payload_path: 'path/to/payload.bin',
  require_sandbox: true,   # Enforce sandbox environment
  dry_run: true,           # Log without executing
  log_level: :debug
)
result = hollower.execute
puts result[:outcome]  # :success or :failure
```

### 1b. CI/CD Poisoning Simulation

```bash
make attack-cicd-demo
```

This runs a simulated pipeline poisoning attack demonstrating how build systems can be compromised through dependency confusion and script injection.

### 1c. LoLRuby Techniques

Living-off-the-Land Ruby techniques use legitimate Ruby features for malicious purposes.

```bash
# List available techniques
make attack-lolruby

# Query specific technique
bundle exec ruby 01_attack_framework/1c_lolruby/lolruby_database/query_interface.rb --technique eval_injection
```

### 1d. ObjectSpace Persistence

Demonstrates how Ruby's ObjectSpace can be abused to hide persistent objects in the heap.

## Phase 2: Detection Engine

### Starting the Agent

The detection agent monitors the host system for suspicious Ruby activity.

```bash
# Start the agent
make detection-start

# Check status
make detection-status

# Stop the agent
make detection-stop
```

### Available Monitors

| Monitor              | Description                                  |
| -------------------- | -------------------------------------------- |
| ProcessMonitor       | Watches for suspicious process creation      |
| FileMonitor          | Detects file system changes in Ruby paths    |
| NetworkMonitor       | Monitors network connections from Ruby procs |
| ObjectSpaceScanner   | Scans Ruby heap for hidden objects           |
| MemoryInspector      | Inspects process memory for anomalies        |
| SyscallTracer        | Traces system calls via eBPF/ptrace          |

### Event Collection

Events flow through the `EventCollector`, which buffers, enriches, and dispatches them to subscribers (rule engine, alerting, logging).

```ruby
collector = RubyGuardian::Detection::EventCollector.new(config: config, logger: logger)
collector.subscribe do |event|
  puts "Alert: #{event[:type]} severity=#{event[:severity]}"
end
collector.start
```

## Phase 3: ML Classifier

### Training Models

```bash
# Full training pipeline
make classifier-train

# With custom config
python3 -m 03_ml_classifier.models.training.train_pipeline \
  --config config/training_config.yml \
  --features data/processed/features/features.csv \
  --labels data/processed/labels/labels.csv
```

The pipeline trains three models (Random Forest, XGBoost, Neural Network) and creates a weighted ensemble.

### Evaluating Models

```bash
make classifier-evaluate
```

### Using the Prediction API

```bash
# Start the API server
make classifier-api

# Submit a Ruby script for classification
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"script_path": "/path/to/script.rb"}'
```

Response format:

```json
{
  "prediction": "malicious",
  "confidence": 0.94,
  "model": "ensemble",
  "features": {
    "entropy": 7.2,
    "eval_count": 3,
    "obfuscation_score": 0.85
  }
}
```

## Phase 4: Memory Forensics

### Capturing a Memory Dump

```bash
# Automated capture
make forensics-dump

# Manual capture of a specific PID
bundle exec ruby -e "
  require_relative '04_memory_forensics/lib/memory_dumper'
  dumper = RubyGuardian::MemoryForensics::MemoryDumper.new(pid: ARGV[0])
  dumper.capture(output: 'dumps/target.dump')
" -- 12345
```

### Running Full Analysis

```bash
make forensics-analyze
```

This runs the complete forensic pipeline:
1. Parse the memory dump
2. Reconstruct Ruby objects from heap data
3. Extract strings and network artifacts
4. Scan for indicators of compromise (IOCs)
5. Build an execution timeline
6. Generate a report

### Verifying Dump Integrity

```ruby
result = RubyGuardian::MemoryForensics::MemoryDumper.verify_integrity('dumps/target.dump.gz')
puts result[:verified] ? "Integrity OK" : "INTEGRITY FAILURE"
```

## Phase 5: Honeypot

### Deploying Honeypots

```bash
# Deploy all honeypot services
make honeypot-deploy

# Check status
make honeypot-status
```

Three decoy applications are available:

| Honeypot          | Purpose                                     |
| ----------------- | ------------------------------------------- |
| Fake Rails App    | Simulates a vulnerable Rails application    |
| Fake Gem Server   | Mimics a RubyGems repository                |
| Fake CI Runner    | Emulates a CI/CD build runner               |

### Monitoring Captured Activity

Captured interactions are forwarded to the ELK stack for analysis. Use the Kibana dashboard to explore attacker behavior:

1. Navigate to `http://localhost:5601`
2. Open the "Honeypot Activity" dashboard
3. Filter by honeypot type, source IP, or time range

## Phase 6: Dashboard

### Starting the Full Dashboard Stack

```bash
make dashboard-start
```

This starts Elasticsearch, Logstash, Kibana, Grafana, and the web UI.

### Development Mode

```bash
make dashboard-web
```

The React UI is available at `http://localhost:8080` and provides:
- Real-time event stream
- Detection rule management
- ML model performance metrics
- Forensic analysis reports
- Honeypot activity timeline

## Common Workflows

### Full Attack-to-Detection Cycle

```bash
# 1. Start detection engine
make detection-start

# 2. Run attack demo (in separate terminal)
make attack-demo

# 3. View alerts in dashboard
make dashboard-start
# Open http://localhost:5601

# 4. Capture memory for forensics
make forensics-dump

# 5. Analyze the dump
make forensics-analyze
```

### Model Retraining Workflow

```bash
# 1. Collect new samples from honeypot captures
# 2. Extract features
python3 -m 03_ml_classifier.feature_extraction.ast_feature_extractor --input samples/ --output data/processed/

# 3. Retrain
make classifier-train

# 4. Evaluate
make classifier-evaluate

# 5. Deploy updated model
make classifier-api
```

## Safety Controls

RubyGuardian includes multiple safety mechanisms:

- **Sandbox detection:** Attack modules verify they are running in a sandboxed environment before executing.
- **Dry-run mode:** All attack modules support `dry_run: true` to log operations without side effects.
- **User confirmation:** Interactive confirmation prompts before dangerous operations.
- **Environment variable gate:** Set `RUBY_GUARDIAN_AUTO_CONFIRM=true` only in automated CI or lab environments.
- **Network restrictions:** Outbound connections are restricted to localhost and private networks by default.
