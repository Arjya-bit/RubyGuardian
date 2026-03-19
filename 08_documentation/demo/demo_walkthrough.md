# RubyGuardian Demo Walkthrough

## Overview

This guide walks through a complete demonstration of RubyGuardian's capabilities, from launching the environment through detecting and analyzing a simulated Ruby-based attack. Estimated time: 30-45 minutes.

## Prerequisites

- Docker and Docker Compose installed
- At least 8 GB RAM available for containers
- Ports 3000, 5601, 9200, and 8080 available
- Clone of the RubyGuardian repository

## Part 1: Environment Setup (5 minutes)

### Step 1.1 - Launch Infrastructure

```bash
cd /path/to/RubyGuardian
docker-compose up -d
```

Wait for all services to become healthy:

```bash
docker-compose ps
# Verify: elasticsearch, logstash, kibana, grafana, web_ui, detection_engine, honeypot
```

### Step 1.2 - Verify Services

| Service           | URL                        | Expected Response          |
|-------------------|----------------------------|----------------------------|
| Elasticsearch     | http://localhost:9200      | Cluster health JSON        |
| Kibana            | http://localhost:5601      | Kibana login page          |
| Grafana           | http://localhost:3000      | Grafana dashboard          |
| RubyGuardian UI   | http://localhost:8080      | Dashboard landing page     |

### Step 1.3 - Load Sample Data

```bash
make demo-seed
# This loads sample events, forensic reports, and honeypot captures
```

## Part 2: Dashboard Overview (5 minutes)

### Step 2.1 - Navigate to the Dashboard

Open http://localhost:8080 in your browser. The main dashboard shows:

- **Metric Cards**: Total events, active alerts, critical findings, ML classification rate
- **Threat Timeline**: Real-time event timeline with severity coloring
- **Alert Table**: Sortable list of security alerts with MITRE ATT&CK mappings
- **Threat Map**: Geographic visualization of threat sources

### Step 2.2 - Explore Alert Details

1. Click on any critical-severity alert in the Alert Table
2. Review the alert details panel showing process info, network connections, and matched rules
3. Note the MITRE ATT&CK technique mapping (e.g., T1055.012 for Process Hollowing)

## Part 3: Simulated Attack Demonstration (10 minutes)

### Step 3.1 - Launch the Target Application

In a new terminal, start the benign Ruby web server:

```bash
docker exec -it ruby_target ruby /app/fixtures/benign/web_server.rb
```

### Step 3.2 - Execute the Attack Sequence

Open another terminal for the attack framework:

```bash
# Stage 1: Reconnaissance
docker exec -it ruby_attacker ruby /app/01_attack_framework/attacks/recon_scan.rb --target ruby_target

# Stage 2: Initial Access via eval() chain
docker exec -it ruby_attacker ruby /app/01_attack_framework/attacks/eval_payload.rb --target ruby_target

# Stage 3: Process Hollowing
docker exec -it ruby_attacker ruby /app/01_attack_framework/attacks/process_hollower.rb --target ruby_target --pid auto

# Stage 4: Data Exfiltration via DNS
docker exec -it ruby_attacker ruby /app/01_attack_framework/attacks/dns_exfil.rb --target ruby_target --data /etc/passwd
```

### Step 3.3 - Observe Real-Time Detection

Return to the dashboard at http://localhost:8080 and observe:

1. **Event Timeline** populates with new events in real time
2. **Alert severity** escalates from `info` to `critical` as the attack progresses
3. **Threat score** increases with each correlated event
4. **MITRE mapping** shows technique chain: T1595 -> T1059.005 -> T1055.012 -> T1071.004

## Part 4: ML Classifier Analysis (5 minutes)

### Step 4.1 - View Classification Results

Navigate to the **Classifier** page in the dashboard sidebar:

1. Review the feature importance chart - syscall frequency and network entropy are top features
2. Check the classification confidence scores for recent events
3. Note how the model distinguishes between benign Ruby operations and malicious patterns

### Step 4.2 - Examine Feature Contributions

Click on any classified event to see:

- Individual feature values compared to population statistics
- SHAP-style contribution breakdown per feature
- Comparison between the event's profile and known-benign baseline

## Part 5: Forensic Investigation (10 minutes)

### Step 5.1 - Access Forensic Reports

Navigate to the **Forensics** page:

1. Select the most recent forensic report (triggered by the process hollowing attack)
2. Review the report summary including severity, affected process, and timeline

### Step 5.2 - Memory Dump Analysis

Switch to the **Memory Dumps** tab:

1. Browse the hex viewer - note the injected shellcode pattern (NOP sled: 0x90 bytes)
2. Switch to **Strings** view to see extracted ASCII strings including C2 URLs
3. Check **Regions** view for executable memory regions with high entropy (>7.0)

### Step 5.3 - IOC Extraction

Switch to the **IOCs** tab:

1. Review automatically extracted indicators: IP addresses, domains, file hashes
2. Filter by IOC type to focus on network indicators
3. Export IOCs to CSV for threat intelligence sharing

## Part 6: Honeypot Intelligence (5 minutes)

### Step 6.1 - Review Captured Interactions

Navigate to Kibana at http://localhost:5601 and open the **Honeypot Intel** dashboard:

1. View attacker interaction patterns
2. Examine captured payloads and commands
3. Review geolocation of connection sources

## Part 7: Cleanup

```bash
docker-compose down -v
```

## Troubleshooting

| Issue                               | Solution                                          |
|-------------------------------------|---------------------------------------------------|
| Elasticsearch not starting          | Increase Docker memory limit to 8GB+              |
| No events appearing in dashboard    | Check Logstash logs: `docker logs logstash`       |
| ML classifier returning errors      | Ensure model is trained: `make train-classifier`  |
| WebSocket disconnections            | Check browser console; verify proxy configuration |

## Demo Talking Points

- RubyGuardian provides defense-in-depth specifically for Ruby runtime environments
- The ML classifier achieves >95% detection rate with <2% false positive rate
- Real-time correlation links individual events into full attack narratives
- Memory forensics captures evidence for post-incident analysis
- MITRE ATT&CK mapping enables standardized threat communication
