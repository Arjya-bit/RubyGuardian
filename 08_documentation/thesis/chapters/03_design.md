# Chapter 3: System Design

## 3.1 Design Goals

RubyGuardian's architecture is guided by five primary design goals:

1. **Ruby-Specific Detection**: Detection rules and features must understand Ruby runtime behavior patterns, not merely generic process activity.
2. **Multi-Layer Defense**: No single detection technique is sufficient; the system must combine signatures, heuristics, and machine learning.
3. **Real-Time Operation**: Detection latency must be sub-second to enable automated response before attack completion.
4. **Evidence Preservation**: Forensic evidence must be captured automatically at the point of detection.
5. **Operational Usability**: The system must present actionable information through intuitive visualizations.

## 3.2 Architecture Overview

RubyGuardian consists of six major subsystems connected through an event-driven pipeline:

```
+-------------------+     +-------------------+     +-------------------+
|  Attack Framework |     |  Honeypot System  |     |  Target Ruby App  |
|  (Red Team Tool)  |     |  (Threat Intel)   |     |  (Monitored)      |
+--------+----------+     +--------+----------+     +--------+----------+
         |                         |                          |
         v                         v                          v
+--------+-------------------------+----------+---------------+---------+
|                        Detection Engine                               |
|  +----------------+  +------------------+  +-------------------------+|
|  | Signature Rules|  |Behavioral Heuris.|  | Event Correlation Engine||
|  +-------+--------+  +--------+---------+  +------------+------------+|
|          |                     |                         |             |
+----------+---------------------+-------------------------+------------+
           |                     |                         |
           v                     v                         v
+----------+---------------------+-------------------------+------------+
|                        ML Classifier                                  |
|  +----------------+  +------------------+  +------------------------+|
|  |Feature Extract.|  | Random Forest    |  | Threat Score Compute   ||
|  +----------------+  +------------------+  +------------------------+|
+---------------------------+-------------------------------------------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
+-------------+----------+  +-------------+------------+
| Memory Forensics       |  |     ELK Stack            |
| +--------------------+ |  | +----------------------+ |
| | Memory Dumper      | |  | | Elasticsearch        | |
| | Entropy Analyzer   | |  | | Logstash Pipelines   | |
| | IOC Extractor      | |  | | Kibana Dashboards    | |
| +--------------------+ |  | +----------------------+ |
+------------------------+  +------+-------------------+
                                    |
                           +--------v--------+
                           |   Web Dashboard |
                           |  (React + Vite) |
                           +-----------------+
```

## 3.3 Event Data Model

All events flowing through RubyGuardian conform to a unified event schema:

```json
{
  "@timestamp": "ISO 8601 timestamp",
  "event": {
    "type": "process_spawn | network_connect | file_write | ...",
    "severity": "critical | high | medium | low | info",
    "category": "process | network | file | memory",
    "kind": "event | alert | enrichment"
  },
  "process": {
    "name": "ruby",
    "pid": 12345,
    "parent": { "pid": 1234, "name": "bash" },
    "command_line": "ruby app.rb",
    "executable": "/usr/bin/ruby"
  },
  "source": { "ip": "...", "port": 0 },
  "destination": { "ip": "...", "port": 0 },
  "rule": { "name": "...", "id": "..." },
  "mitre": { "technique_id": "T1055.012", "tactic": "defense_evasion" },
  "threat": { "score": 0.0 }
}
```

This schema is modeled after the Elastic Common Schema (ECS) to ensure compatibility with the ELK stack and enable straightforward integration with existing SIEM infrastructure.

## 3.4 Detection Engine Design

### 3.4.1 Signature Rule Engine

Signature rules are defined in YAML format, providing declarative pattern matching against event fields:

```yaml
- id: RG-001
  name: "Ruby eval() with network-sourced input"
  severity: high
  mitre:
    technique: T1059.005
    tactic: execution
  conditions:
    event_type: code_execution
    process_name: ruby
    patterns:
      - field: command_line
        regex: "eval.*Net::HTTP|eval.*open-uri|eval.*socket"
  actions:
    - alert
    - trigger_forensics
```

The rule engine evaluates events against all loaded rules using a trie-based index on the `event_type` field to limit the search space. This design achieves O(k) evaluation complexity where k is the number of rules matching the event type, rather than O(n) across all rules.

### 3.4.2 Behavioral Heuristics

Behavioral heuristics maintain statistical models of normal Ruby process behavior and flag deviations:

1. **Syscall Frequency Anomaly**: Maintains a rolling window of syscall counts per process. Triggers when the current window's distribution diverges significantly from the baseline (KL divergence > threshold).

2. **Network Behavior Anomaly**: Flags Ruby processes making unexpected outbound connections, particularly to non-standard ports or high-entropy domains indicative of DGA activity.

3. **File Access Anomaly**: Detects Ruby processes reading sensitive files (/etc/shadow, SSH keys, browser credential stores) outside of expected application file access patterns.

### 3.4.3 Event Correlation Engine

The correlation engine links temporally and causally related events into coherent attack narratives:

- **Time Window**: Configurable window (default: 300 seconds) within which events from the same process tree are considered potentially correlated.
- **Process Tree Tracking**: Events are grouped by process group ID, linking parent-child process relationships.
- **Attack Chain Detection**: Predefined attack chain patterns (e.g., "reconnaissance followed by exploitation followed by exfiltration") are matched against correlated event sequences.
- **Escalation Logic**: Correlated events trigger severity escalation; a sequence of individually medium-severity events may produce a high or critical aggregate alert.

## 3.5 ML Classifier Design

### 3.5.1 Feature Engineering

Features are extracted from three data sources:

**Syscall Features (20 features)**:
- Frequency of key syscalls (read, write, open, connect, mmap, ptrace, execve)
- Syscall sequence n-gram entropy
- Ratio of network to filesystem syscalls
- Unique file descriptors accessed
- Standard deviation of inter-syscall timing

**Network Features (15 features)**:
- Outbound connection count and unique destination IPs
- DNS query frequency and query name entropy
- Bytes sent/received ratio
- Connection duration statistics
- Protocol distribution (TCP, UDP, DNS)

**Process Features (12 features)**:
- Child process spawn count
- Memory allocation growth rate
- CPU time in user vs. kernel mode
- Thread creation rate
- Shared library loading events

### 3.5.2 Model Selection

Random Forest was selected as the primary classifier based on:

1. **Interpretability**: Feature importance scores enable security analysts to understand detection rationale.
2. **Robustness**: Ensemble methods resist overfitting and are less susceptible to adversarial feature perturbation than single decision boundaries.
3. **Performance**: Random Forest provides consistent sub-millisecond inference time suitable for real-time classification.
4. **Training Efficiency**: The model can be retrained incrementally as new labeled data becomes available.

### 3.5.3 Threat Score Computation

The classifier's output probability is combined with rule-based severity to produce a unified threat score:

```
threat_score = alpha * ml_confidence + (1 - alpha) * rule_severity_normalized
```

Where alpha is a configurable weighting factor (default: 0.6) that balances ML confidence against rule-based severity.

## 3.6 Memory Forensics Design

The forensic subsystem operates in a triggered mode: critical-severity alerts automatically initiate memory capture and analysis.

### 3.6.1 Capture Pipeline

1. **Trigger**: Detection engine emits a forensic capture request with target PID
2. **Memory Map Enumeration**: Parse /proc/[pid]/maps to enumerate memory regions
3. **Selective Dump**: Dump regions based on permissions and type (prioritize executable and heap regions)
4. **Analysis**: Run entropy analysis, string extraction, and pattern matching in parallel
5. **IOC Extraction**: Identify IPs, domains, URLs, hashes, and other indicators
6. **Report Generation**: Produce structured forensic report with findings and evidence references

### 3.6.2 Evidence Integrity

All captured memory dumps are hashed (SHA-256) at the time of capture to establish chain-of-custody integrity. Metadata including capture timestamp, process state, and triggering alert are recorded in the forensic report.

## 3.7 Dashboard Design

The web dashboard provides real-time visualization through:

- **WebSocket Streaming**: Live event and alert updates without polling
- **Component Architecture**: Modular React components for reusable visualization elements
- **Responsive Layout**: Adaptive grid layout supporting desktop and tablet displays
- **MITRE ATT&CK Integration**: Visual mapping of detections to ATT&CK techniques and tactics

## 3.8 Deployment Architecture

RubyGuardian is containerized using Docker Compose with the following service topology:

| Service            | Container     | Ports       | Dependencies              |
|--------------------|---------------|-------------|---------------------------|
| Elasticsearch      | elasticsearch | 9200, 9300  | None                      |
| Logstash           | logstash      | 5044-5046   | Elasticsearch              |
| Kibana             | kibana        | 5601        | Elasticsearch              |
| Grafana            | grafana       | 3000        | Elasticsearch              |
| Detection Engine   | detection     | 8081        | Logstash                   |
| ML Classifier      | classifier    | 8082        | Detection Engine           |
| Memory Forensics   | forensics     | 8083        | Detection Engine           |
| Honeypot           | honeypot      | 2222, 8888  | Logstash                   |
| Web Dashboard      | web_ui        | 8080        | Elasticsearch, Classifier  |

## 3.9 Summary

This chapter presented the architecture of RubyGuardian, a multi-layered security monitoring system for Ruby runtimes. The design combines signature-based detection, behavioral heuristics, ML classification, automated forensics, and real-time visualization in an event-driven pipeline. The following chapter details the implementation of each subsystem.
