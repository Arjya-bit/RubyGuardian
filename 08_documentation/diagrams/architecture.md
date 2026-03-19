# RubyGuardian Architecture

## High-Level System Overview

```
+========================================================================+
|                        RubyGuardian Framework                          |
+========================================================================+
|                                                                        |
|  +-------------------+    +-------------------+    +----------------+  |
|  | 01 Attack         |    | 02 Detection      |    | 03 ML          |  |
|  | Framework         |--->| Engine            |--->| Classifier     |  |
|  |                   |    |                   |    |                |  |
|  | - Process Hollow  |    | - Agent Monitors  |    | - Feature Ext. |  |
|  | - CI/CD Poison    |    | - Rule Engine     |    | - Random Forest|  |
|  | - LoLRuby         |    | - Correlation     |    | - XGBoost      |  |
|  | - ObjectSpace     |    | - Alert Pipeline  |    | - Neural Net   |  |
|  +-------------------+    +--------+----------+    | - Ensemble     |  |
|                                    |               +-------+--------+  |
|                                    |                       |           |
|                                    v                       v           |
|  +-------------------+    +-------------------+    +----------------+  |
|  | 05 Honeypot       |    | 04 Memory         |    | 06 Dashboard   |  |
|  | System            |--->| Forensics         |--->| & Monitoring   |  |
|  |                   |    |                   |    |                |  |
|  | - Fake Rails App  |    | - Memory Dumper   |    | - Elasticsearch|  |
|  | - Fake Gem Server |    | - VM Parser       |    | - Kibana       |  |
|  | - Fake CI Runner  |    | - Heap Analyzer   |    | - Grafana      |  |
|  |                   |    | - IOC Scanner     |    | - React Web UI |  |
|  +-------------------+    +-------------------+    +----------------+  |
|                                                                        |
+========================================================================+
|                     07 Infrastructure (Docker / ELK / Config)          |
+========================================================================+
```

---

## Data Flow Architecture

The following diagram shows how data moves through the system during a
typical attack-detection-response cycle:

```
  Attacker Activity            Detection Layer            Response Layer
  ==================          ================          ================

  +--------------+
  | Attack       |     (1) Syscalls, memory writes, network traffic
  | Execution    |---------------------------------------------------+
  +--------------+                                                    |
                                                                      v
                           +------------------------------------------+
                           |         Detection Agent                  |
                           |                                          |
                           |  +-------------+  +------------------+   |
                           |  | Process     |  | Syscall          |   |
                           |  | Monitor     |  | Tracer (eBPF)    |   |
                           |  +------+------+  +--------+---------+   |
                           |         |                  |             |
                           |  +------+------+  +--------+---------+   |
                           |  | Memory      |  | Network          |   |
                           |  | Inspector   |  | Monitor          |   |
                           |  +------+------+  +--------+---------+   |
                           |         |                  |             |
                           |         v                  v             |
                           |  +-----------------------------------+   |
                           |  |        Event Collector            |   |
                           |  +----------------+------------------+   |
                           +-------------------|----------------------+
                                               |
                          (2) Enriched events   |
                                               v
                           +-------------------+------------------+
                           |            Rule Engine               |
                           |                                      |
                           |  +-----------+   +----------------+  |
                           |  | Rule      |   | Condition      |  |
                           |  | Parser    |   | Evaluator      |  |
                           |  +-----------+   +----------------+  |
                           |  +-----------+   +----------------+  |
                           |  | Rule      |   | Correlation    |  |
                           |  | Compiler  |   | Engine         |  |
                           |  +-----------+   +----------------+  |
                           +----------------+---------------------+
                                            |
                          (3) Alerts        |
                                            v
              +-----------------------------+----------------------------+
              |                             |                            |
              v                             v                            v
   +----------+----------+    +-------------+----------+    +------------+--------+
   | ML Classifier API   |    | Memory Forensics       |    | Dashboard           |
   |                     |    |                        |    |                     |
   | POST /predict       |    | Capture -> Analyze ->  |    | Elasticsearch       |
   |   Feature Extract   |    |   Parse -> Scan IOC -> |    |   -> Logstash       |
   |   Ensemble Predict  |    |   Reconstruct Code ->  |    |   -> Kibana         |
   |   Return Score      |    |   Build Timeline       |    |   -> Grafana        |
   +---------------------+    +------------------------+    +---------------------+
```

---

## Component Architecture Details

### Detection Agent Internal Architecture

```
  ruby_guardian_agent.rb (main daemon)
  |
  +-- process_monitor.rb
  |     Polls /proc for new processes, checks image/memory mismatches
  |
  +-- syscall_tracer.rb
  |     Uses eBPF bridge to trace ptrace, mmap, execve, connect
  |
  +-- memory_inspector.rb
  |     Reads /proc/pid/maps for RWX regions, code injection markers
  |
  +-- network_monitor.rb
  |     Captures packets via PacketFu, detects beaconing and exfil
  |
  +-- file_monitor.rb
  |     Watches filesystem via inotify for suspicious file drops
  |
  +-- objectspace_scanner.rb
  |     Introspects Ruby ObjectSpace for hidden persistent objects
  |
  +-- event_collector.rb
  |     Aggregates and enriches events from all monitors
  |
  +-- heartbeat.rb
        Sends periodic health checks to the dashboard
```

### ML Classifier Pipeline

```
  Ruby Script Input
        |
        v
  +-----+-----------+
  | Feature          |
  | Extraction       |
  |                  |
  | +- static_analyzer.py --------+  Byte-level statistics, entropy
  | +- ast_feature_extractor.py --+  Abstract syntax tree features
  | +- string_pattern_extractor.py+  Regex matches for suspicious strings
  | +- api_call_extractor.py -----+  Dangerous API usage (eval, system)
  | +- import_analyzer.py --------+  Required libraries and gems
  | +- obfuscation_scorer.py -----+  Obfuscation complexity metrics
  +-----+------------+
        |
        v  Feature Vector (N dimensions)
  +-----+------------+
  | StandardScaler   |
  | Normalization    |
  +-----+------------+
        |
        v
  +-----+-------------------------------------------+
  |              Ensemble Classifier                 |
  |                                                  |
  |  +------------------+  +---------------------+  |
  |  | Random Forest    |  | XGBoost             |  |
  |  | (n_estimators=   |  | (gradient boosted   |  |
  |  |  200, balanced)  |  |  trees, early stop) |  |
  |  +--------+---------+  +---------+-----------+  |
  |           |                      |               |
  |  +--------+---------+           |               |
  |  | Neural Network   |           |               |
  |  | (3-layer MLP,    +-----------+               |
  |  |  dropout 0.3)    |                           |
  |  +--------+---------+                           |
  |           |                                      |
  |           v                                      |
  |  +--------+---------+                           |
  |  | Weighted Vote    |                           |
  |  | (optimized on    |                           |
  |  |  validation set) |                           |
  |  +--------+---------+                           |
  +-----------|-------------------------------------+
              |
              v
     Classification Result
     { label: "malicious", confidence: 0.94,
       model_scores: { rf: 0.91, xgb: 0.96, nn: 0.93 } }
```

### Memory Forensics Pipeline

```
  Target Process (PID)
        |
        v
  +-----+------------+
  | MemoryDumper     |  Acquisition via /proc/pid/mem, gcore, or ptrace
  | (chain of        |  SHA-256 + MD5 hashing for integrity
  |  custody)        |  Optional gzip compression
  +-----+------------+
        |
        v  Raw Memory Dump + Metadata JSON
  +-----+------------+
  | DumpParser       |  Reads region headers, builds address map
  +-----+------------+
        |
        v
  +-----+------------+
  | RubyVMParser     |  Identifies RVALUE structs, iseq objects,
  | HeapAnalyzer     |  class hierarchies, reference graphs
  +-----+------------+
        |
        +------+------+------+------+
        |      |      |      |      |
        v      v      v      v      v
  +------+ +------+ +------+ +------+ +------+
  |String| |IOC   | |Code  | |Deobf | |Net   |
  |Extr. | |Scan  | |Recon | |usc.  | |Artif.|
  +--+---+ +--+---+ +--+---+ +--+---+ +--+---+
     |        |        |        |        |
     +--------+--------+--------+--------+
              |
              v
  +-----------+-----------+
  | TimelineBuilder       |  Chronological reconstruction
  +-----------+-----------+
              |
              v
  +-----------+-----------+
  | ReportGenerator       |  Formatted forensic report (JSON, HTML)
  +-----+-----+-----------+
```

---

## Infrastructure and Deployment

### Docker Service Topology

```
  docker-compose.yml
  |
  +-- detection-agent  (Ruby 3.2 + native extensions)
  |     Volumes: /proc (read-only), host network access
  |
  +-- classifier-api   (Python 3.11 + FastAPI)
  |     Port: 8000
  |
  +-- honeypot-rails   (Ruby 3.2 + Sinatra)
  |     Port: 3000
  |
  +-- honeypot-gems    (Ruby 3.2 + Sinatra)
  |     Port: 9292
  |
  +-- honeypot-ci      (Ruby 3.2 + Sinatra)
  |     Port: 8080
  |
  +-- elasticsearch    (v8.x)
  |     Port: 9200
  |     Volume: es-data
  |
  +-- logstash         (v8.x)
  |     Port: 5044
  |     Pipeline: detection events -> enrichment -> elasticsearch
  |
  +-- kibana           (v8.x)
  |     Port: 5601
  |
  +-- grafana          (v10.x)
  |     Port: 3001
  |     Datasources: Elasticsearch, Prometheus
  |
  +-- web-ui           (Node.js 18 + React)
        Port: 4000
```

### Network Isolation

```
  +--------------------------------------------------+
  |  Lab Network (isolated)                          |
  |                                                  |
  |  +------------+         +-------------------+    |
  |  | Attacker   |-------->| Honeypot          |    |
  |  | Container  |  HTTP   | Services          |    |
  |  +------------+         +--------+----------+    |
  |                                  |               |
  |                          Log shipping            |
  |                                  |               |
  |  +------------+         +--------v----------+    |
  |  | Detection  |-------->| ELK Stack         |    |
  |  | Agent      |  Events | (Elasticsearch +  |    |
  |  +------------+         |  Logstash +        |    |
  |       |                 |  Kibana)           |    |
  |       | Alerts          +-------------------+    |
  |       v                                          |
  |  +------------+                                  |
  |  | Classifier |                                  |
  |  | API        |                                  |
  |  +------------+                                  |
  +--------------------------------------------------+
       |  NO external network access
       X  (air-gapped or NAT-only)
```

---

## Technology Stack Summary

| Layer          | Technology                     | Language   |
|----------------|--------------------------------|------------|
| Attack Tools   | FFI, ptrace, process_vm_writev | Ruby       |
| Detection      | eBPF, inotify, PacketFu        | Ruby + C   |
| ML Classifier  | scikit-learn, XGBoost, PyTorch | Python     |
| Forensics      | /proc, gcore, Zlib             | Ruby       |
| Honeypot       | Sinatra, Puma                  | Ruby       |
| Dashboard      | ELK Stack, Grafana, React      | Multi      |
| Infrastructure | Docker Compose                 | YAML       |
| Testing        | RSpec, pytest                  | Ruby + Py  |
| CI/CD          | GitHub Actions                 | YAML       |
