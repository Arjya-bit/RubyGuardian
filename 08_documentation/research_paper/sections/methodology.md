# 3. Methodology

## 3.1 Framework Architecture

RubyGuardian follows a modular, pipeline-oriented architecture where each
phase produces artifacts consumed by downstream phases. The framework is
implemented primarily in Ruby (attack framework, detection engine,
forensics, honeypot) with Python used for machine learning components.
Docker Compose orchestrates all services in an isolated lab environment.

The architecture comprises six phases:

1. **Attack Framework** generates malicious behaviors and labeled samples.
2. **Detection Engine** monitors processes and produces security events.
3. **ML Classifier** classifies Ruby scripts using static features.
4. **Memory Forensics** captures and analyzes process memory.
5. **Honeypot System** attracts and records attacker activity.
6. **Dashboard** aggregates data for visualization and incident response.

## 3.2 Attack Framework Design

### 3.2.1 Process Hollowing Implementation

We implement process hollowing (MITRE ATT&CK T1055.012) for Linux using
Ruby's FFI gem to invoke native system calls. The technique proceeds as
follows:

1. **Target creation.** Fork a child process and immediately stop it
   with `SIGSTOP`, preventing execution of the original binary.

2. **Process attachment.** Attach to the stopped child via
   `ptrace(PTRACE_ATTACH)` to gain memory read/write access.

3. **Memory analysis.** Parse `/proc/<pid>/maps` to identify the
   target's executable memory regions, base address, and loaded
   libraries.

4. **Image hollowing.** Unmap the original executable image from the
   target's address space using a ptrace-injected `munmap` syscall.

5. **Payload injection.** Allocate new memory in the target with
   `RWX` permissions via ptrace-injected `mmap`, then write the
   payload using `process_vm_writev`.

6. **Thread hijacking.** Modify the target's instruction pointer
   (`RIP` register) via `PTRACE_SETREGS` to redirect execution to
   the injected payload.

7. **Resumption.** Detach from the target with `PTRACE_DETACH`,
   allowing it to resume execution with the injected code.

Safety controls include mandatory sandbox detection, user confirmation
prompts, dry-run mode, and automatic cleanup of spawned processes and
allocated memory regions on failure.

### 3.2.2 Additional Techniques

- **CI/CD Poisoning (T1195.002):** Demonstrates dependency confusion,
  build script injection, and artifact tampering in pipeline environments.
- **LoLRuby:** Catalogs living-off-the-land techniques that abuse Ruby
  standard library features (Net::HTTP for C2, OpenSSL for encryption,
  Fiddle for FFI, etc.).
- **ObjectSpace Persistence:** Injects persistent objects into Ruby's
  heap that survive garbage collection and can reconstitute malicious
  behavior after trigger conditions are met.

## 3.3 Detection Engine Design

### 3.3.1 Agent Architecture

The detection agent runs as a daemon process with six concurrent monitors:

| Monitor              | Data Source                   | Technique                       |
|----------------------|-------------------------------|---------------------------------|
| ProcessMonitor       | `/proc` filesystem polling    | Process creation, image mismatch|
| SyscallTracer        | eBPF programs via C bridge    | Dangerous syscall sequences     |
| MemoryInspector      | `/proc/<pid>/maps`            | RWX region detection            |
| NetworkMonitor       | PacketFu raw capture          | C2 beaconing, DNS tunneling     |
| FileMonitor          | inotify watch descriptors     | Suspicious file creation        |
| ObjectSpaceScanner   | Ruby VM `ObjectSpace.each_object` | Hidden object detection     |

Each monitor emits structured events to the `EventCollector`, which
enriches them with hostname, agent version, and timestamp metadata.

### 3.3.2 Rule Engine

Enriched events are evaluated by the `RuleEngine::Engine` against
YAML-defined detection rules. The engine supports:

- **Threshold-based rules:** Fire when a numeric indicator exceeds a
  configured score threshold. Sensitivity levels (`low`, `medium`,
  `high`, `paranoid`) map to score thresholds (80, 60, 40, 20).

- **Condition evaluation:** Complex boolean expressions over event
  fields (`AND`, `OR`, `NOT`) with support for regex matching,
  numeric comparison, and set membership.

- **Correlation rules:** Cross-monitor patterns that require multiple
  events within a time window (e.g., "process creation followed by
  RWX memory allocation within 5 seconds").

- **False positive suppression:** Whitelisted tools, alert cooldown
  periods, and deduplication windows reduce noise.

The rule compiler pre-processes rules into optimized matching structures,
and the condition evaluator returns a numeric confidence score for each
event-rule pair.

### 3.3.3 Alert Generation

When a rule matches with a score at or above the sensitivity threshold,
the engine constructs an alert containing:

- Unique alert ID, rule ID, rule name, and description
- Severity (info, low, medium, high, critical) with automatic
  escalation for very high confidence scores (>= 90)
- MITRE ATT&CK technique mapping
- The triggering event with full context
- Metadata including sensitivity level and active rule count

Alerts are forwarded to Elasticsearch via Logstash for storage and
visualization.

## 3.4 ML Classifier Design

### 3.4.1 Feature Extraction

We extract six categories of static features from Ruby source files:

1. **Byte-level statistics:** File size, entropy, byte frequency
   distribution, printable character ratio.

2. **AST features:** Node type counts (method calls, assignments,
   conditionals), tree depth, number of `eval`/`send` invocations,
   metaprogramming construct density.

3. **String patterns:** Presence of IP addresses, URLs, Base64-encoded
   blobs, hex-encoded data, shell command strings, and known malware
   signatures via regex matching.

4. **API call analysis:** Counts of dangerous method calls (`eval`,
   `exec`, `system`, `IO.popen`, `Kernel.open`, `ObjectSpace`),
   network API usage, and file system operations.

5. **Import analysis:** Required gems and standard libraries, presence
   of FFI, Socket, OpenSSL, or other security-relevant imports.

6. **Obfuscation scoring:** Variable name entropy, average identifier
   length, comment-to-code ratio, string literal obfuscation patterns,
   encoding chain complexity.

The extracted feature vector contains approximately 150 dimensions per
script.

### 3.4.2 Model Architecture

We train three base classifiers and one ensemble:

- **Random Forest:** 200 estimators with balanced class weights,
  max depth 30, minimum samples split 5. Provides interpretable
  feature importance rankings.

- **XGBoost:** Gradient-boosted trees with early stopping on
  validation loss, learning rate 0.1, max depth 8, L2 regularization.

- **Neural Network:** Three-layer MLP (256-128-64 units) with ReLU
  activations, dropout 0.3, trained with Adam optimizer and binary
  cross-entropy loss for 100 epochs with early stopping.

- **Ensemble:** Weighted soft-voting combination of all three models.
  Weights are optimized on the validation set by grid search over
  the weight simplex.

### 3.4.3 Training Protocol

Data is split into train (65%), validation (15%), and test (20%) sets
using stratified sampling to preserve class balance. Features are
normalized with `StandardScaler` fitted on training data only.
Five-fold stratified cross-validation is used for hyperparameter
selection and variance estimation.

## 3.5 Memory Forensics Design

### 3.5.1 Acquisition

The `MemoryDumper` supports three acquisition methods:

- **`/proc/pid/mem`:** Direct memory reading via the proc filesystem.
  Most efficient but requires read permissions.
- **`gcore`:** GDB-based core dump generation. Produces ELF core files.
- **`ptrace`:** Attach to the target process, read memory while
  suspended, then detach. Most universal but slowest.

All acquisitions:
- Pause the target process during capture (`SIGSTOP` / `SIGCONT`)
- Compute SHA-256 and MD5 hashes for chain-of-custody integrity
- Record metadata (PID, timestamp, method, regions, Ruby version)
- Support optional gzip compression

### 3.5.2 Analysis Pipeline

The analysis pipeline processes captured dumps through nine sequential
modules:

1. `DumpParser` reads the binary dump format and region headers.
2. `RubyVMParser` identifies Ruby VM structures (RVALUE, T_DATA, iseq).
3. `HeapAnalyzer` reconstructs the object graph and allocation patterns.
4. `StringExtractor` extracts readable strings with surrounding context.
5. `IOCScanner` matches against IOC rule sets (IPs, domains, hashes).
6. `CodeReconstructor` rebuilds Ruby source from instruction sequences.
7. `Deobfuscator` applies entropy analysis and decoding heuristics.
8. `NetworkArtifactExtractor` identifies URLs, IP addresses, and DNS data.
9. `TimelineBuilder` constructs a chronological event timeline.

The `ReportGenerator` produces a structured JSON report consolidating
findings from all modules.

## 3.6 Honeypot Design

Three decoy applications emulate common Ruby infrastructure targets:

- **Fake Rails App:** A Sinatra application mimicking a vulnerable
  Rails admin panel with deliberate SQL injection and authentication
  bypass surfaces. Logs all request parameters, headers, and payloads.

- **Fake Gem Server:** Emulates an internal RubyGems repository with
  fabricated private gems (internal-auth, company-utils, deploy-tools).
  Detects dependency confusion attacks and captures uploaded gem files.

- **Fake CI Runner:** Mimics a CI/CD build agent that accepts and logs
  pipeline definitions, capturing build script injection attempts.

All honeypots ship interaction logs to Elasticsearch for analysis.

## 3.7 Experimental Setup

### 3.7.1 Dataset

We construct a labeled dataset of 2,000 Ruby scripts:
- **1,200 benign scripts** sourced from popular open-source gems,
  Rails applications, and standard library usage examples.
- **800 malicious scripts** including shellcode loaders, reverse
  shells, cryptominers, information stealers, and obfuscated
  variants generated by our attack framework.

### 3.7.2 Evaluation Metrics

We report the following metrics:
- **Accuracy, Precision, Recall, F1-score** (weighted and macro)
- **Matthews Correlation Coefficient (MCC)**
- **ROC-AUC** and **PR-AUC** curves
- **Confusion matrices** with TP, TN, FP, FN counts
- **Threshold analysis** for optimal operating points

### 3.7.3 Environment

All experiments are conducted in Docker containers on a machine with:
- Ubuntu 24.04 LTS, Linux kernel 6.8
- 16 CPU cores (AMD Ryzen 9), 64 GB RAM
- Ruby 3.2.2, Python 3.11.7
- scikit-learn 1.4.0, XGBoost 2.0.3, PyTorch 2.1.2
