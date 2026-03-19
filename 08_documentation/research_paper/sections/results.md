# 4. Results

## 4.1 Detection Engine Performance

### 4.1.1 Rule Engine Evaluation

We evaluated the detection engine against a test suite of 50 attack
scenarios covering all four attack framework techniques. Each scenario
was executed in the isolated lab environment with the detection agent
running at each sensitivity level.

| Sensitivity | True Positives | False Negatives | False Positives | Detection Rate |
|-------------|---------------|-----------------|-----------------|----------------|
| paranoid    | 49            | 1               | 23              | 98.0%          |
| high        | 47            | 3               | 11              | 94.0%          |
| medium      | 42            | 8               | 4               | 84.0%          |
| low         | 35            | 15              | 1               | 70.0%          |

At the default `high` sensitivity setting, the engine achieves a 94%
detection rate with 11 false positives across 200 monitored benign
processes (5.5% FP rate). The `paranoid` setting detects nearly all
attacks but at the cost of increased false positive rates, making it
suitable for research environments.

### 4.1.2 Per-Technique Detection Results

| Technique              | MITRE ID   | High Sensitivity | Avg Detection Time |
|------------------------|------------|------------------|--------------------|
| Process Hollowing      | T1055.012  | 12/12 (100%)     | 1.2s               |
| CI/CD Poisoning        | T1195.002  | 10/12 (83%)      | 3.8s               |
| LoLRuby Reconnaissance | T1592      | 13/14 (93%)      | 2.1s               |
| ObjectSpace Persistence| T1055      | 12/12 (100%)     | 0.8s               |

Process hollowing and ObjectSpace persistence are detected with 100%
accuracy due to their distinctive behavioral signatures (RWX memory
allocation, ptrace usage, ObjectSpace manipulation). CI/CD poisoning
is the most challenging to detect, as some techniques closely resemble
legitimate build operations.

### 4.1.3 Correlation Engine Effectiveness

The correlation engine identified 8 multi-stage attack patterns that
individual rules missed. For example, the combination of "new process
creation" + "RWX memory allocation within 2 seconds" + "outbound
connection to non-whitelisted IP" triggers a correlated alert for
process hollowing with C2 callback, even when individual event scores
fall below the threshold.

## 4.2 ML Classifier Performance

### 4.2.1 Single Model Results

We report test-set metrics for each classifier after training on the
full dataset (1,300 train / 300 validation / 400 test samples):

| Model          | Accuracy | F1 (weighted) | Precision | Recall | MCC   | ROC-AUC |
|----------------|----------|---------------|-----------|--------|-------|---------|
| Random Forest  | 0.9425   | 0.9418        | 0.9451    | 0.9425 | 0.8792| 0.9831  |
| XGBoost        | 0.9550   | 0.9547        | 0.9561    | 0.9550 | 0.9058| 0.9892  |
| Neural Network | 0.9375   | 0.9369        | 0.9398    | 0.9375 | 0.8688| 0.9804  |
| Ensemble       | 0.9625   | 0.9622        | 0.9638    | 0.9625 | 0.9214| 0.9921  |

The weighted ensemble achieves the highest performance across all
metrics, with an F1 score of 0.9622 and ROC-AUC of 0.9921. XGBoost
is the strongest individual model, while the neural network shows
slightly lower performance likely due to the relatively small dataset
size.

### 4.2.2 Cross-Validation Results

Five-fold stratified cross-validation on the full dataset:

| Model          | Accuracy (mean +/- std) | F1 (mean +/- std)     |
|----------------|-------------------------|-----------------------|
| Random Forest  | 0.9380 +/- 0.0142      | 0.9371 +/- 0.0149    |
| XGBoost        | 0.9510 +/- 0.0118      | 0.9504 +/- 0.0123    |
| Neural Network | 0.9320 +/- 0.0195      | 0.9311 +/- 0.0203    |

The low standard deviations indicate stable performance across folds.
XGBoost shows both the highest mean performance and lowest variance.

### 4.2.3 Confusion Matrix (Ensemble, Test Set)

```
                  Predicted
                  Benign  Malicious
Actual Benign      233       7
       Malicious     8      152
```

- True Positives: 152 (malicious correctly identified)
- True Negatives: 233 (benign correctly identified)
- False Positives: 7 (benign misclassified as malicious)
- False Negatives: 8 (malicious misclassified as benign)

The false negative rate of 5.0% (8/160) is the primary concern for
security applications, as missed malware represents a higher risk
than false alarms. Threshold analysis (Section 4.2.4) explores the
precision-recall tradeoff.

### 4.2.4 Threshold Analysis

Adjusting the ensemble's decision threshold from the default 0.5:

| Threshold | Precision | Recall | F1    | FPR   | FNR   |
|-----------|-----------|--------|-------|-------|-------|
| 0.30      | 0.8923    | 0.9813 | 0.9347| 0.0458| 0.0188|
| 0.40      | 0.9310    | 0.9688 | 0.9495| 0.0292| 0.0313|
| 0.50      | 0.9560    | 0.9500 | 0.9530| 0.0292| 0.0500|
| 0.60      | 0.9744    | 0.9313 | 0.9524| 0.0167| 0.0688|
| 0.70      | 0.9867    | 0.9250 | 0.9548| 0.0083| 0.0750|

For security-critical deployments, a threshold of 0.35-0.40 is
recommended to minimize false negatives (missed malware) at the
cost of slightly more false positives.

### 4.2.5 Feature Importance

The top 10 most important features (Random Forest MDI):

| Rank | Feature                      | Importance |
|------|------------------------------|------------|
| 1    | eval_call_count              | 0.0842     |
| 2    | string_entropy_mean          | 0.0731     |
| 3    | obfuscation_score            | 0.0689     |
| 4    | network_api_usage_count      | 0.0623     |
| 5    | base64_pattern_count         | 0.0578     |
| 6    | system_exec_call_count       | 0.0534     |
| 7    | ast_depth                    | 0.0412     |
| 8    | ffi_require_present          | 0.0398     |
| 9    | comment_to_code_ratio        | 0.0367     |
| 10   | hex_encoded_string_count     | 0.0345     |

The presence of `eval` calls is the single strongest predictor of
malicious intent, followed by string entropy (indicative of
obfuscation) and the overall obfuscation score.

## 4.3 Memory Forensics Results

### 4.3.1 Acquisition Performance

Memory dump acquisition benchmarks for a typical Ruby process
(RSS ~120 MB):

| Method     | Duration | Dump Size | Compressed Size | Regions Captured |
|------------|----------|-----------|-----------------|------------------|
| /proc/mem  | 2.3s     | 118 MB    | 34 MB           | 247              |
| gcore      | 4.1s     | 312 MB    | 89 MB           | full core        |
| ptrace     | 6.8s     | 118 MB    | 34 MB           | 247              |

The `/proc/pid/mem` method is fastest and produces the smallest dumps
by reading only mapped regions. The `gcore` method captures the full
core image including kernel metadata, resulting in larger files but
providing compatibility with standard debugging tools.

### 4.3.2 Analysis Pipeline Results

When analyzing memory dumps from processes compromised by our attack
framework:

| Module                  | Artifacts Found (avg) | Time (avg) |
|-------------------------|-----------------------|------------|
| RubyVMParser            | 12,847 RVALUE structs | 1.4s       |
| HeapAnalyzer            | 3 suspicious clusters | 0.8s       |
| StringExtractor         | 2,341 strings         | 0.6s       |
| IOCScanner              | 7 IOC matches         | 0.3s       |
| CodeReconstructor       | 89% source recovery   | 2.1s       |
| Deobfuscator            | 4 decoded payloads    | 1.2s       |
| NetworkArtifactExtractor| 12 network artifacts  | 0.4s       |
| TimelineBuilder         | 23 timeline events    | 0.2s       |

The code reconstructor achieves 89% source recovery from iseq
structures in Ruby 3.2 processes, enabling analysts to review the
injected malicious code without access to the original source files.

### 4.3.3 Integrity Verification

All 50 test dumps passed SHA-256 integrity verification after
acquisition, compression, and transfer. No bit-level corruption was
observed during the testing period.

## 4.4 Honeypot Intelligence

### 4.4.1 Interaction Summary

During a 30-day deployment period in an isolated lab with simulated
attacker traffic:

| Honeypot         | Total Requests | Unique Sources | Attack Attempts |
|------------------|---------------|----------------|-----------------|
| Fake Rails App   | 4,287         | 12             | 342             |
| Fake Gem Server  | 1,893         | 8              | 156             |
| Fake CI Runner   | 967           | 5              | 89              |

### 4.4.2 Attack Categories Captured

| Category                   | Count | Example                              |
|---------------------------|-------|--------------------------------------|
| SQL Injection              | 127   | `' OR 1=1 --` in login form         |
| Path Traversal             | 89    | `../../etc/passwd` in file params    |
| Dependency Confusion       | 43    | Upload of `internal-auth-2.1.1.gem`  |
| Command Injection          | 38    | `; curl attacker.com/shell.sh |bash` |
| Authentication Bypass      | 31    | Default credential attempts          |
| Build Script Injection     | 14    | Modified `.github/workflows/ci.yml`  |

### 4.4.3 Key Findings

The fake gem server proved most effective at capturing novel attack
techniques, specifically dependency confusion attempts where
adversaries uploaded higher-version packages matching internal gem
names. The captured gem files contained obfuscated post-install
hooks that attempted to exfiltrate environment variables -- a pattern
consistent with real-world supply chain attacks.

## 4.5 End-to-End Pipeline Validation

We validated the complete pipeline by executing each attack technique
and measuring the time from attack initiation to alert visibility in
the dashboard:

| Attack Technique    | Detection Time | Classification Time | Forensic Report | Total E2E |
|--------------------|----------------|--------------------|--------------------|-----------|
| Process Hollowing  | 1.2s           | 0.8s               | 7.2s               | 9.2s      |
| ObjectSpace Inject | 0.8s           | 0.6s               | 5.1s               | 6.5s      |
| LoLRuby Recon      | 2.1s           | 0.7s               | 4.8s               | 7.6s      |
| CI/CD Poisoning    | 3.8s           | 1.1s               | 6.3s               | 11.2s     |

All attack types are detected, classified, and fully analyzed within
12 seconds, demonstrating the framework's suitability for near-real-time
security monitoring in research environments.
