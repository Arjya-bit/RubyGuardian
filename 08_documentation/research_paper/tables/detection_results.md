# Detection Results Tables

## Table 1: Per-Technique Detection Rates by Detection Layer

| Attack Technique              | MITRE ID   | N    | Signature | Behavioral | ML    | Combined | Avg Latency |
|-------------------------------|------------|------|-----------|------------|-------|----------|-------------|
| eval() Chain Exploitation     | T1059.005  | 200  | 95.0%     | 88.0%      | 97.0% | 99.0%    | 28ms        |
| Process Hollowing             | T1055.012  | 200  | 92.0%     | 95.0%      | 96.0% | 99.0%    | 35ms        |
| Shared Library Injection      | T1055.001  | 150  | 90.0%     | 85.0%      | 94.0% | 98.0%    | 42ms        |
| Obfuscated Payload Delivery   | T1027      | 200  | 72.0%     | 80.0%      | 93.0% | 96.0%    | 55ms        |
| DNS Exfiltration              | T1071.004  | 200  | 88.0%     | 92.0%      | 95.0% | 98.0%    | 22ms        |
| HTTP C2 Communication         | T1071.001  | 150  | 85.0%     | 78.0%      | 91.0% | 96.0%    | 38ms        |
| Credential File Access        | T1003      | 150  | 94.0%     | 90.0%      | 92.0% | 99.0%    | 18ms        |
| Privilege Escalation          | T1068      | 100  | 88.0%     | 86.0%      | 89.0% | 97.0%    | 45ms        |
| File System Discovery         | T1083      | 200  | 80.0%     | 75.0%      | 88.0% | 94.0%    | 32ms        |
| Lateral Movement              | T1021      | 100  | 82.0%     | 80.0%      | 86.0% | 95.0%    | 58ms        |
| Data Staging                  | T1074      | 150  | 78.0%     | 82.0%      | 90.0% | 95.0%    | 48ms        |
| Data Destruction              | T1485      | 100  | 92.0%     | 94.0%      | 91.0% | 99.0%    | 15ms        |
| **Weighted Average**          |            |**2000**|**86.3%**| **85.4%**  |**91.8%**|**97.1%**| **36ms**  |

## Table 2: Detection by Severity Level

| Severity  | True Alerts | False Alerts | Missed Attacks | Precision | Recall | F1    |
|-----------|-------------|--------------|----------------|-----------|--------|-------|
| Critical  | 312         | 8            | 6              | 97.5%     | 98.1%  | 97.8% |
| High      | 548         | 22           | 18             | 96.1%     | 96.8%  | 96.5% |
| Medium    | 620         | 45           | 28             | 93.2%     | 95.7%  | 94.4% |
| Low       | 380         | 35           | 20             | 91.6%     | 95.0%  | 93.3% |
| Info      | 82          | 15           | 10             | 84.5%     | 89.1%  | 86.7% |
| **Total** | **1942**    | **125**      | **82**         | **93.9%** |**95.9%**|**94.9%**|

## Table 3: End-to-End Detection Pipeline Latency

| Pipeline Stage        | p50    | p90    | p95    | p99    | Max    |
|-----------------------|--------|--------|--------|--------|--------|
| Event Capture         | 2ms    | 5ms    | 8ms    | 15ms   | 32ms   |
| Signature Matching    | 3ms    | 8ms    | 12ms   | 25ms   | 48ms   |
| Behavioral Analysis   | 5ms    | 12ms   | 18ms   | 35ms   | 62ms   |
| ML Classification     | 4ms    | 10ms   | 15ms   | 28ms   | 45ms   |
| Event Correlation     | 8ms    | 20ms   | 30ms   | 55ms   | 95ms   |
| Alert Generation      | 2ms    | 4ms    | 5ms    | 10ms   | 18ms   |
| **Full Pipeline**     | **32ms**| **85ms**| **120ms**| **250ms**| **380ms** |
| Dashboard Display     | 50ms   | 120ms  | 180ms  | 350ms  | 520ms  |

## Table 4: Correlation Engine Effectiveness

| Attack Pattern              | Events in Chain | Correlation Rate | Severity Escalation | Avg FP Reduction |
|-----------------------------|-----------------|------------------|---------------------|------------------|
| Recon -> Exploit -> Exfil   | 8-15            | 94.2%            | Medium -> Critical  | 62%              |
| eval() -> Injection -> C2   | 5-10            | 96.1%            | High -> Critical    | 55%              |
| Discovery -> Staging -> DNS | 6-12            | 91.8%            | Low -> High         | 71%              |
| Credential -> Lateral -> Impact | 4-8         | 93.5%            | Medium -> Critical  | 58%              |

## Table 5: False Positive Analysis by Source

| False Positive Source              | Count | Percentage | Mitigation Applied           |
|------------------------------------|-------|------------|------------------------------|
| Rails metaprogramming (eval)       | 32    | 25.6%      | Allowlist for Rails methods  |
| Gem installation (file writes)     | 28    | 22.4%      | Process context filtering    |
| Test framework (spawn processes)   | 22    | 17.6%      | Test environment detection   |
| Background job workers (network)   | 18    | 14.4%      | Baseline profile per app     |
| IRB/Pry debugging sessions         | 15    | 12.0%      | Interactive session flag     |
| Other                              | 10    | 8.0%       | Manual review                |
| **Total**                          |**125**| **100%**   |                              |

## Table 6: Detection Rate Over Time (Weekly Aggregation)

| Week | Events Processed | True Positives | False Positives | FPR   | Detection Rate |
|------|------------------|----------------|-----------------|-------|----------------|
| 1    | 35,200           | 1,420          | 52              | 1.5%  | 97.2%          |
| 2    | 38,100           | 1,580          | 48              | 1.3%  | 97.5%          |
| 3    | 42,500           | 1,710          | 65              | 1.5%  | 96.8%          |
| 4    | 36,800           | 1,490          | 58              | 1.6%  | 96.5%          |
| Avg  | 38,150           | 1,550          | 56              | 1.5%  | 97.0%          |

## Table 7: Forensic Evidence Quality

| Evidence Type        | Captures | Successful | Complete Data | Useful IOCs | Avg Capture Time |
|----------------------|----------|------------|---------------|-------------|------------------|
| Process Memory Dump  | 312      | 305 (97.8%)| 298 (95.5%)   | 285 (91.3%) | 1.2s             |
| Network Buffer       | 548      | 540 (98.5%)| 535 (97.6%)   | 510 (93.1%) | 0.3s             |
| File Artifacts       | 245      | 242 (98.8%)| 240 (98.0%)   | 230 (93.9%) | 0.8s             |
| Process Tree State   | 620      | 618 (99.7%)| 615 (99.2%)   | N/A         | 0.1s             |
