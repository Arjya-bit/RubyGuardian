# ML Performance Comparison Tables

## Table 1: Classifier Performance Comparison (5-Fold Cross-Validation)

| Model                | Accuracy | Precision | Recall | F1 Score | AUC-ROC | FPR   | FNR   | Train Time | Inference |
|----------------------|----------|-----------|--------|----------|---------|-------|-------|------------|-----------|
| Random Forest        | 96.8%    | 95.2%     | 97.5%  | 96.3%    | 0.992   | 1.8%  | 2.5%  | 12.4s      | 0.8ms     |
| Gradient Boosted     | 97.1%    | 96.0%     | 96.8%  | 96.4%    | 0.994   | 1.5%  | 3.2%  | 28.6s      | 1.2ms     |
| XGBoost              | 97.0%    | 95.8%     | 97.0%  | 96.4%    | 0.993   | 1.6%  | 3.0%  | 22.1s      | 0.9ms     |
| SVM (RBF Kernel)     | 94.2%    | 93.1%     | 94.8%  | 93.9%    | 0.978   | 3.2%  | 5.2%  | 45.2s      | 2.1ms     |
| SVM (Linear)         | 92.8%    | 91.5%     | 93.2%  | 92.3%    | 0.968   | 4.1%  | 6.8%  | 8.5s       | 0.3ms     |
| Neural Network (MLP) | 95.6%    | 94.8%     | 95.2%  | 95.0%    | 0.986   | 2.4%  | 4.8%  | 85.3s      | 0.5ms     |
| Logistic Regression  | 91.2%    | 90.0%     | 91.8%  | 90.9%    | 0.962   | 4.8%  | 8.2%  | 2.1s       | 0.1ms     |
| K-Nearest Neighbors  | 93.5%    | 92.2%     | 94.0%  | 93.1%    | 0.975   | 3.5%  | 6.0%  | N/A        | 5.8ms     |
| Decision Tree        | 92.1%    | 90.8%     | 92.5%  | 91.6%    | 0.925   | 4.2%  | 7.5%  | 1.8s       | 0.2ms     |
| Naive Bayes          | 88.5%    | 86.2%     | 89.8%  | 88.0%    | 0.940   | 6.5%  | 10.2% | 0.5s       | 0.1ms     |

**Dataset**: 8,000 samples (5,000 benign, 3,000 malicious), 47 features
**Hardware**: AMD Ryzen 9 5900X, 64 GB RAM

## Table 2: Feature Importance Rankings by Model

| Rank | Random Forest                  | Gradient Boosted               | XGBoost                        |
|------|--------------------------------|--------------------------------|--------------------------------|
| 1    | ptrace_syscall_count (0.142)   | ptrace_syscall_count (0.128)   | dns_query_entropy (0.135)      |
| 2    | dns_query_entropy (0.098)      | dns_query_entropy (0.112)      | ptrace_syscall_count (0.121)   |
| 3    | unique_outbound_ips (0.087)    | mmap_exec_calls (0.095)        | unique_outbound_ips (0.098)    |
| 4    | mmap_exec_calls (0.076)        | unique_outbound_ips (0.082)    | mmap_exec_calls (0.085)        |
| 5    | bytes_sent_recv_ratio (0.065)  | child_process_spawns (0.068)   | bytes_sent_recv_ratio (0.072)  |
| 6    | child_process_spawns (0.058)   | bytes_sent_recv_ratio (0.062)  | syscall_seq_entropy (0.065)    |
| 7    | file_write_to_tmp (0.052)      | syscall_seq_entropy (0.055)    | child_process_spawns (0.058)   |
| 8    | syscall_seq_entropy (0.048)    | file_write_to_tmp (0.048)      | file_write_to_tmp (0.052)     |
| 9    | mem_alloc_growth_rate (0.041)  | connect_nonstandard (0.042)    | connect_nonstandard (0.045)    |
| 10   | connect_nonstandard (0.038)    | mem_alloc_growth_rate (0.038)  | mem_alloc_growth_rate (0.040)  |

## Table 3: Feature Category Contribution Analysis

| Feature Category      | Count | RF Importance | GB Importance | XGB Importance | Avg Contribution |
|-----------------------|-------|---------------|---------------|----------------|------------------|
| Syscall Frequency     | 12    | 38.2%         | 35.8%         | 36.5%          | 36.8%            |
| Network Behavior      | 15    | 32.5%         | 34.2%         | 35.1%          | 33.9%            |
| Process Metadata      | 12    | 18.8%         | 19.5%         | 18.2%          | 18.8%            |
| Temporal Patterns     | 8     | 10.5%         | 10.5%         | 10.2%          | 10.4%            |

## Table 4: Hyperparameter Sensitivity (Random Forest)

| Parameter          | Value Tested       | Accuracy | F1 Score | FPR   | Selected |
|--------------------|--------------------|----------|----------|-------|----------|
| n_estimators       | 50                 | 95.2%    | 94.8%    | 2.5%  |          |
|                    | 100                | 96.1%    | 95.6%    | 2.0%  |          |
|                    | **200**            | **96.8%**| **96.3%**| **1.8%** | **Yes** |
|                    | 500                | 96.9%    | 96.4%    | 1.7%  |          |
| max_depth          | 10                 | 95.5%    | 95.0%    | 2.2%  |          |
|                    | **20**             | **96.8%**| **96.3%**| **1.8%** | **Yes** |
|                    | 30                 | 96.5%    | 96.0%    | 2.0%  |          |
|                    | None               | 96.2%    | 95.7%    | 2.1%  |          |
| min_samples_leaf   | 1                  | 96.4%    | 95.9%    | 2.1%  |          |
|                    | **5**              | **96.8%**| **96.3%**| **1.8%** | **Yes** |
|                    | 10                 | 96.0%    | 95.5%    | 1.9%  |          |
|                    | 20                 | 95.2%    | 94.7%    | 1.8%  |          |
| class_weight       | None               | 95.8%    | 94.2%    | 1.2%  |          |
|                    | **balanced**       | **96.8%**| **96.3%**| **1.8%** | **Yes** |

## Table 5: Adversarial Robustness Results

| Attack Method                    | Evasion Rate | Detection Degradation | Functionality Preserved |
|----------------------------------|--------------|----------------------|-------------------------|
| No attack (baseline)             | 0.0%         | 0.0%                 | N/A                     |
| Random feature noise (sigma=0.1) | 1.2%         | -0.8%                | Yes                     |
| Random feature noise (sigma=0.5) | 3.2%         | -2.1%                | Yes                     |
| Random feature noise (sigma=1.0) | 8.5%         | -5.8%                | Partial                 |
| Gradient-based (FGSM)           | 12.8%        | -8.5%                | Partial                 |
| Gradient-based (PGD, 10 steps)  | 15.2%        | -10.1%               | Partial                 |
| Mimicry (benign syscall inject) | 18.5%        | -12.2%               | Yes                     |
| Functionality-preserving        | 8.2%         | -5.5%                | Yes                     |
| Combined (gradient + mimicry)   | 22.1%        | -14.8%               | Partial                 |

## Table 6: Concept Drift Detection and Adaptation

| Time Period | No Retrain Acc | Weekly Retrain Acc | Drift Score | Retrain Triggered | New Samples Added |
|-------------|----------------|--------------------|-------------|-------------------|-------------------|
| Week 0      | 96.8%          | 96.8%              | 0.00        | No                | 0                 |
| Week 1      | 95.5%          | 96.8%              | 0.12        | No                | 0                 |
| Week 2      | 94.1%          | 96.5%              | 0.28        | Yes               | 150               |
| Week 3      | 91.3%          | 96.2%              | 0.45        | Yes               | 200               |
| Week 4      | 87.6%          | 95.9%              | 0.62        | Yes               | 250               |
| Week 5      | 84.2%          | 96.1%              | 0.78        | Yes               | 180               |
| Week 6      | 81.5%          | 95.8%              | 0.85        | Yes               | 220               |

**Drift Detection Method**: Page-Hinkley test with delta=0.005, lambda=50

## Table 7: Cross-Dataset Generalization

| Training Set          | Test Set               | Accuracy | Precision | Recall | F1    |
|-----------------------|------------------------|----------|-----------|--------|-------|
| Lab-generated only    | Lab-generated          | 96.8%    | 95.2%     | 97.5%  | 96.3% |
| Lab-generated only    | Honeypot captures      | 88.5%    | 85.2%     | 90.1%  | 87.6% |
| Lab + Honeypot        | Lab-generated          | 96.2%    | 95.0%     | 96.8%  | 95.9% |
| Lab + Honeypot        | Honeypot captures      | 94.1%    | 92.8%     | 94.5%  | 93.6% |
| Lab + Honeypot        | Mixed (50/50)          | 95.2%    | 93.9%     | 95.7%  | 94.8% |

## Table 8: Per-Class Performance (Random Forest)

| Class              | Support | Precision | Recall | F1 Score | Avg Confidence |
|--------------------|---------|-----------|--------|----------|----------------|
| Benign             | 5,000   | 98.2%     | 96.4%  | 97.3%    | 0.94           |
| Malicious (all)    | 3,000   | 95.2%     | 97.5%  | 96.3%    | 0.91           |
| - Process Injection| 600     | 96.8%     | 98.2%  | 97.5%    | 0.95           |
| - Code Execution   | 600     | 95.5%     | 97.8%  | 96.6%    | 0.92           |
| - Exfiltration     | 500     | 94.2%     | 96.5%  | 95.3%    | 0.89           |
| - C2 Communication | 450     | 93.8%     | 97.0%  | 95.4%    | 0.88           |
| - Discovery/Recon  | 500     | 94.0%     | 96.2%  | 95.1%    | 0.87           |
| - Other Malicious  | 350     | 96.1%     | 98.5%  | 97.3%    | 0.93           |
