# Chapter 2: Background and Related Work

## 2.1 Ruby Language Security

### 2.1.1 Ruby's Dynamic Features as Attack Surface

Ruby is a dynamically typed, interpreted language with extensive metaprogramming capabilities. Several core language features present security implications when exposed to attacker-controlled input:

- **eval() family**: `eval`, `instance_eval`, `class_eval`, and `module_eval` execute arbitrary strings as Ruby code. Remote code execution (RCE) vulnerabilities frequently exploit these methods when user input reaches an eval boundary without sanitization.

- **Open Classes**: Ruby allows modification of any class at runtime, including core classes such as `String`, `Integer`, and `IO`. An attacker with code execution can redefine fundamental methods to intercept sensitive data.

- **method_missing**: This callback is invoked when an undefined method is called on an object. Malicious redefinition can create invisible proxy layers that capture method arguments.

- **ObjectSpace**: The `ObjectSpace` module provides enumeration of all live objects in the Ruby heap, enabling an attacker to search for credentials, tokens, and encryption keys in memory.

- **Binding**: Ruby's `Binding` objects capture the execution context (local variables, self, block) at a specific point, which can be exploited to access otherwise-private state.

### 2.1.2 Supply Chain Threats in RubyGems

The RubyGems ecosystem has experienced multiple high-profile supply chain attacks:

- **rest-client (2019)**: A compromised maintainer account was used to publish a malicious version that exfiltrated environment variables to an attacker-controlled server.
- **strong_password (2019)**: A malicious update added a backdoor that downloaded and executed remote code.
- **Typosquatting campaigns**: Researchers have identified hundreds of malicious gems with names similar to popular packages (e.g., `atlas-client` vs `atlas_client`).

### 2.1.3 Ruby Process Internals

CRuby (MRI) uses a Global VM Lock (GVL) that serializes Ruby thread execution on a single native thread. This architectural detail has security implications: monitoring a Ruby process's syscall behavior reveals the interleaving of Ruby-level operations with native extensions that release the GVL. Understanding this behavior pattern is essential for distinguishing benign from malicious activity.

## 2.2 Runtime Security Monitoring

### 2.2.1 System Call Monitoring

System call interception is the foundational technique for runtime security monitoring on Linux. Three primary mechanisms exist:

1. **ptrace**: The POSIX process trace API allows a tracer process to intercept and inspect syscalls of a tracee. While flexible, ptrace imposes significant overhead (2-5x slowdown) and is limited to tracing a single process per tracer.

2. **seccomp-BPF**: The Secure Computing Berkeley Packet Filter mechanism allows userspace processes to install syscall filters in kernel space. Filters execute with near-zero overhead but are limited to allow/deny decisions with restricted inspection capability.

3. **eBPF**: Extended Berkeley Packet Filter programs run in-kernel and can attach to syscall tracepoints, kprobes, and uprobes. eBPF combines the flexibility of ptrace with the performance of seccomp, though it requires recent kernel versions (4.15+) and appropriate privileges.

RubyGuardian employs ptrace for its initial implementation due to the rich inspection capabilities it provides, with eBPF migration planned as future work.

### 2.2.2 Existing Runtime Security Tools

Several open-source tools provide runtime security monitoring capabilities:

- **Falco** (Sysdig): An eBPF-based runtime security tool that monitors container and host behavior using a rule engine. Falco provides general-purpose system monitoring but lacks language-specific detection logic.

- **OSSEC/Wazuh**: Host-based intrusion detection systems that monitor log files, file integrity, and rootkit detection. These tools operate at the host level without process-level behavioral analysis.

- **osquery**: Provides a SQL interface to system state, enabling point-in-time queries about running processes, network connections, and file system state. While powerful for investigation, osquery is not designed for real-time streaming detection.

- **Tracee** (Aqua Security): An eBPF-based runtime security tool for Linux with behavioral detection rules. Like Falco, it provides general-purpose monitoring without language-specific awareness.

None of these tools provide Ruby-specific detection capabilities, feature extraction, or integrated ML classification tailored to Ruby runtime behavior.

## 2.3 Machine Learning for Intrusion Detection

### 2.3.1 Feature Engineering for Syscall-Based Detection

The application of machine learning to intrusion detection based on system call analysis has been studied extensively:

- **Forrest et al. (1996)** pioneered the use of short sequences of system calls as a discriminator between normal and anomalous process behavior.
- **Warrender et al. (1999)** compared Hidden Markov Models, RIPPER rule induction, and sequence time-delay embedding on the UNM syscall dataset, establishing baseline performance metrics.
- **Creech and Hu (2014)** introduced semantic features derived from syscall arguments and return values, significantly improving classification accuracy over sequence-only approaches.

### 2.3.2 Ensemble Methods for Security Classification

Random Forest and Gradient Boosted ensemble methods have demonstrated strong performance in security classification tasks:

- **Zhang et al. (2018)** achieved 97.2% accuracy on network intrusion detection using XGBoost with engineered flow features.
- **Buczak and Guven (2016)** provide a comprehensive survey showing ensemble methods consistently outperform single-model approaches for intrusion detection.
- **Apruzzese et al. (2020)** demonstrate that Random Forest classifiers are robust to adversarial feature perturbation in network intrusion detection settings.

### 2.3.3 Adversarial Machine Learning in Security

The robustness of ML-based security systems to adversarial manipulation is a critical concern:

- **Biggio et al. (2013)** formalize evasion attacks against ML classifiers, demonstrating that attackers can craft inputs that exploit decision boundary weaknesses.
- **Grosse et al. (2017)** show that adversarial examples can evade malware classifiers with high success rates, highlighting the need for robustness testing.
- **Pierazzi et al. (2020)** distinguish between feature-space and problem-space adversarial attacks, noting that problem-space attacks must preserve malicious functionality.

## 2.4 Memory Forensics

### 2.4.1 Process Memory Analysis

Memory forensics enables the recovery of volatile evidence from process address spaces:

- **Process memory layout**: Linux processes consist of text (code), data, heap, stack, and memory-mapped file regions. Analysis of these regions reveals injected code, decrypted payloads, and runtime state.

- **Entropy analysis**: Shannon entropy measurement of memory regions provides a heuristic for identifying encrypted or compressed data. Regions with entropy approaching 8.0 bits/byte often contain packed malware or shellcode.

- **String extraction**: ASCII and Unicode string extraction from process memory recovers URLs, file paths, credentials, and command-and-control infrastructure identifiers.

### 2.4.2 Tools and Frameworks

- **Volatility**: The de facto standard for memory forensics, providing plugins for process analysis, network connection recovery, and malware detection. Originally designed for full memory dumps rather than live process analysis.

- **proc filesystem**: Linux's /proc virtual filesystem exposes process memory maps (/proc/[pid]/maps) and memory content (/proc/[pid]/mem), enabling live memory inspection without the overhead of a full memory dump.

### 2.4.3 Automated Forensic Evidence Collection

The automation of forensic evidence collection triggered by detection events is an emerging area:

- **GRR (Google Rapid Response)** provides automated forensic data collection at scale but requires manual analysis of collected artifacts.
- **DFIR-IRIS** offers a collaborative incident response platform with automated timeline generation but does not integrate with real-time detection systems.

RubyGuardian's contribution in this space is the tight integration between detection events and automated forensic capture, ensuring that volatile evidence is preserved at the moment of detection rather than during manual investigation.

## 2.5 MITRE ATT&CK Framework

The MITRE ATT&CK framework provides a standardized taxonomy for adversary tactics and techniques. RubyGuardian maps all detection rules to specific ATT&CK techniques, enabling:

- Standardized communication between security teams
- Gap analysis of detection coverage against known attack techniques
- Integration with threat intelligence sharing platforms (STIX/TAXII)

Key ATT&CK techniques relevant to Ruby runtime attacks include:
- T1059.005 (Command and Scripting Interpreter: Ruby)
- T1055.012 (Process Injection: Process Hollowing)
- T1027 (Obfuscated Files or Information)
- T1071.004 (Application Layer Protocol: DNS)
- T1041 (Exfiltration Over C2 Channel)

## 2.6 Summary

This chapter reviewed the relevant background in Ruby language security, runtime monitoring, ML-based intrusion detection, memory forensics, and the MITRE ATT&CK framework. The identified gaps in existing work -- specifically the absence of Ruby-aware runtime security monitoring with integrated ML classification and automated forensics -- motivate the design of RubyGuardian as presented in the following chapter.
