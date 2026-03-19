# Chapter 1: Introduction

## 1.1 Motivation

The Ruby programming language and its flagship web framework, Ruby on Rails, power a significant portion of the modern web infrastructure. Organizations including GitHub, Shopify, Basecamp, and Stripe rely on Ruby for mission-critical applications serving millions of users. Despite this widespread adoption, the security monitoring ecosystem for Ruby runtimes remains notably underdeveloped compared to languages such as Java or C#, which benefit from mature instrumentation frameworks and extensive security tooling.

Ruby's design philosophy of developer productivity and expressiveness introduces inherent security challenges. Language features such as `eval()`, `instance_eval`, `method_missing`, open classes, and dynamic method definition enable powerful metaprogramming patterns but simultaneously create an expansive attack surface. An attacker who gains the ability to execute arbitrary Ruby code within a running process can leverage these features to dynamically modify application behavior, inject malicious logic into existing classes, and evade static analysis tools that cannot reason about runtime-generated code.

The threat landscape for Ruby applications has intensified in recent years. Supply chain attacks targeting the RubyGems package repository have grown substantially, with malicious gems employing techniques ranging from credential theft to cryptocurrency mining. The 2019 `rest-client` gem compromise affected over 100 million installations, demonstrating the scale of impact that a single compromised dependency can achieve. More recently, typosquatting attacks and dependency confusion techniques have introduced novel vectors for compromising Ruby applications.

Existing security solutions are insufficient for addressing these Ruby-specific threats. Traditional endpoint detection and response (EDR) systems operate at the operating system level and lack awareness of Ruby's internal execution model. Static analysis tools such as Brakeman can identify known vulnerability patterns in source code but cannot detect runtime-only attacks such as process injection or dynamic code evaluation. Web application firewalls (WAFs) protect the HTTP layer but offer no visibility into post-exploitation activity within the Ruby process.

## 1.2 Problem Statement

This thesis addresses the following research question: **How can we design and implement an integrated security monitoring system that leverages Ruby-specific behavioral analysis, machine learning classification, and automated memory forensics to detect, classify, and investigate attacks targeting Ruby runtime environments?**

The problem decomposes into several sub-questions:

1. What syscall patterns and behavioral signatures distinguish malicious Ruby process activity from benign operations?
2. Can machine learning classifiers trained on Ruby-specific features achieve sufficient accuracy to supplement signature-based detection in production environments?
3. How can automated memory forensics be integrated with detection systems to preserve digital evidence while minimizing operational disruption?
4. What is the minimum detection latency achievable for real-time alerting on active attacks?

## 1.3 Contributions

This thesis makes the following contributions to the field of runtime security monitoring:

1. **RubyGuardian System Architecture**: We present the design and implementation of RubyGuardian, an integrated security monitoring platform specifically engineered for Ruby runtime environments. The system combines signature-based detection, behavioral heuristics, machine learning classification, and automated memory forensics in a cohesive pipeline.

2. **Ruby-Specific Attack Framework**: We develop a comprehensive red team framework implementing real-world attack techniques adapted for Ruby runtimes, including process hollowing via ptrace, eval() chain exploitation, obfuscated payload delivery, and DNS-based data exfiltration. These implementations serve as both a testing corpus and a contribution to the security research community's understanding of Ruby-specific threats.

3. **Multi-Layer Detection Engine**: We design a detection engine that processes system events through three complementary layers: YAML-defined signature rules matching known attack patterns, behavioral heuristics detecting anomalous Ruby process behavior, and a time-windowed event correlation engine that links individual events into attack narratives.

4. **ML Threat Classifier**: We develop and evaluate a machine learning classifier trained on 47 features extracted from syscall traces, network flows, and process metadata. The classifier achieves 96.8% accuracy with a 1.8% false positive rate using a Random Forest ensemble approach.

5. **Automated Memory Forensics Pipeline**: We implement an automated forensic analysis pipeline that triggers memory dumps based on detection severity, performs entropy analysis to identify injected code regions, and extracts indicators of compromise (IOCs) for threat intelligence sharing.

6. **Empirical Evaluation**: We provide comprehensive evaluation results demonstrating detection coverage across 12 attack techniques, classifier performance under adversarial conditions, and end-to-end system latency measurements.

## 1.4 Scope and Limitations

RubyGuardian focuses specifically on monitoring CRuby (MRI) version 2.7 through 3.2 on Linux-based systems. The system relies on ptrace-based syscall interception for process monitoring, which imposes constraints on deployment environments where ptrace may be restricted (e.g., hardened container runtimes). Alternative Ruby implementations (JRuby, TruffleRuby, mruby) are not covered in this work.

The attack framework implements twelve representative techniques mapped to the MITRE ATT&CK framework. While these techniques cover the most prevalent attack patterns observed in Ruby-targeted incidents, they do not constitute an exhaustive enumeration of all possible Ruby attack vectors.

The ML classifier is evaluated in a controlled laboratory environment with synthetic and semi-synthetic datasets. Production deployment would require additional validation with organization-specific baseline data and ongoing retraining to address concept drift.

## 1.5 Thesis Organization

The remainder of this thesis is organized as follows:

- **Chapter 2: Background and Related Work** reviews the relevant literature on runtime security monitoring, Ruby language security, machine learning for intrusion detection, and memory forensics.
- **Chapter 3: System Design** presents the architecture of RubyGuardian, detailing the design decisions, component interactions, and data flow.
- **Chapter 4: Implementation** describes the implementation of each subsystem, including the attack framework, detection engine, ML classifier, memory forensics module, and dashboard.
- **Chapter 5: Evaluation** presents experimental results including detection coverage, classifier performance, adversarial robustness testing, and performance benchmarks.
- **Chapter 6: Conclusion** summarizes findings, discusses implications, and outlines directions for future research.
