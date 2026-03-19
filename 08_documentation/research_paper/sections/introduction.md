# 1. Introduction

## 1.1 Background

The Ruby programming language has become a foundational technology in modern
web development, DevOps tooling, and cloud infrastructure. With over 170,000
gems published on RubyGems.org and widespread adoption through frameworks
like Ruby on Rails, Sinatra, and Chef, Ruby occupies a significant position
in the software supply chain. However, this ubiquity has attracted the
attention of adversaries who exploit Ruby's dynamic nature for malicious
purposes.

Ruby's powerful metaprogramming capabilities -- including `eval`, `send`,
`define_method`, `ObjectSpace`, and runtime class modification -- provide
attackers with a uniquely flexible toolkit for crafting evasive malware.
Unlike compiled languages where static analysis can reliably identify
suspicious patterns, Ruby's dynamic dispatch and open classes make it
possible to construct payloads that are semantically opaque until runtime.
This fundamental characteristic poses significant challenges for traditional
signature-based detection approaches.

Recent incidents have demonstrated the growing threat landscape for
Ruby-based attacks. Supply chain compromises through malicious gems
(e.g., the `rest-client` gem compromise of 2019, the `ua-parser-js`
ecosystem attack of 2021), CI/CD pipeline poisoning, and in-memory
persistence techniques have emerged as practical attack vectors. Despite
these threats, the security research community has produced relatively
few comprehensive frameworks that combine offensive technique
demonstration with defensive detection and forensic analysis
capabilities specifically tailored to the Ruby ecosystem.

## 1.2 Problem Statement

Current approaches to Ruby malware detection suffer from several
limitations:

1. **Signature fragility.** Traditional YARA-based and regex-based
   signatures are effective against known malware families but fail to
   generalize to novel or polymorphic variants. Ruby's dynamic evaluation
   capabilities allow trivial obfuscation that defeats pattern matching.

2. **Limited behavioral analysis.** Most Ruby application security tools
   focus on static analysis of source code (e.g., Brakeman for Rails).
   Runtime behavioral monitoring of Ruby processes -- including syscall
   tracing, memory region analysis, and ObjectSpace inspection -- remains
   an underexplored detection surface.

3. **Absence of memory forensics tooling.** When a Ruby process is
   compromised, responders lack specialized tools for capturing and
   analyzing the Ruby virtual machine's heap, reconstructing injected
   code from iseq structures, and extracting indicators of compromise
   from process memory.

4. **Insufficient training data.** Machine learning approaches to malware
   classification require labeled datasets of benign and malicious Ruby
   scripts. No comprehensive, openly available dataset exists for this
   purpose, forcing researchers to construct their own corpora.

5. **Fragmented research.** Existing work addresses individual aspects
   (static analysis, gem vetting, dependency auditing) in isolation,
   without providing an integrated pipeline from attack simulation
   through detection, classification, forensics, and reporting.

## 1.3 Research Objectives

This research presents **RubyGuardian**, an integrated framework that
addresses the above gaps through six interconnected phases:

1. **Attack Framework** -- Implement documented offensive techniques
   (process hollowing, CI/CD poisoning, living-off-the-land Ruby abuse,
   ObjectSpace persistence) to generate realistic threat scenarios and
   ground-truth labeled data.

2. **Detection Engine** -- Develop a multi-sensor detection agent that
   combines syscall tracing (via eBPF), memory inspection, network
   monitoring, filesystem watching, and Ruby ObjectSpace scanning with
   a configurable rule engine supporting threshold, sequence, and
   correlation-based detection logic.

3. **ML Classifier** -- Train and evaluate an ensemble of machine
   learning classifiers (Random Forest, XGBoost, Neural Network) on
   static features extracted from Ruby scripts, achieving robust
   classification of benign versus malicious code.

4. **Memory Forensics** -- Build a forensic acquisition and analysis
   pipeline that captures process memory with chain-of-custody
   integrity, parses Ruby VM structures, reconstructs injected code,
   and produces structured forensic reports.

5. **Honeypot System** -- Deploy realistic decoy Ruby applications
   (a fake Rails app, gem server, and CI runner) that attract and
   capture adversary behavior for intelligence collection.

6. **Unified Dashboard** -- Integrate all components through an ELK
   Stack and Grafana-based monitoring platform with a React web UI
   for real-time visibility and incident response.

## 1.4 Contributions

The principal contributions of this work are:

- A comprehensive, open-source framework that spans the full spectrum
  from offensive technique implementation to defensive detection and
  forensic response, specifically targeting the Ruby ecosystem.

- A novel detection engine architecture that combines six distinct
  monitoring surfaces (process, syscall, memory, network, filesystem,
  and ObjectSpace) with a correlation-capable rule engine.

- An empirical evaluation of ensemble machine learning classifiers
  for Ruby malware detection, demonstrating the relative effectiveness
  of static feature extraction across multiple model architectures.

- A specialized memory forensics toolkit for Ruby processes that can
  reconstruct source code from in-memory iseq structures and identify
  indicators of compromise in heap dumps.

- A curated dataset of benign and malicious Ruby scripts with extracted
  feature vectors suitable for reproducible machine learning research.

## 1.5 Paper Organization

The remainder of this paper is organized as follows. Section 2 reviews
related work in malware detection, Ruby security, and memory forensics.
Section 3 describes our methodology, including the architecture of each
framework component and the experimental design. Section 4 presents
our results, covering detection engine efficacy, classifier performance
metrics, forensic analysis capabilities, and honeypot intelligence
findings. Section 5 discusses limitations, ethical considerations, and
directions for future work. Section 6 concludes the paper.
