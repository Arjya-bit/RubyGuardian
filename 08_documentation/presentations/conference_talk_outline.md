# RubyGuardian: Runtime Security Monitoring for Ruby Applications

## Conference Talk Outline

**Target Audience**: Security researchers, Ruby developers, DevSecOps engineers
**Duration**: 45 minutes + 15 minutes Q&A
**Format**: Technical talk with live demonstration

---

## Slide 1: Title & Introduction (2 minutes)

- **Title**: "RubyGuardian: Detecting and Analyzing Attacks Against Ruby Runtimes"
- Speaker introduction and background
- Brief overview: What is RubyGuardian and why does it matter?

## Slide 2: The Problem Space (5 minutes)

### Ruby in the Enterprise
- Ruby on Rails powers significant portions of web infrastructure (GitHub, Shopify, Basecamp)
- Ruby's dynamic nature (eval, method_missing, open classes) creates a unique attack surface
- Supply chain attacks targeting RubyGems have increased 300% since 2020

### Current Gaps
- Traditional AV/EDR solutions lack Ruby-specific detection logic
- Static analysis cannot catch runtime-only attack patterns
- No existing tool combines Ruby-aware detection with ML classification and memory forensics

### Threat Model
- Malicious gem dependencies executing arbitrary code
- eval() chain exploits in web applications
- Process injection and hollowing from Ruby processes
- Data exfiltration via DNS tunneling from Ruby applications

## Slide 3: Architecture Overview (5 minutes)

### System Components
```
Attack Framework (Red Team) --> Detection Engine --> ML Classifier
         |                            |                   |
    Honeypot System              Event Correlation    Threat Scoring
         |                            |                   |
    Threat Intel             Forensic Capture         Dashboard
```

### Design Principles
1. **Defense in Depth**: Multiple detection layers (signature, behavioral, ML)
2. **Ruby-Native**: Detection rules understand Ruby-specific syscall patterns
3. **Real-Time**: Sub-second detection with WebSocket event streaming
4. **Evidence Preservation**: Automated memory dumps and artifact collection
5. **Standards-Based**: MITRE ATT&CK mapping for all detections

## Slide 4: Attack Framework (5 minutes)

### Red Team Capabilities
- Process Hollowing: Inject malicious code into legitimate Ruby processes
- eval() Chain Exploitation: Multi-stage payload delivery via dynamic evaluation
- Obfuscated Loaders: Base64/XOR encoded payloads to evade static analysis
- DNS Exfiltration: Encode stolen data in DNS query subdomain labels
- Gem Typosquatting Simulation: Simulate malicious dependency installation

### Implementation Highlights
- Written in Ruby to accurately model real-world Ruby attack patterns
- Uses ptrace and /proc filesystem for process manipulation
- Implements actual MITRE ATT&CK techniques (T1055.012, T1059.005, T1071.004)

## Slide 5: Detection Engine Deep Dive (5 minutes)

### Multi-Layer Detection
1. **Signature Rules** (YAML-based)
   - Syscall sequence matching (e.g., ptrace + mmap + memcpy pattern)
   - Command-line argument analysis
   - Network behavior signatures

2. **Behavioral Heuristics**
   - Anomalous syscall frequency detection
   - Unexpected network connections from Ruby processes
   - File access pattern deviations

3. **Event Correlation**
   - Time-windowed correlation of related events
   - Process tree relationship tracking
   - Multi-stage attack chain detection

### Performance
- Processes 10,000+ events/second on a single node
- Average detection latency: 50ms from event to alert

## Slide 6: ML Classifier (5 minutes)

### Feature Engineering
- 47 features extracted from syscall traces, network flows, and process metadata
- Feature categories: syscall frequency, network entropy, process behavior, file operations
- Temporal features capturing behavioral patterns over sliding windows

### Model Architecture
- Random Forest ensemble classifier (primary)
- Gradient Boosted Trees (secondary, for comparison)
- 5-fold stratified cross-validation during training

### Results
| Metric     | Random Forest | Gradient Boosted |
|------------|---------------|------------------|
| Accuracy   | 96.8%         | 97.1%            |
| Precision  | 95.2%         | 96.0%            |
| Recall     | 97.5%         | 96.8%            |
| F1 Score   | 96.3%         | 96.4%            |
| FPR        | 1.8%          | 1.5%             |

## Slide 7: Memory Forensics (3 minutes)

### Capabilities
- Automated memory dump triggered by critical detections
- Process memory region enumeration and classification
- Entropy analysis for detecting packed/encrypted payloads
- Automatic string and IOC extraction from memory dumps
- Memory-mapped file identification

### Key Findings
- Injected shellcode identifiable through entropy analysis (entropy > 7.0)
- Stolen credentials recoverable from process heap memory
- C2 infrastructure URLs extractable from network buffer regions

## Slide 8: Honeypot System (3 minutes)

### Design
- Simulates vulnerable Ruby web services (Rails, Sinatra, RubyGems API)
- Captures attacker TTPs for threat intelligence
- Feeds captured payloads into ML classifier training pipeline

### Intelligence Gathering
- Records full interaction sessions with attacker IP geolocation
- Extracts novel attack payloads for signature generation
- Tracks evolution of attack techniques over time

## Slide 9: Dashboard & Visualization (2 minutes)

### Live Demo of Dashboard
- Real-time event timeline with severity-colored markers
- Alert table with MITRE ATT&CK technique mapping
- Geographic threat origin map
- ML classifier feature importance visualization
- Memory dump hex viewer with string extraction

## Slide 10: Live Demonstration (8 minutes)

### Demo Scenario: Complete Attack Chain
1. Start the target Ruby application
2. Execute reconnaissance scan
3. Deploy eval() chain payload
4. Perform process hollowing injection
5. Initiate DNS-based data exfiltration
6. Observe real-time detection and alerting
7. Review forensic evidence and IOCs

## Slide 11: Evaluation & Results (3 minutes)

### Detection Coverage
- 12/12 implemented attack techniques detected
- Average time from attack initiation to alert: 2.3 seconds
- Zero attacks evaded all detection layers simultaneously

### Adversarial Testing
- Tested against obfuscation evasion (Base64, XOR, string splitting)
- Tested against feature manipulation attacks
- Robustness to noise injection verified
- Concept drift handling with periodic retraining

## Slide 12: Future Work (2 minutes)

1. **eBPF-Based Monitoring**: Replace ptrace with eBPF for lower-overhead syscall capture
2. **LLM-Assisted Analysis**: Use language models for natural-language forensic report generation
3. **Distributed Deployment**: Multi-node detection with federated ML model training
4. **Ruby 3.x Ractor Support**: Monitor Ruby's new parallel execution model
5. **STIX/TAXII Integration**: Automated threat intelligence sharing

## Slide 13: Conclusion & Q&A (2 minutes)

### Key Takeaways
- Dynamic languages need specialized security monitoring
- ML classification complements signature-based detection
- Automated forensics reduces incident response time
- Open-source tools can provide enterprise-grade Ruby security

### Resources
- GitHub Repository: github.com/rubyguardian/rubyguardian
- Documentation: rubyguardian.readthedocs.io
- Research Paper: (link to published paper)

---

## Speaker Notes

### Equipment Requirements
- Laptop with Docker (16GB RAM recommended)
- External display/projector (1920x1080)
- Stable internet connection for live demo (have offline fallback)

### Timing Checkpoints
- 10 min mark: Should be finishing Architecture Overview
- 20 min mark: Should be starting ML Classifier section
- 30 min mark: Should be starting Live Demo
- 40 min mark: Should be wrapping up with evaluation
- 45 min mark: Q&A begins

### Common Questions to Prepare For
1. "How does this compare to Falco or OSSEC?" - Focus on Ruby-specific detection
2. "What's the performance overhead?" - <3% CPU overhead in production benchmarks
3. "Can this detect zero-day attacks?" - ML layer provides anomaly detection beyond known signatures
4. "How do you handle false positives?" - Severity-based tuning + feedback loop to ML retraining
