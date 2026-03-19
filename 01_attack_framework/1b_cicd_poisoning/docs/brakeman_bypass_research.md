# Brakeman Bypass Research

> **EDUCATIONAL MATERIAL - For authorized security research only**
> Understanding static analysis limitations helps build better defenses.

## Overview

Brakeman is the most widely used static analysis security scanner for Ruby on Rails
applications. Understanding its detection capabilities and limitations is essential for:

1. Security researchers developing more robust scanning tools
2. Defenders who need to understand the gaps in their tooling
3. Building complementary detection mechanisms

## 1. How Brakeman Works

### 1.1 Analysis Approach

Brakeman performs static analysis by:

1. **Parsing**: Converts Ruby source files into an Abstract Syntax Tree (AST)
2. **Data Flow Analysis**: Tracks how data flows from sources (user input) to sinks
   (dangerous operations like SQL queries, system calls)
3. **Pattern Matching**: Matches known-dangerous code patterns
4. **Taint Tracking**: Marks user-controlled data as "tainted" and checks if it reaches
   sensitive operations without sanitization

### 1.2 Detection Categories

Brakeman checks for:
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Mass Assignment
- Dangerous eval usage
- File access vulnerabilities
- Information disclosure
- And many more...

## 2. Fundamental Limitations of Static Analysis

### 2.1 The Halting Problem

Static analysis cannot perfectly determine all possible runtime behaviors. This means:
- False negatives (missed vulnerabilities) are inevitable
- Any static analyzer must make trade-offs between precision and recall
- Dynamic behaviors are especially challenging

### 2.2 Ruby-Specific Challenges

Ruby's dynamic nature creates significant challenges for static analysis:

```ruby
# Challenge 1: Dynamic method dispatch
# Brakeman cannot always resolve which method is being called
obj.send(user_input.to_sym, args)

# Challenge 2: Dynamic string construction
# Complex string building may not be traced
table = ["us", "ers"].join
query = "SELECT * FROM #{table}"

# Challenge 3: Metaprogramming
# define_method, method_missing, and other meta features
# create methods that don't exist in source code
```

## 3. Bypass Techniques (Educational)

### 3.1 Indirect eval Through Metaprogramming

```ruby
# EDUCATIONAL: Brakeman detects direct eval calls
# These would be flagged:
eval(user_input)                    # Detected
Kernel.eval(user_input)             # Detected
instance_eval(user_input)           # Detected

# EDUCATIONAL: These indirect patterns may evade detection
# Pattern 1: Method reference
method(:eval).call(payload)

# Pattern 2: send-based dispatch
# Brakeman may not resolve the target method
Kernel.send(:eval, payload)

# Pattern 3: Dynamic method lookup
eval_method = "ev" + "al"
Kernel.send(eval_method.to_sym, payload)

# Pattern 4: Binding-based evaluation
binding.eval(payload)

# Pattern 5: Through a lambda/proc wrapper
evaluator = ->(code) { eval(code) }
evaluator.call(payload)
```

### 3.2 Obfuscated Command Execution

```ruby
# EDUCATIONAL: Brakeman detects standard command execution
system(user_input)        # Detected
`#{user_input}`           # Detected
exec(user_input)          # Detected
IO.popen(user_input)      # Detected

# EDUCATIONAL: Patterns that may evade detection

# Pattern 1: Open3 usage (may not be fully tracked)
require 'open3'
Open3.capture3(constructed_command)

# Pattern 2: PTY-based execution
require 'pty'
PTY.spawn(command) { |r, w, pid| r.read }

# Pattern 3: Process.spawn with complex arguments
Process.spawn(env_hash, command, chdir: dir, unsetenv_others: true)

# Pattern 4: Fiddle for direct libc calls (advanced)
require 'fiddle'
# Can call system() directly through FFI, bypassing Ruby-level detection
```

### 3.3 SQL Injection Bypass Patterns

```ruby
# EDUCATIONAL: Brakeman detects standard SQL injection
User.where("name = '#{params[:name]}'")           # Detected
User.find_by_sql("SELECT * FROM users WHERE #{q}") # Detected

# EDUCATIONAL: Patterns that may evade detection

# Pattern 1: Arel manipulation
table = User.arel_table
condition = Arel::Nodes::SqlLiteral.new(user_controlled_string)
User.where(condition)

# Pattern 2: Connection-level queries
ActiveRecord::Base.connection.select_all(
  "SELECT * FROM #{sanitize_table(params[:table])}"
)
# If sanitize_table is custom and Brakeman doesn't recognize it as unsafe

# Pattern 3: Multi-step string construction
parts = []
parts << "SELECT * FROM users WHERE "
parts << "name = '#{params[:name]}'"
ActiveRecord::Base.connection.execute(parts.join)

# Pattern 4: Through a caching layer
Rails.cache.fetch("query_#{params[:id]}") do
  User.find_by_sql(cached_query_template % params[:id])
end
```

### 3.4 File Operation Bypass

```ruby
# EDUCATIONAL: Brakeman detects direct file operations with user input
File.read(params[:filename])      # Detected
File.open(params[:path])          # Detected
send_file(params[:file])          # Detected

# EDUCATIONAL: Evasion patterns

# Pattern 1: Pathname-based access
path = Pathname.new(base_dir).join(params[:file])
path.read  # Brakeman may not track Pathname operations

# Pattern 2: Through IO class
IO.read(constructed_path)
IO.foreach(constructed_path) { |line| process(line) }

# Pattern 3: Dir-based enumeration
Dir.glob(params[:pattern]).each { |f| process_file(f) }

# Pattern 4: Tempfile manipulation
tmp = Tempfile.new('prefix')
tmp.write(File.read(user_controlled_path))
```

### 3.5 Deserialization Bypass

```ruby
# EDUCATIONAL: Brakeman detects unsafe deserialization
Marshal.load(user_input)       # Detected
YAML.load(user_input)          # Detected (in older Ruby/Psych)

# EDUCATIONAL: Evasion patterns

# Pattern 1: Psych direct usage
Psych.unsafe_load(data)  # May not be specifically checked

# Pattern 2: JSON.parse with create_additions
JSON.parse(data, create_additions: true)
# This enables automatic object instantiation from JSON

# Pattern 3: Custom deserialization through ERB
template = ERB.new(user_controlled_template)
template.result(binding)  # ERB evaluation with full Ruby access

# Pattern 4: Oj gem (if used instead of stdlib JSON)
Oj.load(data, mode: :object)  # Object mode allows arbitrary instantiation
```

## 4. Supply Chain Specific Bypasses

### 4.1 Code Not in Application Source

```ruby
# EDUCATIONAL: Brakeman typically scans application code, not gem source
# Malicious code in a gem's lib/ directory is usually outside Brakeman's scope

# A poisoned gem can contain arbitrary malicious code that Brakeman
# won't scan because:
# 1. It's in the vendor/bundle or gem installation directory
# 2. Brakeman focuses on app/, lib/, config/ of the Rails app
# 3. Gem code is trusted by default
```

### 4.2 Initializer-Based Attacks

```ruby
# EDUCATIONAL: Code in config/initializers/ runs at boot time
# While Brakeman scans initializers, complex patterns may evade detection

# config/initializers/metrics.rb
# Looks innocent but contains obfuscated backdoor
require 'base64'

Rails.application.config.after_initialize do
  # This runs after all initializers, making it hard to trace
  if defined?(Rails::Server)
    # Only activates when running as a server (not in tests/console)
    Thread.new do
      # Background operations are harder for static analysis to follow
      loop do
        sleep 3600
        # Educational: periodic beacon or data collection
      end
    end
  end
end
```

### 4.3 Monkey-Patching Core Classes

```ruby
# EDUCATIONAL: Monkey-patching in gems executes when the gem is loaded
# Brakeman doesn't typically analyze these modifications

# In a malicious gem:
module ActionController
  class Base
    # Override a common method to intercept all requests
    alias_method :original_process_action, :process_action

    def process_action(*args)
      # Educational: intercept and log all request parameters
      # This runs for every request but is invisible to Brakeman
      # because it's in gem code, not application code
      original_process_action(*args)
    end
  end
end
```

## 5. Improving Detection

### 5.1 Complementary Tools

| Tool | Coverage |
|------|----------|
| Brakeman | Rails-specific static analysis |
| RuboCop (security cops) | General Ruby patterns |
| Bundler Audit | Known vulnerable dependencies |
| bearer | API and data flow analysis |
| Semgrep | Custom pattern matching |

### 5.2 Custom Brakeman Checks

```ruby
# You can extend Brakeman with custom checks
# lib/brakeman/checks/check_supply_chain.rb
require 'brakeman/checks/base_check'

class Brakeman::CheckSupplyChain < Brakeman::BaseCheck
  Brakeman::Checks.add self

  @description = "Checks for supply chain attack indicators"

  def run_check
    # Check for suspicious patterns in initializers
    tracker.find_call(target: nil, method: :eval).each do |result|
      warn result,
           warning_type: "Supply Chain",
           message: "eval() detected - verify this is intentional",
           confidence: :medium
    end
  end
end
```

### 5.3 Runtime Detection

```ruby
# Runtime detection complements static analysis
# Monitor for:
# 1. Unexpected eval() calls
# 2. New network connections during boot
# 3. File system modifications outside expected paths
# 4. Process spawning during gem loading
# 5. Modifications to core classes after boot
```

## 6. Recommendations

1. **Don't rely solely on Brakeman** -- use it as one layer in a defense-in-depth strategy
2. **Add custom checks** for patterns specific to your application
3. **Scan gem source code** -- don't limit analysis to application code
4. **Use runtime monitoring** to catch what static analysis misses
5. **Implement SBOM and dependency verification** to detect supply chain tampering
6. **Review all initializer changes** with extra scrutiny
7. **Monitor for monkey-patching** of security-critical classes

## References

- Brakeman documentation: https://brakemanscanner.org/docs/
- "Static Analysis at Scale" - Caitlin Sadowski et al.
- OWASP Static Analysis guide
- Brakeman source code and check implementations
