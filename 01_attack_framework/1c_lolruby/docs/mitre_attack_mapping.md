# LoLRuby MITRE ATT&CK Mapping

## Overview

This document maps each LoLRuby technique to the corresponding MITRE ATT&CK framework
technique IDs, tactics, and procedures. The ATT&CK framework version referenced is v14.

---

## Reconnaissance

### T1046 - Network Service Discovery
- **LoLRuby ID**: LR-R-001, LR-R-002, LR-R-003
- **Techniques**: `network_scan.rb`, `service_enum.rb`
- **Ruby Methods**: `TCPSocket.new`, `Net::HTTP.get_response`, `Socket.connect_nonblock`
- **Description**: Ruby's socket library provides full TCP/UDP connectivity for port scanning
  and service enumeration without external tools like nmap.
- **Procedure**: Create TCPSocket connections to enumerate open ports; use Net::HTTP to
  fingerprint web services; grab banners via raw socket reads.

### T1087 - Account Discovery
- **LoLRuby ID**: LR-R-004
- **Sub-technique**: T1087.001 (Local Account)
- **Techniques**: `user_enum.rb`
- **Ruby Methods**: `Etc.passwd`, `Dir['/home/*']`, `File.read('/etc/passwd')`
- **Description**: Ruby's `Etc` module provides direct access to the passwd database.
- **Procedure**: Iterate `Etc.passwd` entries or parse `/etc/passwd` to enumerate local users,
  home directories, shells, and UIDs.

### T1082 - System Information Discovery
- **LoLRuby ID**: LR-R-005
- **Techniques**: `env_dump.rb`
- **Ruby Methods**: `ENV.to_h`, `RbConfig::CONFIG`, `RUBY_PLATFORM`
- **Description**: Environment variables and Ruby configuration expose system details.
- **Procedure**: Dump `ENV` hash for secrets, paths, and system configuration. Inspect
  `RbConfig::CONFIG` for compiler, architecture, and OS details.

### T1580 - Cloud Infrastructure Discovery
- **LoLRuby ID**: LR-R-006
- **Techniques**: `cloud_metadata.rb`
- **Ruby Methods**: `Net::HTTP.get` targeting metadata endpoints
- **Description**: Cloud instance metadata services (IMDS) expose sensitive configuration.
- **Procedure**: Query `169.254.169.254` metadata endpoints for AWS, GCP, and Azure
  instance details, IAM roles, and temporary credentials.

---

## Credential Access

### T1552 - Unsecured Credentials
- **LoLRuby ID**: LR-C-001, LR-C-005, LR-C-006
- **Sub-techniques**:
  - T1552.001 - Credentials In Files
  - T1552.004 - Private Keys
- **Techniques**: `file_harvester.rb`, `ssh_key_finder.rb`
- **Ruby Methods**: `File.read`, `Dir.glob`, `YAML.load_file`, `JSON.parse`
- **Description**: Ruby's file I/O and structured data parsing make credential harvesting
  straightforward.
- **Procedure**: Glob for configuration files (`.env`, `database.yml`, `credentials.json`),
  parse structured formats, extract secrets matching known patterns.

### T1003 - OS Credential Dumping
- **LoLRuby ID**: LR-C-002
- **Sub-technique**: T1003.007 (Proc Filesystem)
- **Techniques**: `memory_scraper.rb`
- **Ruby Methods**: `File.read('/proc/PID/maps')`, `File.read('/proc/PID/mem')`
- **Description**: On Linux, `/proc` filesystem exposes process memory.
- **Procedure**: Read process memory maps, identify readable regions, scan for credential
  patterns (passwords, tokens, keys).

### T1552.003 - Bash History
- **LoLRuby ID**: LR-C-003
- **Techniques**: `history_reader.rb`
- **Ruby Methods**: `File.read`, `Dir.glob('~/.*_history')`
- **Description**: Shell history files often contain credentials passed as arguments.
- **Procedure**: Read `.bash_history`, `.zsh_history`, `.python_history` etc. and search
  for patterns indicating passwords, tokens, or connection strings.

---

## Exfiltration

### T1048 - Exfiltration Over Alternative Protocol
- **LoLRuby ID**: LR-E-001, LR-E-003
- **Sub-techniques**:
  - T1048.001 - Exfiltration Over Symmetric Encrypted Non-C2 Protocol
  - T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol
- **Techniques**: `dns_exfil.rb`, `icmp_tunnel.rb`
- **Ruby Methods**: `Resolv::DNS`, `UDPSocket`, `Socket.new(:INET, :RAW)`
- **Description**: DNS and ICMP are often less monitored than HTTP traffic.
- **Procedure**: Encode data into DNS query labels (max 63 chars per label) or ICMP
  echo request payloads to exfiltrate data through channels that bypass web proxies.

### T1041 - Exfiltration Over C2 Channel
- **LoLRuby ID**: LR-E-002
- **Techniques**: `http_exfil.rb`
- **Ruby Methods**: `Net::HTTP.post`, `URI`, `OpenSSL`
- **Description**: HTTP/HTTPS exfiltration blends with normal web traffic.
- **Procedure**: Chunk data, encode (Base64/hex), POST to attacker-controlled endpoint
  or encode into GET parameters, cookies, or custom headers.

### T1027 - Obfuscated Files or Information
- **LoLRuby ID**: LR-E-004
- **Sub-technique**: T1027.003 - Steganography
- **Techniques**: `steganography.rb`
- **Ruby Methods**: Binary file I/O, bit manipulation
- **Description**: Data hidden in image least-significant bits evades content inspection.
- **Procedure**: Read carrier image pixel data, encode secret data into LSBs of color
  channels, write modified image that appears visually identical.

---

## Execution

### T1059.002 - Command and Scripting Interpreter: Ruby (custom mapping)
- **LoLRuby ID**: LR-X-001 through LR-X-010
- **Techniques**: `eval_execution.rb`, `open3_exec.rb`, `backtick_exec.rb`,
  `system_exec.rb`, `io_popen_exec.rb`
- **Ruby Methods**: `eval`, `Open3.popen3`, backticks, `system`, `IO.popen`
- **Description**: Ruby provides at least 6 distinct mechanisms for executing commands
  and arbitrary code, each with different visibility to monitoring tools.
- **Procedure**: Select execution method based on requirements (output capture, shell
  expansion, background execution, stream handling).

### T1106 - Native API
- **LoLRuby ID**: LR-X-009
- **Techniques**: (Fiddle FFI - referenced in matrix)
- **Ruby Methods**: `Fiddle::Function`, `Fiddle::Importer`
- **Description**: Ruby's Fiddle library provides direct FFI access to shared libraries.
- **Procedure**: Load libc or other shared objects, call native functions directly from
  Ruby bypassing shell command logging.

---

## Persistence

### T1053 - Scheduled Task/Job
- **LoLRuby ID**: LR-P-001
- **Sub-technique**: T1053.003 - Cron
- **Techniques**: `cron_installer.rb`
- **Ruby Methods**: `File.write`, `IO.popen('crontab')`
- **Description**: Ruby can programmatically create or modify crontab entries.
- **Procedure**: Read existing crontab, append malicious entry, write back via pipe to
  `crontab -` command.

### T1546 - Event Triggered Execution
- **LoLRuby ID**: LR-P-002
- **Sub-technique**: T1546.004 - Unix Shell Configuration Modification
- **Techniques**: `bashrc_injector.rb`
- **Ruby Methods**: `File.open(path, 'a')`, `File.write`
- **Description**: Shell rc files execute on every new shell session.
- **Procedure**: Append Ruby one-liner or source command to `.bashrc`, `.zshrc`, or
  `.profile` for execution on user login.

### T1505 - Server Software Component
- **LoLRuby ID**: LR-P-003
- **Sub-technique**: T1505.003 - Web Shell (adapted for Gem backdoor)
- **Techniques**: `gem_backdoor.rb`
- **Ruby Methods**: `Gem::Specification`, `Gem.post_install`
- **Description**: Malicious code in gem install hooks executes during gem operations.
- **Procedure**: Modify gem specification to include `post_install_message` with eval,
  or inject code into gem's `extconf.rb` executed during native extension compilation.

### T1543 - Create or Modify System Process
- **LoLRuby ID**: LR-P-004
- **Sub-technique**: T1543.002 - Systemd Service
- **Techniques**: `service_installer.rb`
- **Ruby Methods**: `File.write` (unit files), `system('systemctl')`
- **Description**: Systemd unit files provide persistent service execution.
- **Procedure**: Generate a systemd unit file that executes a Ruby script, install to
  user or system service directory, enable via systemctl.

---

## Defense Evasion

### T1070 - Indicator Removal
- **LoLRuby ID**: LR-D-001
- **Sub-techniques**:
  - T1070.003 - Clear Command History
  - T1070.006 - Timestomp
- **Techniques**: `log_cleaner.rb`, `timestamp_stomper.rb`
- **Ruby Methods**: `File.truncate`, `File.utime`, `File.write`
- **Description**: Ruby's file manipulation APIs can alter or remove forensic artifacts.
- **Procedure**: Truncate or selectively edit log files; use `File.utime` to modify
  access and modification timestamps to match surrounding files.

### T1036 - Masquerading
- **LoLRuby ID**: LR-D-003
- **Sub-technique**: T1036.004 - Masquerade Task or Service
- **Techniques**: `process_rename.rb`
- **Ruby Methods**: `$0 = 'name'`, `Process.setproctitle`
- **Description**: Ruby allows runtime modification of the process name visible in `ps`.
- **Procedure**: Set `$0` to a benign process name like `[kworker/0:0]` or `sshd` to
  blend in with legitimate system processes.

### T1027 - Obfuscated Files or Information
- **LoLRuby ID**: LR-D-004
- **Techniques**: `obfuscator.rb`
- **Ruby Methods**: `Base64.encode64`, `Marshal.dump`, `eval`, string manipulation
- **Description**: Multiple encoding and obfuscation layers can defeat static analysis.
- **Procedure**: Apply multiple encoding passes (Base64, hex, XOR, Marshal) with eval
  unwrapping to make payload content opaque to signature-based detection.

---

## ATT&CK Navigator Layer

The following JSON can be imported into the ATT&CK Navigator to visualize LoLRuby coverage:

```json
{
  "name": "LoLRuby Coverage",
  "versions": { "attack": "14", "navigator": "4.9.1", "layer": "4.5" },
  "domain": "enterprise-attack",
  "techniques": [
    {"techniqueID": "T1046", "color": "#66b1ff", "comment": "Network scanning via TCPSocket"},
    {"techniqueID": "T1087", "color": "#66b1ff", "comment": "User enum via Etc module"},
    {"techniqueID": "T1082", "color": "#66b1ff", "comment": "Env/system info dump"},
    {"techniqueID": "T1580", "color": "#66b1ff", "comment": "Cloud metadata query"},
    {"techniqueID": "T1552", "color": "#ff6666", "comment": "File/env credential harvest"},
    {"techniqueID": "T1003", "color": "#ff6666", "comment": "Proc memory scraping"},
    {"techniqueID": "T1048", "color": "#ff9933", "comment": "DNS/ICMP exfiltration"},
    {"techniqueID": "T1041", "color": "#ff9933", "comment": "HTTP exfiltration"},
    {"techniqueID": "T1027", "color": "#ff9933", "comment": "Steganography/obfuscation"},
    {"techniqueID": "T1059", "color": "#cc66ff", "comment": "Ruby execution methods"},
    {"techniqueID": "T1106", "color": "#cc66ff", "comment": "FFI native API"},
    {"techniqueID": "T1053", "color": "#ffcc00", "comment": "Cron persistence"},
    {"techniqueID": "T1546", "color": "#ffcc00", "comment": "Shell rc injection"},
    {"techniqueID": "T1505", "color": "#ffcc00", "comment": "Gem backdoor"},
    {"techniqueID": "T1543", "color": "#ffcc00", "comment": "Systemd service"},
    {"techniqueID": "T1070", "color": "#99cc99", "comment": "Log/timestamp manipulation"},
    {"techniqueID": "T1036", "color": "#99cc99", "comment": "Process masquerading"},
    {"techniqueID": "T1027", "color": "#99cc99", "comment": "Code obfuscation"}
  ]
}
```
