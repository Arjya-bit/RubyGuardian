# LoLRuby Technique Matrix

## Technique x Operating System x Risk Level

Risk levels: **LOW** (information gathering), **MEDIUM** (file access/modification),
**HIGH** (code execution/persistence), **CRITICAL** (credential theft/exfiltration)

### Reconnaissance Techniques

| ID       | Technique            | Ruby Method                     | Linux | macOS | Windows | Risk   |
|----------|----------------------|---------------------------------|-------|-------|---------|--------|
| LR-R-001 | Network Port Scan    | TCPSocket.new / connect_nonblock| Yes   | Yes   | Yes     | LOW    |
| LR-R-002 | HTTP Service Enum    | Net::HTTP.get_response          | Yes   | Yes   | Yes     | LOW    |
| LR-R-003 | Service Banner Grab  | TCPSocket.new + recv            | Yes   | Yes   | Yes     | LOW    |
| LR-R-004 | User Enumeration     | Etc.passwd / Dir['/home/*']     | Yes   | Yes   | Partial | LOW    |
| LR-R-005 | Environment Dump     | ENV.to_h                        | Yes   | Yes   | Yes     | MEDIUM |
| LR-R-006 | Cloud Metadata       | Net::HTTP (169.254.169.254)     | Yes   | Yes   | Yes     | HIGH   |
| LR-R-007 | DNS Enumeration      | Resolv::DNS                     | Yes   | Yes   | Yes     | LOW    |
| LR-R-008 | Process Listing      | Dir['/proc/*/cmdline']          | Yes   | No    | No      | LOW    |
| LR-R-009 | Filesystem Recon     | Dir.glob / Find.find            | Yes   | Yes   | Yes     | LOW    |
| LR-R-010 | OS Fingerprinting    | RUBY_PLATFORM / RbConfig        | Yes   | Yes   | Yes     | LOW    |

### Credential Access Techniques

| ID       | Technique            | Ruby Method                     | Linux | macOS | Windows | Risk     |
|----------|----------------------|---------------------------------|-------|-------|---------|----------|
| LR-C-001 | Config File Harvest  | File.read / Dir.glob            | Yes   | Yes   | Partial | CRITICAL |
| LR-C-002 | Memory Scraping      | File.read('/proc/pid/maps')     | Yes   | No    | No      | CRITICAL |
| LR-C-003 | Shell History Read   | File.read('~/.bash_history')    | Yes   | Yes   | No      | HIGH     |
| LR-C-004 | SSH Key Discovery    | Dir.glob('~/.ssh/*')            | Yes   | Yes   | Partial | CRITICAL |
| LR-C-005 | Environment Secrets  | ENV.select (API keys, tokens)   | Yes   | Yes   | Yes     | CRITICAL |
| LR-C-006 | Database Cred Extract| YAML.load / JSON.parse configs  | Yes   | Yes   | Yes     | CRITICAL |
| LR-C-007 | Browser Data Access  | File.read (cookie/login DBs)    | Yes   | Yes   | Yes     | CRITICAL |
| LR-C-008 | Keyring/Keychain     | system('security find-*')       | No    | Yes   | No      | CRITICAL |

### Exfiltration Techniques

| ID       | Technique            | Ruby Method                     | Linux | macOS | Windows | Risk     |
|----------|----------------------|---------------------------------|-------|-------|---------|----------|
| LR-E-001 | DNS Exfiltration     | Resolv::DNS / UDPSocket         | Yes   | Yes   | Yes     | CRITICAL |
| LR-E-002 | HTTP/S Exfiltration  | Net::HTTP.post                  | Yes   | Yes   | Yes     | CRITICAL |
| LR-E-003 | ICMP Tunnel          | Socket (RAW_SOCK + ICMP)        | Yes   | Yes   | No      | CRITICAL |
| LR-E-004 | Steganography        | Pixel bit manipulation          | Yes   | Yes   | Yes     | CRITICAL |
| LR-E-005 | TCP Custom Protocol  | TCPSocket / TCPServer           | Yes   | Yes   | Yes     | HIGH     |
| LR-E-006 | File Encoding        | Base64.encode64 / Marshal.dump  | Yes   | Yes   | Yes     | MEDIUM   |
| LR-E-007 | Clipboard Exfil      | IO.popen('xclip') / pbcopy      | Yes   | Yes   | Yes     | MEDIUM   |
| LR-E-008 | Log Channel Exfil    | Logger / Syslog injection       | Yes   | Yes   | No      | HIGH     |

### Execution Techniques

| ID       | Technique            | Ruby Method                     | Linux | macOS | Windows | Risk   |
|----------|----------------------|---------------------------------|-------|-------|---------|--------|
| LR-X-001 | Eval Execution       | eval / instance_eval            | Yes   | Yes   | Yes     | HIGH   |
| LR-X-002 | Open3 Execution      | Open3.popen3 / capture3         | Yes   | Yes   | Yes     | HIGH   |
| LR-X-003 | Backtick Execution   | `cmd` / %x{cmd}                 | Yes   | Yes   | Yes     | HIGH   |
| LR-X-004 | System Execution     | system() / exec()               | Yes   | Yes   | Yes     | HIGH   |
| LR-X-005 | IO.popen Execution   | IO.popen('cmd')                 | Yes   | Yes   | Yes     | HIGH   |
| LR-X-006 | Process.spawn        | Process.spawn + wait            | Yes   | Yes   | Yes     | HIGH   |
| LR-X-007 | DRb Remote Exec      | DRb::DRbServer                  | Yes   | Yes   | Yes     | HIGH   |
| LR-X-008 | ERB Template Exec    | ERB.new(payload).result         | Yes   | Yes   | Yes     | HIGH   |
| LR-X-009 | Fiddle FFI Exec      | Fiddle::Function                | Yes   | Yes   | Yes     | HIGH   |
| LR-X-010 | Load/Require Exec    | load / require (remote)         | Yes   | Yes   | Yes     | HIGH   |

### Persistence Techniques

| ID       | Technique            | Ruby Method                     | Linux | macOS | Windows | Risk   |
|----------|----------------------|---------------------------------|-------|-------|---------|--------|
| LR-P-001 | Cron Job Install     | File.write crontab              | Yes   | Yes   | No      | HIGH   |
| LR-P-002 | Bashrc Injection     | File.open('~/.bashrc', 'a')     | Yes   | Yes   | No      | HIGH   |
| LR-P-003 | Gem Backdoor         | Gem::Specification modification | Yes   | Yes   | Yes     | HIGH   |
| LR-P-004 | Systemd Service      | File.write unit file            | Yes   | No    | No      | HIGH   |
| LR-P-005 | LaunchAgent Install  | Plist generation                | No    | Yes   | No      | HIGH   |
| LR-P-006 | Ruby Init Hook       | .irbrc / .pryrc injection      | Yes   | Yes   | Yes     | MEDIUM |
| LR-P-007 | Rake Task Backdoor   | Rakefile modification           | Yes   | Yes   | Yes     | MEDIUM |
| LR-P-008 | Bundler Hook         | .bundle/config manipulation     | Yes   | Yes   | Yes     | MEDIUM |

### Defense Evasion Techniques

| ID       | Technique            | Ruby Method                     | Linux | macOS | Windows | Risk   |
|----------|----------------------|---------------------------------|-------|-------|---------|--------|
| LR-D-001 | Log Cleaning         | File.write / truncate           | Yes   | Yes   | Partial | HIGH   |
| LR-D-002 | Timestamp Stomping   | File.utime                      | Yes   | Yes   | Yes     | MEDIUM |
| LR-D-003 | Process Renaming     | $0 = 'name' / prctl            | Yes   | Yes   | No      | MEDIUM |
| LR-D-004 | Code Obfuscation     | Base64 + eval / Marshal         | Yes   | Yes   | Yes     | MEDIUM |
| LR-D-005 | Memory-Only Exec     | eval(Net::HTTP.get(...))        | Yes   | Yes   | Yes     | HIGH   |
| LR-D-006 | Signal Handling      | Signal.trap masking             | Yes   | Yes   | Partial | LOW    |
| LR-D-007 | Anti-Debug           | Trace point detection           | Yes   | Yes   | Yes     | LOW    |
| LR-D-008 | Environment Cleanup  | ENV.delete / sanitization       | Yes   | Yes   | Yes     | LOW    |

## Risk Summary by Tactic

| Tactic            | Total Techniques | Critical | High | Medium | Low |
|-------------------|-----------------|----------|------|--------|-----|
| Reconnaissance    | 10              | 0        | 1    | 1      | 8   |
| Credential Access | 8               | 6        | 1    | 0      | 1   |
| Exfiltration      | 8               | 4        | 2    | 2      | 0   |
| Execution         | 10              | 0        | 10   | 0      | 0   |
| Persistence       | 8               | 0        | 4    | 4      | 0   |
| Defense Evasion   | 8               | 0        | 2    | 3      | 3   |
| **Total**         | **52**          | **10**   | **20**| **10** | **12** |

## Platform Coverage

| Platform | Supported Techniques | Coverage |
|----------|---------------------|----------|
| Linux    | 50/52               | 96%      |
| macOS    | 47/52               | 90%      |
| Windows  | 37/52               | 71%      |
