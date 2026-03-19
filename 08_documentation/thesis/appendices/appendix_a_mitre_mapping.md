# Appendix A: MITRE ATT&CK Mapping

## A.1 Overview

This appendix provides a complete mapping between RubyGuardian's detection capabilities and the MITRE ATT&CK framework (version 14). Each entry includes the technique ID, name, associated tactic, RubyGuardian detection rule IDs, and detection methodology.

## A.2 Tactic Coverage Matrix

| Tactic                  | ID     | Techniques Covered | Coverage |
|-------------------------|--------|--------------------|----------|
| Reconnaissance          | TA0043 | 1                  | Partial  |
| Initial Access          | TA0001 | 2                  | Partial  |
| Execution               | TA0002 | 3                  | High     |
| Persistence             | TA0003 | 2                  | Moderate |
| Privilege Escalation    | TA0004 | 2                  | Moderate |
| Defense Evasion         | TA0005 | 4                  | High     |
| Credential Access       | TA0006 | 2                  | Moderate |
| Discovery               | TA0007 | 3                  | Moderate |
| Lateral Movement        | TA0008 | 1                  | Low      |
| Collection              | TA0009 | 2                  | Moderate |
| Command and Control     | TA0011 | 3                  | High     |
| Exfiltration            | TA0010 | 2                  | High     |
| Impact                  | TA0040 | 1                  | Low      |

## A.3 Detailed Technique Mapping

### A.3.1 Execution (TA0002)

#### T1059.005 - Command and Scripting Interpreter: Ruby

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-001, RG-002, RG-003                                  |
| **Detection**     | Signature + ML                                           |
| **Description**   | Detects execution of Ruby code via eval(), system(), exec(), and backtick operators with suspicious arguments |
| **Data Sources**  | Process command line, syscall trace (execve)              |
| **Severity**      | High                                                     |
| **False Positive**| Legitimate metaprogramming frameworks (e.g., Rails)      |
| **Mitigation**    | Input validation, sandboxed eval environments            |

#### T1106 - Native API

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-010, RG-011                                          |
| **Detection**     | Signature + Behavioral                                   |
| **Description**   | Detects Ruby processes using FFI or Fiddle to call native system APIs directly |
| **Data Sources**  | Shared library loads, syscall trace                      |
| **Severity**      | Medium-High                                              |

#### T1053.003 - Scheduled Task/Job: Cron

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-015                                                  |
| **Detection**     | Signature                                                |
| **Description**   | Detects Ruby processes creating or modifying cron entries |
| **Data Sources**  | File write events to /etc/cron*, /var/spool/cron         |
| **Severity**      | Medium                                                   |

### A.3.2 Defense Evasion (TA0005)

#### T1055.012 - Process Injection: Process Hollowing

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-004, RG-005                                          |
| **Detection**     | Signature + ML + Forensics                               |
| **Description**   | Detects ptrace-based process hollowing where a Ruby process attaches to another process, unmaps memory regions, and writes new code |
| **Data Sources**  | Syscall trace (ptrace, mmap, munmap), memory regions     |
| **Severity**      | Critical                                                 |
| **Key Features**  | ptrace_syscall_count, mmap_exec_calls                    |

#### T1055.001 - Process Injection: Dynamic-link Library Injection

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-006                                                  |
| **Detection**     | Signature + Behavioral                                   |
| **Description**   | Detects Ruby processes loading unexpected shared libraries via dlopen |
| **Data Sources**  | Syscall trace (open, mmap), /proc/pid/maps               |
| **Severity**      | High                                                     |

#### T1027 - Obfuscated Files or Information

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-007, RG-008                                          |
| **Detection**     | ML (primary), Signature (secondary)                      |
| **Description**   | Detects obfuscated Ruby code using Base64, XOR, string splitting, and polymorphic encoding |
| **Data Sources**  | Process command line, code content analysis               |
| **Severity**      | Medium-High                                              |
| **Key Features**  | syscall_sequence_entropy, command_line_entropy            |

#### T1140 - Deobfuscate/Decode Files or Information

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-009                                                  |
| **Detection**     | Behavioral                                               |
| **Description**   | Detects runtime deobfuscation patterns (Base64.decode64, XOR loops) |
| **Data Sources**  | Syscall trace, memory write patterns                     |
| **Severity**      | Medium                                                   |

### A.3.3 Command and Control (TA0011)

#### T1071.001 - Application Layer Protocol: Web Protocols

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-020, RG-021                                          |
| **Detection**     | Signature + ML                                           |
| **Description**   | Detects Ruby processes establishing HTTP/HTTPS connections to suspicious destinations |
| **Data Sources**  | Network connections, DNS queries, TLS handshakes         |
| **Severity**      | Medium-High                                              |
| **Key Features**  | unique_outbound_ips, connect_to_nonstandard_ports        |

#### T1071.004 - Application Layer Protocol: DNS

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-022, RG-023                                          |
| **Detection**     | Signature + ML + Behavioral                              |
| **Description**   | Detects DNS tunneling and DNS-based C2 communication from Ruby processes |
| **Data Sources**  | DNS queries, network traffic                             |
| **Severity**      | High                                                     |
| **Key Features**  | dns_query_entropy, dns_query_frequency                   |

#### T1573.001 - Encrypted Channel: Symmetric Cryptography

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-024                                                  |
| **Detection**     | Behavioral                                               |
| **Description**   | Detects use of OpenSSL encryption APIs in unexpected contexts |
| **Data Sources**  | Library calls, syscall patterns                          |
| **Severity**      | Medium                                                   |

### A.3.4 Exfiltration (TA0010)

#### T1041 - Exfiltration Over C2 Channel

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-030, RG-031                                          |
| **Detection**     | ML + Behavioral                                          |
| **Description**   | Detects data exfiltration over established C2 channels   |
| **Data Sources**  | Network bytes, connection patterns                       |
| **Severity**      | Critical                                                 |
| **Key Features**  | bytes_sent_received_ratio, outbound_data_volume          |

#### T1048.003 - Exfiltration Over Alternative Protocol: DNS

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-032                                                  |
| **Detection**     | Signature + ML                                           |
| **Description**   | Detects data encoded in DNS subdomain labels for exfiltration |
| **Data Sources**  | DNS query content, subdomain entropy                     |
| **Severity**      | Critical                                                 |

### A.3.5 Discovery (TA0007)

#### T1082 - System Information Discovery

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-040                                                  |
| **Detection**     | Behavioral                                               |
| **Description**   | Detects Ruby processes gathering system information (uname, /proc/cpuinfo, /etc/os-release) |
| **Data Sources**  | File read events, command execution                      |
| **Severity**      | Low-Medium                                               |

#### T1083 - File and Directory Discovery

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-041                                                  |
| **Detection**     | Behavioral + ML                                          |
| **Description**   | Detects enumeration of filesystem contents beyond normal application scope |
| **Data Sources**  | Syscall trace (opendir, readdir, stat)                   |
| **Severity**      | Low-Medium                                               |

#### T1057 - Process Discovery

| Attribute         | Value                                                    |
|-------------------|----------------------------------------------------------|
| **Rule IDs**      | RG-042                                                  |
| **Detection**     | Signature                                                |
| **Description**   | Detects enumeration of running processes via /proc or ps command |
| **Data Sources**  | File reads to /proc/*/status, process execution          |
| **Severity**      | Low                                                      |

## A.4 Detection Gap Analysis

The following MITRE ATT&CK techniques are relevant to Ruby runtime attacks but are not currently covered by RubyGuardian:

| Technique ID | Name                            | Gap Reason                         |
|--------------|---------------------------------|------------------------------------|
| T1195.001    | Supply Chain: Compromise Deps   | Requires pre-execution analysis    |
| T1620        | Reflective Code Loading         | Requires deeper Ruby VM hooks      |
| T1497        | Virtualization Evasion          | Low relevance for Ruby attacks     |
| T1222        | File Permission Modification    | Planned for future release         |

## A.5 ATT&CK Navigator Layer

A machine-readable ATT&CK Navigator layer file is available at:
`06_dashboard/elk_stack/kibana/dashboards/attack_timeline.ndjson`

This layer can be imported into the MITRE ATT&CK Navigator tool to visualize RubyGuardian's detection coverage against the full ATT&CK matrix.
