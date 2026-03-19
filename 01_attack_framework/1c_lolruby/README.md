# Phase 1c - Living-off-the-Land Ruby (LoLRuby)

## Educational Security Research Framework

> **DISCLAIMER**: This module is strictly for educational and authorized security research
> purposes. All techniques documented here are intended to help defenders understand how
> Ruby's standard library and runtime can be abused, enabling better detection and prevention.
> Unauthorized use against systems you do not own or have explicit permission to test is
> illegal and unethical.

## Concept

**Living-off-the-Land Ruby (LoLRuby)** extends the "Living off the Land" (LotL) concept —
well-known from LOLBins and GTFOBins — into the Ruby ecosystem. The core idea: attackers
who gain access to a system with Ruby installed can leverage Ruby's powerful standard library
to perform reconnaissance, credential harvesting, lateral movement, exfiltration, and
persistence **without downloading additional tools**.

Ruby is particularly potent for LotL because:

1. **Rich standard library** — `Net::HTTP`, `Socket`, `OpenSSL`, `Open3`, `FileUtils`,
   `JSON`, `CSV`, `ERB`, `DRb`, and dozens more ship with every Ruby installation.
2. **One-liner capability** — `ruby -e '...'` allows complex operations in a single command.
3. **Eval-based execution** — `eval`, `instance_eval`, `class_eval`, `Binding#eval` provide
   dynamic code execution without touching disk.
4. **Process spawning** — At least 6 distinct methods to execute system commands:
   `system()`, backticks, `exec()`, `Open3.popen3()`, `IO.popen()`, `Process.spawn()`.
5. **Cross-platform** — Ruby runs on Linux, macOS, Windows, and BSDs with consistent APIs.
6. **Common in production** — Ruby is present on many servers due to Rails, Chef, Puppet,
   Vagrant, Homebrew, and other DevOps tools.

## GTFOBins Comparison

| Feature             | GTFOBins (Shell)       | LoLRuby                          |
|---------------------|------------------------|----------------------------------|
| Language            | Bash/sh utilities      | Ruby standard library            |
| Scope               | Individual binaries    | Full programming language        |
| Complexity          | Simple one-liners      | Simple to highly complex         |
| Network capability  | Limited (curl, wget)   | Full TCP/UDP/HTTP/DNS stack      |
| Crypto capability   | Rare                   | OpenSSL, Digest, Base64 built-in |
| Detection           | Well-studied           | Under-researched                 |
| File operations     | Shell redirects        | Full File/Dir/IO API             |
| Process control     | fork/exec              | 6+ spawning methods              |
| Eval / dynamic exec | `eval` in bash         | Multiple eval variants           |
| Data formats        | Text processing        | JSON, CSV, YAML, XML, Marshal    |

## Module Structure

```
1c_lolruby/
├── README.md                          # This file
├── docs/
│   ├── lolruby_matrix.md              # Technique x OS x Risk matrix
│   ├── mitre_attack_mapping.md        # MITRE ATT&CK technique mapping
│   └── real_world_examples.md         # Real-world incident references
├── techniques/
│   ├── reconnaissance/                # T1046, T1087, T1082, T1580
│   ├── credential_access/             # T1552, T1003, T1552.001
│   ├── exfiltration/                  # T1048, T1041, T1572
│   ├── execution/                     # T1059.002, T1106
│   ├── persistence/                   # T1053, T1546, T1505
│   └── defense_evasion/               # T1070, T1036, T1027
├── lolruby_database/                  # SQLite technique catalog
├── one_liners/
│   ├── benign_samples/                # Legitimate Ruby one-liners
│   └── malicious_samples/             # Malicious Ruby one-liners
└── specs/                             # RSpec tests
```

## Usage

```ruby
# Load a specific technique for study
require_relative 'techniques/reconnaissance/network_scan'

scanner = RubyGuardian::LoLRuby::Reconnaissance::NetworkScan.new
scanner.describe  # Print educational description

# Query the technique database
require_relative 'lolruby_database/query_interface'

db = RubyGuardian::LoLRuby::Database::QueryInterface.new
db.find_by_tactic('reconnaissance')
db.find_by_mitre_id('T1046')
```

## Detection Guidance

Each technique file includes specific detection recommendations. General approaches:

- **Process monitoring**: Watch for `ruby -e` invocations with suspicious arguments
- **Script analysis**: Scan `.rb` files for known malicious patterns
- **Network monitoring**: Alert on unexpected Ruby process network connections
- **File integrity**: Monitor for changes to `.bashrc`, crontabs, gem directories
- **Behavioral analysis**: Baseline normal Ruby usage patterns per environment

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [GTFOBins](https://gtfobins.github.io/)
- [LOLBins](https://lolbas-project.github.io/)
- [Ruby Standard Library Documentation](https://ruby-doc.org/stdlib/)
