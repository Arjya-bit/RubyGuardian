# RubyGuardian Phase 4 - Memory Forensics Toolkit

## Overview

The Memory Forensics Toolkit provides comprehensive capabilities for analyzing Ruby
process memory dumps to detect malware, reconstruct attack timelines, and extract
indicators of compromise (IOCs). This module bridges the gap between traditional
memory forensics tools and the Ruby-specific internals needed to investigate
incidents involving Ruby applications.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Memory Forensics Toolkit                  │
├─────────────┬──────────────┬──────────────┬─────────────────┤
│  Acquisition│   Analysis   │ Reconstruction│   Reporting    │
│             │              │               │                │
│ memory_     │ heap_        │ objectspace_  │ report_        │
│  dumper.rb  │  analyzer.rb │  reconstructor│  generator.rb  │
│             │              │   .rb         │                │
│ Volatility  │ ruby_vm_     │ code_         │ timeline_      │
│  Plugins    │  parser.rb   │  reconstructor│  builder.rb    │
│             │              │   .rb         │                │
│ GDB Scripts │ ioc_         │ deobfuscator  │                │
│             │  scanner.rb  │   .rb         │                │
│             │              │               │                │
│             │ string_      │ network_      │                │
│             │  extractor.rb│  artifact_    │                │
│             │              │  extractor.rb │                │
│             │ dump_        │               │                │
│             │  parser.rb   │               │                │
└─────────────┴──────────────┴──────────────┴─────────────────┘
```

## Components

### Memory Acquisition
- **memory_dumper.rb** - Captures memory dumps from live Ruby processes using
  `/proc/<pid>/mem`, `gcore`, or platform-specific APIs
- **Volatility Plugins** - Custom plugins for the Volatility framework to parse
  Ruby-specific memory structures
- **GDB Scripts** - Automated GDB scripts for live debugging and heap inspection

### Memory Analysis
- **dump_parser.rb** - Parses raw memory dumps and identifies Ruby VM structures
- **ruby_vm_parser.rb** - Interprets Ruby VM internal data (RVALUEs, heap pages,
  instruction sequences)
- **heap_analyzer.rb** - Analyzes Ruby heap layout, detects anomalies, and identifies
  suspicious allocations
- **ioc_scanner.rb** - Scans memory for known indicators of compromise using YARA
  rules and pattern matching
- **string_extractor.rb** - Extracts and categorizes strings from memory dumps

### Reconstruction
- **objectspace_reconstructor.rb** - Rebuilds the Ruby ObjectSpace from raw memory,
  recovering object relationships
- **code_reconstructor.rb** - Recovers Ruby source code from instruction sequences
  found in memory
- **deobfuscator.rb** - Reverses common Ruby obfuscation techniques found in malware
- **network_artifact_extractor.rb** - Recovers network-related artifacts (URLs, IPs,
  DNS queries, socket structures)

### Reporting
- **timeline_builder.rb** - Constructs forensic timelines from memory artifacts
- **report_generator.rb** - Generates comprehensive forensic reports in multiple formats

## Quick Start

### Prerequisites

```bash
# Install Ruby dependencies
bundle install

# Install Python dependencies (for Volatility plugins)
pip install -r requirements.txt

# Install system dependencies
sudo apt-get install gdb volatility3 yara
```

### Capture a Memory Dump

```bash
# From a live Ruby process
./scripts/capture_memory_dump.sh <PID>

# Or programmatically
ruby -e "
  require_relative 'lib/memory_dumper'
  dumper = RubyGuardian::MemoryForensics::MemoryDumper.new(pid: 12345)
  dumper.capture(output: 'sample_dumps/incident_001.dmp')
"
```

### Run Full Analysis

```bash
ruby scripts/run_full_analysis.rb --dump sample_dumps/incident_001.dmp --output reports/
```

### Generate Report

```bash
ruby scripts/generate_report.rb --analysis-dir reports/ --format html
```

## Case Studies

- **Case 001: CI/CD Pipeline Poisoning** - Analysis of a compromised Bundler gem
  that injected malicious code during builds
- **Case 002: ObjectSpace Hiding** - Investigation of malware that manipulated
  ObjectSpace to hide its objects from inspection
- **Case 003: Process Hollowing** - Forensic analysis of a Ruby process that was
  hollowed out and replaced with a cryptominer

## Configuration

Edit `config/forensics_config.yml` to customize:
- Memory dump acquisition settings
- Analysis thresholds and heuristics
- YARA rule paths
- Report output formats
- Volatility profile locations

## Testing

```bash
# Run Ruby specs
bundle exec rspec specs/

# Run Python plugin tests
pytest specs/integration/volatility_plugin_spec.py

# Run integration tests
bundle exec rspec specs/integration/
```

## Educational Notes

This toolkit demonstrates several important forensic concepts:

1. **Memory acquisition** must be performed carefully to minimize alteration of the
   target process state
2. **Ruby VM internals** (RVALUE unions, heap page structures, instruction sequences)
   are essential knowledge for Ruby-specific forensics
3. **Chain of custody** is maintained through cryptographic hashing of all evidence
4. **Timeline reconstruction** from memory artifacts provides crucial context for
   incident response
5. **IOC extraction** from memory often reveals artifacts that disk-based forensics
   would miss

## License

Part of the RubyGuardian security research project. For educational and authorized
security testing purposes only.
