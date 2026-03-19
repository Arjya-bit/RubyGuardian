# Case 001: CI/CD Pipeline Poisoning via Malicious Gem Dependency

## Summary

A supply chain attack was discovered in a production Ruby on Rails application
where a compromised gem dependency injected a backdoor during CI/CD pipeline
execution. The attacker modified the `post_install` hook of a popular gem's
transitive dependency to execute arbitrary code during `bundle install`.

## Timeline

- **T-30d**: Attacker creates typosquatted gem `activesupport-utils` on
  rubygems.org, closely mimicking the real `activesupport` gem.
- **T-14d**: Attacker publishes version 7.0.8.1 with a malicious `extconf.rb`
  that downloads and executes a second-stage payload during gem installation.
- **T-7d**: A developer adds `activesupport-utils` to the Gemfile by mistake
  (autocomplete error). The CI/CD pipeline installs and executes the payload.
- **T-0**: Memory forensics reveals the injected code persists in the Ruby
  heap as a set of `T_STRING` objects containing Base64-encoded shell commands.

## Memory Forensic Findings

### Heap Analysis

The memory dump of the CI runner process (PID 14823) was captured using
`capture_memory_dump.sh` and analyzed with the RubyGuardian toolkit.

1. **Anomalous String Distribution**: 87.3% of heap objects were `T_STRING`
   (normal ratio is 30-45%). This was caused by the payload decoding loop
   creating thousands of intermediate string objects.

2. **Base64 Payload Strings**: 342 unique Base64-encoded strings were found
   in the heap, averaging 1,847 bytes each. When decoded, they contained:
   - Shell commands to exfiltrate environment variables (`ENV['SECRET_KEY_BASE']`)
   - A reverse shell connecting to `198.51.100.47:4444`
   - A script to modify `config/database.yml` with attacker-controlled credentials

3. **ObjectSpace Anomaly**: 18 `T_DATA` objects were found in anonymous
   memory regions outside the normal Ruby heap. These contained native
   extension wrappers for a custom OpenSSL context used to establish C2
   communication over TLS.

### IOC Scan Results

- **YARA**: 4 rules matched (reverse_shell_pattern, base64_eval_chain,
  env_exfil_pattern, suspicious_native_ext)
- **Heuristic**: 12 hits for `eval_injection`, `shell_execution`, and
  `data_exfiltration` patterns
- **Credential**: AWS access key `AKIAIOSFODNN7EXAMPLE` found in heap memory

### Stack Analysis

The GDB stack walker revealed a 7-deep eval chain:
```
#0 eval -> #1 instance_eval -> #2 send -> #3 eval -> #4 system -> #5 exec
```
This chain originated from `activesupport-utils-7.0.8.1/lib/loader.rb:42`.

## Root Cause

The `extconf.rb` in the malicious gem executed during native extension
compilation. It downloaded a second-stage Ruby script from a compromised
CDN endpoint and eval'd the content. The payload persisted by monkey-patching
`Kernel#require` to re-inject itself on every subsequent require call.

## Recommendations

1. Pin all gem dependencies to exact versions with integrity hashes
2. Use `bundle install --frozen` in CI/CD to prevent lockfile modifications
3. Monitor CI/CD runner processes for anomalous memory patterns
4. Implement gem allowlisting in production environments
5. Deploy RubyGuardian memory forensics as a post-build verification step

## Evidence Artifacts

- Memory dump: `case_001_cicd_runner_14823.dump.gz` (SHA256: a1b2c3...)
- Strace log: `case_001_strace.log`
- Network capture: `case_001_network.pcap`
- Malicious gem source: `activesupport-utils-7.0.8.1.gem` (quarantined)
