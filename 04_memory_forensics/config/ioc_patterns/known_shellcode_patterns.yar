/*
 * RubyGuardian Phase 4 - Known Shellcode Patterns
 * ================================================
 * YARA rules for detecting known shellcode patterns in Ruby process memory.
 * These rules identify common shellcode techniques that may be injected into
 * Ruby processes through deserialization vulnerabilities, native extensions,
 * or memory corruption exploits.
 *
 * Educational Reference: These patterns are well-documented in public security
 * research and are used for defensive detection purposes only.
 */

import "pe"
import "elf"
import "math"

rule NopSled_x86 {
    meta:
        description = "Detects x86/x64 NOP sled patterns commonly used in heap spray and buffer overflow attacks"
        author = "RubyGuardian Research Team"
        severity = "high"
        category = "shellcode"
        reference = "Standard x86 NOP sled detection"

    strings:
        // Classic NOP sled (0x90 repeated)
        $nop_classic = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                         90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

        // Multi-byte NOP equivalents used to evade simple NOP detection
        $nop_xchg_eax = { 87 C0 87 C0 87 C0 87 C0 87 C0 87 C0 87 C0 87 C0 }

        // NOP with segment override prefix
        $nop_prefix = { 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 }

        // LEA-based NOP (lea eax, [eax+0])
        $nop_lea = { 8D 40 00 8D 40 00 8D 40 00 8D 40 00 }

    condition:
        any of them
}

rule Shellcode_LinuxExecve {
    meta:
        description = "Detects Linux x86_64 execve shellcode patterns for spawning shells"
        author = "RubyGuardian Research Team"
        severity = "critical"
        category = "shellcode"

    strings:
        // syscall number for execve (59 = 0x3b) loaded into rax
        $execve_setup = { 48 C7 C0 3B 00 00 00 }  // mov rax, 0x3b
        $execve_xor = { 48 31 C0 [0-4] B0 3B }     // xor rax,rax; ...; mov al, 0x3b

        // /bin/sh string pushed onto stack
        $binsh_push = { 68 2F 73 68 00 }           // push "/sh\0"
        $binsh_mov = { 48 BB 2F 62 69 6E 2F 73 68 } // mov rbx, "/bin/sh"

        // syscall instruction
        $syscall = { 0F 05 }

    condition:
        ($execve_setup or $execve_xor) and $syscall and (#syscall > 0)
}

rule Shellcode_ReverseShell {
    meta:
        description = "Detects reverse shell shellcode patterns (connect-back)"
        author = "RubyGuardian Research Team"
        severity = "critical"
        category = "shellcode"

    strings:
        // socket() syscall setup (Linux x86_64: syscall 41)
        $socket_call = { 48 C7 C0 29 00 00 00 }    // mov rax, 41 (socket)
        $socket_af_inet = { 48 C7 C7 02 00 00 00 }  // mov rdi, 2 (AF_INET)

        // connect() syscall (Linux x86_64: syscall 42)
        $connect_call = { 48 C7 C0 2A 00 00 00 }    // mov rax, 42 (connect)

        // dup2() for stdin/stdout/stderr redirection (Linux x86_64: syscall 33)
        $dup2_call = { 48 C7 C0 21 00 00 00 }       // mov rax, 33 (dup2)

        // Common sockaddr_in structure patterns
        $sockaddr = { 02 00 [2] [4] 00 00 00 00 00 00 00 00 }

    condition:
        ($socket_call or $socket_af_inet) and ($connect_call or $dup2_call)
}

rule Shellcode_Meterpreter_Stager {
    meta:
        description = "Detects Metasploit Meterpreter stager shellcode patterns"
        author = "RubyGuardian Research Team"
        severity = "critical"
        category = "shellcode"
        reference = "Common Meterpreter payload signatures"

    strings:
        // Meterpreter reverse_tcp stager patterns
        $meterpreter_header = { 4D 5A }  // MZ header in memory (reflective DLL)

        // API hashing used by Metasploit
        $api_hash_ror13 = { C1 CF 0D 01 C7 }  // ror ecx,0xd; add edi,ecx

        // WSAStartup hash
        $wsa_hash = { 60 6B 8A E0 }

        // VirtualAlloc pattern for RWX allocation
        $virtualalloc_rwx = { 68 40 00 00 00 [0-8] 68 00 10 00 00 }

    condition:
        2 of them
}

rule Shellcode_Encoded_XOR {
    meta:
        description = "Detects XOR-encoded shellcode with decoder stub"
        author = "RubyGuardian Research Team"
        severity = "high"
        category = "shellcode"

    strings:
        // Common XOR decoder stub patterns
        // xor byte [esi], key; inc esi; loop
        $xor_decoder_1 = { 80 36 ?? 46 E2 FA }
        // xor byte [edi], key; inc edi; dec ecx; jnz
        $xor_decoder_2 = { 80 37 ?? 47 49 75 F9 }
        // xor dword loop pattern
        $xor_decoder_3 = { 31 ?? 83 ?? 04 ?? ?? ?? }

        // fnstenv-based GetPC technique
        $getpc_fnstenv = { D9 EE D9 74 24 F4 }
        // call $+5 GetPC technique
        $getpc_call = { E8 00 00 00 00 (58 | 59 | 5A | 5B | 5D | 5E | 5F) }

    condition:
        any of ($xor_decoder_*) and any of ($getpc_*)
}

rule Shellcode_HeapSpray_Pattern {
    meta:
        description = "Detects heap spray patterns targeting Ruby process memory"
        author = "RubyGuardian Research Team"
        severity = "high"
        category = "exploitation"

    strings:
        // Repeated addresses commonly used in heap sprays (0x0c0c0c0c, 0x0d0d0d0d)
        $spray_0c = { 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C }
        $spray_0d = { 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D 0D }
        $spray_41 = { 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 }

    condition:
        // More than 256 occurrences suggests spray rather than legitimate data
        for any of them : (# > 256)
}

rule Shellcode_StackPivot {
    meta:
        description = "Detects stack pivot gadgets used in ROP chains"
        author = "RubyGuardian Research Team"
        severity = "high"
        category = "exploitation"

    strings:
        // xchg eax, esp; ret
        $pivot_xchg_esp = { 94 C3 }
        // mov esp, eax; ret
        $pivot_mov_esp = { 89 C4 C3 }
        // leave; ret (stack pivot via saved EBP)
        $pivot_leave = { C9 C3 }
        // pop rsp; ret (x86_64)
        $pivot_pop_rsp = { 5C C3 }

    condition:
        // These are common instructions, so require proximity to other shellcode indicators
        2 of them in (0..256)
}

rule Shellcode_Syscall_Sequence {
    meta:
        description = "Detects suspicious Linux syscall sequences outside of libc"
        author = "RubyGuardian Research Team"
        severity = "medium"
        category = "shellcode"

    strings:
        // Multiple syscall instructions in close proximity
        $syscall = { 0F 05 }
        // int 0x80 (32-bit Linux syscall)
        $int80 = { CD 80 }

    condition:
        // 5+ syscalls within 512 bytes is suspicious outside libc
        #syscall > 5 in (0..512) or #int80 > 5 in (0..512)
}

rule Shellcode_ProcessInjection_Linux {
    meta:
        description = "Detects patterns associated with Linux process injection via ptrace or /proc/pid/mem"
        author = "RubyGuardian Research Team"
        severity = "critical"
        category = "injection"

    strings:
        // ptrace PTRACE_ATTACH (16) syscall
        $ptrace_attach = { 48 C7 C7 10 00 00 00 [0-16] 48 C7 C0 65 00 00 00 0F 05 }

        // /proc/self/mem or /proc/*/mem path strings
        $proc_mem = "/proc/self/mem"
        $proc_mem_pid = /\/proc\/\d+\/mem/

        // mmap with PROT_EXEC
        $mmap_exec = { 48 C7 C0 09 00 00 00 [0-32] BA 07 00 00 00 }  // mmap with PROT_READ|WRITE|EXEC

    condition:
        any of them
}

rule Ruby_Marshal_Shellcode_Injection {
    meta:
        description = "Detects shellcode delivered via Ruby Marshal.load deserialization"
        author = "RubyGuardian Research Team"
        severity = "critical"
        category = "ruby_specific"
        reference = "CVE-2013-0156 and similar Ruby deserialization attacks"

    strings:
        // Ruby Marshal header followed by suspicious patterns
        $marshal_header = { 04 08 }  // Marshal format version 4.8

        // ERB template injection via Marshal
        $erb_injection = { 04 08 6F 3A [1-4] 45 52 42 }

        // Marshal + system/exec call patterns
        $marshal_system = { 04 08 [0-64] 73 79 73 74 65 6D }  // "system" near marshal data
        $marshal_exec = { 04 08 [0-64] 60 }  // backtick exec near marshal data

    condition:
        $marshal_header and any of ($erb_injection, $marshal_system, $marshal_exec)
}
