# RubyGuardian -- GDB Command File for Ruby Memory Forensics
#
# Load this file in GDB to set up the Ruby forensics environment:
#   gdb -x commands.gdb -p <ruby_pid>
#   gdb -x commands.gdb <core_file>
#
# Prerequisites:
#   - Ruby built with debug symbols (or separate debuginfo installed)
#   - Python GDB scripts in the same directory

# ============================================================
# Environment Setup
# ============================================================

# Disable pagination for scripted output
set pagination off

# Increase print limits for complex Ruby structures
set print elements 2000
set print pretty on
set print array on

# Don't stop on SIGPIPE (Ruby uses this internally)
handle SIGPIPE nostop noprint pass

# Don't stop on SIGUSR1/SIGUSR2 (Ruby uses these for thread control)
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass

# Set a reasonable command timeout for long-running scans
set remotetimeout 30

# ============================================================
# Load Python GDB Extension Scripts
# ============================================================

source ruby_heap_inspector.py
source ruby_stack_walker.py

# ============================================================
# Convenience Functions for Ruby Forensics
# ============================================================

# Print the current Ruby VM state
define ruby-vm-info
  printf "[RubyGuardian] Ruby VM Information\n"
  printf "==================================\n"

  # Try to access the Ruby VM global
  set $vm = ruby_current_vm_ptr
  if $vm != 0
    printf "  VM Address:       %p\n", $vm
    printf "  Running:          %d\n", $vm->ractor.cnt
    printf "  Living threads:   %d\n", $vm->living_thread_num
  else
    printf "  ERROR: Could not locate Ruby VM pointer\n"
    printf "  Ensure the process has Ruby debug symbols\n"
  end
  printf "==================================\n"
end

document ruby-vm-info
Display basic Ruby VM information including ractor and thread counts.
end

# Print Ruby version string from memory
define ruby-version
  printf "[RubyGuardian] Detecting Ruby version...\n"
  set $ver = ruby_version
  if $ver != 0
    printf "  Ruby version: %s\n", $ver
  else
    printf "  Could not determine Ruby version\n"
  end
  set $desc = ruby_description
  if $desc != 0
    printf "  Description:  %s\n", $desc
  end
end

document ruby-version
Print the Ruby version string from the running process.
end

# Inspect a specific Ruby VALUE
define ruby-inspect
  if $argc != 1
    printf "Usage: ruby-inspect <VALUE_address>\n"
  else
    set $val = (unsigned long long)$arg0
    set $flags = *(unsigned long long *)$val
    set $type_id = $flags & 0x1f
    set $klass = *(unsigned long long *)($val + 8)

    printf "[RubyGuardian] Inspecting VALUE at %p\n", $val
    printf "  Flags:     0x%016llx\n", $flags
    printf "  Type ID:   0x%02x", $type_id

    # Print type name
    if $type_id == 0x00
      printf " (T_NONE)\n"
    end
    if $type_id == 0x01
      printf " (T_OBJECT)\n"
    end
    if $type_id == 0x02
      printf " (T_CLASS)\n"
    end
    if $type_id == 0x03
      printf " (T_MODULE)\n"
    end
    if $type_id == 0x05
      printf " (T_STRING)\n"
      # Try to print string content
      set $noembed = $flags & (1 << 13)
      if $noembed
        set $str_len = *(long long *)($val + 16)
        set $str_ptr = *(char **)($val + 24)
        printf "  Length:    %lld\n", $str_len
        if $str_ptr != 0 && $str_len > 0 && $str_len < 1024
          printf "  Content:   %s\n", $str_ptr
        end
      else
        set $embed_len = ($flags & 0x1f0000) >> 16
        printf "  Embed len: %d\n", $embed_len
        if $embed_len > 0 && $embed_len <= 24
          printf "  Content:   "
          output/s ($val + 16)
          printf "\n"
        end
      end
    end
    if $type_id == 0x07
      printf " (T_ARRAY)\n"
      set $arr_len = *(long long *)($val + 16)
      printf "  Length:    %lld\n", $arr_len
    end
    if $type_id == 0x08
      printf " (T_HASH)\n"
    end

    printf "  Class:     %p\n", $klass
    printf "  Frozen:    %d\n", ($flags >> 11) & 1
    printf "  Exivar:    %d\n", ($flags >> 12) & 1

    # Show raw bytes
    printf "  Raw data:\n"
    x/5gx $val
  end
end

document ruby-inspect
Inspect a Ruby VALUE at a given memory address, displaying type,
flags, and content for known types (String, Array, etc.).
Usage: ruby-inspect <address>
end

# Search memory for a string pattern
define ruby-search-string
  if $argc != 1
    printf "Usage: ruby-search-string \"pattern\"\n"
  else
    printf "[RubyGuardian] Searching for string pattern in heap...\n"
    find /1, (void *)$arg0, 0x7fffffffffff, $arg0
  end
end

document ruby-search-string
Search process memory for a string pattern. Useful for finding
eval payloads, URLs, shell commands, etc.
Usage: ruby-search-string "pattern"
end

# Dump all T_STRING values in a memory range
define ruby-dump-strings
  if $argc != 2
    printf "Usage: ruby-dump-strings <start_addr> <end_addr>\n"
  else
    set $addr = (unsigned long long)$arg0
    set $end = (unsigned long long)$arg1
    set $count = 0

    printf "[RubyGuardian] Dumping T_STRING values from %p to %p\n", $addr, $end

    while $addr < $end
      set $flags = *(unsigned long long *)$addr
      set $type_id = $flags & 0x1f

      if $type_id == 0x05 && $flags != 0
        set $noembed = $flags & (1 << 13)
        if $noembed
          set $slen = *(long long *)($addr + 16)
          set $sptr = *(char **)($addr + 24)
          if $sptr != 0 && $slen > 3 && $slen < 4096
            printf "  [%p] len=%lld: ", $addr, $slen
            output/s $sptr
            printf "\n"
            set $count = $count + 1
          end
        end
      end

      set $addr = $addr + 40
    end

    printf "\n  Found %d string objects\n", $count
  end
end

document ruby-dump-strings
Scan a memory range for T_STRING RValues and print their contents.
Useful for examining heap pages or specific memory regions.
Usage: ruby-dump-strings <start_address> <end_address>
end

# Check process memory map for suspicious regions
define ruby-check-maps
  printf "[RubyGuardian] Checking memory maps for anomalies...\n"
  shell cat /proc/$PPID/maps | grep -E 'rwx|/tmp/|/dev/shm/'
  printf "\n  Regions above (if any) are potentially suspicious:\n"
  printf "  - rwx: Writable+Executable (code injection)\n"
  printf "  - /tmp/: Code loaded from temp directory\n"
  printf "  - /dev/shm/: Shared memory (fileless malware)\n"
end

document ruby-check-maps
Examine /proc/PID/maps for suspicious memory regions such as
writable+executable segments, code loaded from /tmp, or /dev/shm.
end

# ============================================================
# Forensic Workflow Commands
# ============================================================

# Run a full forensic scan
define ruby-forensic-scan
  printf "\n"
  printf "================================================================\n"
  printf "  RubyGuardian -- Full Forensic Scan\n"
  printf "================================================================\n"
  printf "\n"

  ruby-version
  printf "\n"
  ruby-vm-info
  printf "\n"
  ruby-heap-summary
  printf "\n"
  ruby-heap-anomalies
  printf "\n"
  ruby-stack
  printf "\n"
  ruby-stack-eval-chain
  printf "\n"
  ruby-stack-detect-anomalies
  printf "\n"
  ruby-check-maps

  printf "\n"
  printf "================================================================\n"
  printf "  Scan Complete\n"
  printf "================================================================\n"
end

document ruby-forensic-scan
Run a comprehensive forensic scan of the Ruby process, including
VM state, heap analysis, stack walking, and memory map checks.
end

# ============================================================
# Initialization
# ============================================================

printf "\n"
printf "[RubyGuardian] Memory Forensics GDB Environment Loaded\n"
printf "  Available commands:\n"
printf "    ruby-version          - Show Ruby version\n"
printf "    ruby-vm-info          - Display VM state\n"
printf "    ruby-inspect <addr>   - Inspect a VALUE\n"
printf "    ruby-search-string    - Search for string pattern\n"
printf "    ruby-dump-strings     - Dump strings in range\n"
printf "    ruby-check-maps       - Check memory maps\n"
printf "    ruby-heap-summary     - Heap overview\n"
printf "    ruby-heap-page <addr> - Inspect heap page\n"
printf "    ruby-heap-anomalies   - Detect heap issues\n"
printf "    ruby-stack            - Ruby call stack\n"
printf "    ruby-stack-eval-chain - Find eval chains\n"
printf "    ruby-forensic-scan    - Full forensic scan\n"
printf "\n"
