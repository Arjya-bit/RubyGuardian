#!/usr/bin/env bash
# frozen_string_literal: true
#
# RubyGuardian Phase 4 - Memory Dump Capture Script
# Captures memory dumps from live Ruby processes for forensic analysis.
#
# Usage:
#   ./capture_memory_dump.sh --pid <pid>              # Capture specific process
#   ./capture_memory_dump.sh --name <process_name>    # Capture by process name
#   ./capture_memory_dump.sh --all-ruby               # Capture all Ruby processes
#
# Requirements:
#   - Root or ptrace-capable privileges
#   - gcore (gdb) or /proc filesystem access
#   - gzip or zstd for compression

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_FILE="${PROJECT_DIR}/config/forensics_config.yml"
OUTPUT_BASE="${PROJECT_DIR}/dumps"
LOG_DIR="${PROJECT_DIR}/logs"
TIMESTAMP="$(date -u +%Y%m%d_%H%M%S)"
LOG_FILE="${LOG_DIR}/capture_${TIMESTAMP}.log"

# Defaults
COMPRESS=true
COMPRESSION_TOOL="gzip"
HASH_ALGORITHMS=("sha256" "md5")
MAX_DUMP_SIZE=$((10 * 1024 * 1024 * 1024))  # 10 GB
PAUSE_PROCESS=true
TIMEOUT=300

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =============================================================================
# Logging
# =============================================================================

mkdir -p "$LOG_DIR"

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    echo "[${ts}] ${level} ${msg}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO " "$@"; }
log_warn() { log "WARN " "$@"; echo -e "${YELLOW}WARNING: $*${NC}" >&2; }
log_error() { log "ERROR" "$@"; echo -e "${RED}ERROR: $*${NC}" >&2; }
log_success() { log "INFO " "$@"; echo -e "${GREEN}$*${NC}"; }

# =============================================================================
# Utility Functions
# =============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        # Check if we have ptrace capability
        if ! capsh --print 2>/dev/null | grep -q "cap_sys_ptrace"; then
            log_warn "Not running as root and no ptrace capability. Some features may not work."
            log_info "Consider running with: sudo $0 $*"
        fi
    fi
}

check_dependencies() {
    local missing=()

    for cmd in stat date basename dirname; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done

    if [[ "$COMPRESS" == true ]]; then
        if command -v zstd &>/dev/null; then
            COMPRESSION_TOOL="zstd"
        elif command -v gzip &>/dev/null; then
            COMPRESSION_TOOL="gzip"
        else
            missing+=("gzip or zstd")
        fi
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing[*]}"
        exit 1
    fi

    # Check for acquisition tools
    if [[ ! -d /proc ]]; then
        log_warn "/proc filesystem not available. Using gcore method."
        if ! command -v gcore &>/dev/null; then
            log_error "Neither /proc nor gcore available. Cannot capture memory."
            exit 1
        fi
    fi
}

validate_pid() {
    local pid="$1"
    if [[ ! -d "/proc/${pid}" ]]; then
        log_error "Process ${pid} does not exist"
        return 1
    fi
    return 0
}

is_ruby_process() {
    local pid="$1"
    local cmdline
    cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "")"
    local exe
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "")"

    if [[ "$cmdline" == *ruby* ]] || [[ "$exe" == *ruby* ]]; then
        return 0
    fi
    return 1
}

get_process_info() {
    local pid="$1"
    local cmdline exe rss vms

    cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "unknown")"
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "unknown")"
    rss="$(awk '/VmRSS/ {print $2}' "/proc/${pid}/status" 2>/dev/null || echo "0")"
    vms="$(awk '/VmSize/ {print $2}' "/proc/${pid}/status" 2>/dev/null || echo "0")"

    echo "PID: ${pid}"
    echo "  Command: ${cmdline}"
    echo "  Executable: ${exe}"
    echo "  RSS: ${rss} kB"
    echo "  Virtual: ${vms} kB"
}

format_size() {
    local bytes="$1"
    if [[ "$bytes" -ge $((1024 * 1024 * 1024)) ]]; then
        echo "$(echo "scale=2; $bytes / 1073741824" | bc) GB"
    elif [[ "$bytes" -ge $((1024 * 1024)) ]]; then
        echo "$(echo "scale=2; $bytes / 1048576" | bc) MB"
    elif [[ "$bytes" -ge 1024 ]]; then
        echo "$(echo "scale=2; $bytes / 1024" | bc) KB"
    else
        echo "${bytes} B"
    fi
}

# =============================================================================
# Memory Capture Functions
# =============================================================================

capture_via_proc_mem() {
    local pid="$1"
    local output_path="$2"
    local mem_path="/proc/${pid}/mem"
    local maps_path="/proc/${pid}/maps"

    if [[ ! -r "$mem_path" ]]; then
        log_error "Cannot read ${mem_path}. Insufficient permissions."
        return 1
    fi

    log_info "Capturing memory via /proc/${pid}/mem"
    log_info "Reading memory maps from ${maps_path}"

    local region_count=0
    local total_bytes=0

    # Parse memory maps and dump readable regions
    while IFS= read -r line; do
        local range perms
        range="$(echo "$line" | awk '{print $1}')"
        perms="$(echo "$line" | awk '{print $2}')"

        # Skip non-readable regions
        if [[ "${perms:0:1}" != "r" ]]; then
            continue
        fi

        local start_hex end_hex
        start_hex="$(echo "$range" | cut -d'-' -f1)"
        end_hex="$(echo "$range" | cut -d'-' -f2)"

        local start_dec end_dec size
        start_dec=$((16#${start_hex}))
        end_dec=$((16#${end_hex}))
        size=$((end_dec - start_dec))

        total_bytes=$((total_bytes + size))
        if [[ "$total_bytes" -gt "$MAX_DUMP_SIZE" ]]; then
            log_warn "Dump size exceeds maximum ($(format_size $MAX_DUMP_SIZE)). Stopping."
            break
        fi

        # Read memory region using dd
        dd if="$mem_path" bs=1 skip="$start_dec" count="$size" \
            >> "$output_path" 2>/dev/null || true

        region_count=$((region_count + 1))
    done < "$maps_path"

    log_info "Captured ${region_count} memory regions ($(format_size $total_bytes))"
    return 0
}

capture_via_gcore() {
    local pid="$1"
    local output_path="$2"

    if ! command -v gcore &>/dev/null; then
        log_error "gcore not found. Install gdb package."
        return 1
    fi

    log_info "Capturing memory via gcore for PID ${pid}"

    local temp_dir
    temp_dir="$(mktemp -d)"
    local core_prefix="${temp_dir}/core"

    timeout "$TIMEOUT" gcore -o "$core_prefix" "$pid" 2>&1 | tee -a "$LOG_FILE"

    local core_file
    core_file="$(find "$temp_dir" -name "core.*" -type f 2>/dev/null | head -1)"

    if [[ -z "$core_file" || ! -f "$core_file" ]]; then
        log_error "gcore failed to produce a core file"
        rm -rf "$temp_dir"
        return 1
    fi

    mv "$core_file" "$output_path"
    rm -rf "$temp_dir"

    log_info "gcore capture complete: $(format_size "$(stat -c%s "$output_path")")"
    return 0
}

# =============================================================================
# Post-Capture Processing
# =============================================================================

compress_dump() {
    local input_path="$1"
    local compressed_path

    case "$COMPRESSION_TOOL" in
        zstd)
            compressed_path="${input_path}.zst"
            log_info "Compressing with zstd..."
            zstd -T0 -9 "$input_path" -o "$compressed_path" 2>&1 | tee -a "$LOG_FILE"
            ;;
        gzip)
            compressed_path="${input_path}.gz"
            log_info "Compressing with gzip..."
            gzip -9 -c "$input_path" > "$compressed_path"
            ;;
        *)
            log_warn "Unknown compression tool: ${COMPRESSION_TOOL}. Skipping compression."
            echo "$input_path"
            return
            ;;
    esac

    local orig_size comp_size ratio
    orig_size="$(stat -c%s "$input_path")"
    comp_size="$(stat -c%s "$compressed_path")"
    ratio="$(echo "scale=1; $comp_size * 100 / $orig_size" | bc 2>/dev/null || echo "?")"

    log_info "Compressed: $(format_size "$orig_size") -> $(format_size "$comp_size") (${ratio}%)"

    rm -f "$input_path"
    echo "$compressed_path"
}

compute_hashes() {
    local file_path="$1"
    local meta_file="${file_path}.hashes"

    log_info "Computing integrity hashes..."

    echo "# RubyGuardian Memory Dump Hashes" > "$meta_file"
    echo "# File: $(basename "$file_path")" >> "$meta_file"
    echo "# Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$meta_file"
    echo "" >> "$meta_file"

    for algo in "${HASH_ALGORITHMS[@]}"; do
        local hash_cmd
        case "$algo" in
            sha256) hash_cmd="sha256sum" ;;
            md5)    hash_cmd="md5sum" ;;
            sha1)   hash_cmd="sha1sum" ;;
            *)      log_warn "Unknown hash algorithm: ${algo}"; continue ;;
        esac

        if command -v "$hash_cmd" &>/dev/null; then
            local hash_value
            hash_value="$($hash_cmd "$file_path" | awk '{print $1}')"
            echo "${algo}: ${hash_value}" >> "$meta_file"
            log_info "${algo}: ${hash_value}"
        fi
    done
}

write_metadata() {
    local file_path="$1"
    local pid="$2"
    local method="$3"
    local meta_file="${file_path}.meta.json"

    local cmdline exe ruby_version file_size
    cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || echo "N/A")"
    exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || echo "N/A")"
    ruby_version="$($exe --version 2>/dev/null || echo "unknown")"
    file_size="$(stat -c%s "$file_path" 2>/dev/null || echo 0)"

    cat > "$meta_file" <<EOF
{
  "magic": "RGMEM",
  "version": 1,
  "acquisition": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "pid": ${pid},
    "method": "${method}",
    "host": "$(hostname)",
    "operator": "$(whoami)"
  },
  "process": {
    "cmdline": "$(echo "$cmdline" | sed 's/"/\\"/g')",
    "executable": "${exe}",
    "ruby_version": "$(echo "$ruby_version" | sed 's/"/\\"/g')"
  },
  "dump": {
    "file": "$(basename "$file_path")",
    "size": ${file_size},
    "compressed": ${COMPRESS}
  },
  "tool": {
    "name": "RubyGuardian Memory Forensics",
    "version": "4.0.0"
  }
}
EOF

    log_info "Metadata written to ${meta_file}"
}

# =============================================================================
# Main Capture Orchestration
# =============================================================================

capture_process() {
    local pid="$1"

    if ! validate_pid "$pid"; then
        return 1
    fi

    log_info "========================================="
    log_info "Capturing memory dump for PID ${pid}"
    log_info "========================================="
    get_process_info "$pid" | while IFS= read -r line; do log_info "$line"; done

    local output_dir="${OUTPUT_BASE}/pid${pid}_${TIMESTAMP}"
    mkdir -p "$output_dir"
    local raw_path="${output_dir}/memory_pid${pid}.raw"

    # Pause process for consistent snapshot
    if [[ "$PAUSE_PROCESS" == true ]]; then
        log_info "Pausing process ${pid} (SIGSTOP)"
        kill -STOP "$pid" 2>/dev/null || log_warn "Could not pause process"
    fi

    local capture_method="proc_mem"
    local capture_start
    capture_start="$(date +%s%N)"

    # Try /proc/mem first, fall back to gcore
    if [[ -r "/proc/${pid}/mem" ]]; then
        capture_via_proc_mem "$pid" "$raw_path" || {
            log_warn "proc_mem capture failed. Trying gcore..."
            capture_method="gcore"
            capture_via_gcore "$pid" "$raw_path"
        }
    else
        capture_method="gcore"
        capture_via_gcore "$pid" "$raw_path"
    fi

    # Resume process
    if [[ "$PAUSE_PROCESS" == true ]]; then
        log_info "Resuming process ${pid} (SIGCONT)"
        kill -CONT "$pid" 2>/dev/null || true
    fi

    local capture_end
    capture_end="$(date +%s%N)"
    local duration_ms=$(( (capture_end - capture_start) / 1000000 ))
    log_info "Capture duration: ${duration_ms}ms"

    if [[ ! -f "$raw_path" ]]; then
        log_error "No dump file produced for PID ${pid}"
        return 1
    fi

    # Post-processing
    local final_path="$raw_path"
    if [[ "$COMPRESS" == true ]]; then
        final_path="$(compress_dump "$raw_path")"
    fi

    compute_hashes "$final_path"
    write_metadata "$final_path" "$pid" "$capture_method"

    log_success "Dump saved: ${final_path}"
    log_success "Size: $(format_size "$(stat -c%s "$final_path")")"
    echo "$final_path"
}

# =============================================================================
# CLI Argument Parsing
# =============================================================================

usage() {
    cat <<EOF
${BLUE}RubyGuardian Memory Forensics - Memory Dump Capture${NC}

Usage: $(basename "$0") [OPTIONS]

Options:
  -p, --pid PID           Capture memory from specific process ID
  -n, --name NAME         Capture memory from process matching name
  -a, --all-ruby          Capture all Ruby processes
  -o, --output DIR        Output directory (default: ${OUTPUT_BASE})
  -c, --no-compress       Disable compression
  -P, --no-pause          Do not pause process during capture
  -t, --timeout SECS      Acquisition timeout (default: ${TIMEOUT}s)
  -h, --help              Show this help message

Examples:
  $(basename "$0") --pid 12345
  $(basename "$0") --name "puma"
  $(basename "$0") --all-ruby --output /mnt/evidence/dumps

EOF
    exit 0
}

TARGET_PID=""
TARGET_NAME=""
ALL_RUBY=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -p|--pid)     TARGET_PID="$2"; shift 2 ;;
        -n|--name)    TARGET_NAME="$2"; shift 2 ;;
        -a|--all-ruby) ALL_RUBY=true; shift ;;
        -o|--output)  OUTPUT_BASE="$2"; shift 2 ;;
        -c|--no-compress) COMPRESS=false; shift ;;
        -P|--no-pause) PAUSE_PROCESS=false; shift ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -h|--help)    usage ;;
        *)            log_error "Unknown option: $1"; usage ;;
    esac
done

# =============================================================================
# Main
# =============================================================================

main() {
    echo -e "${BLUE}======================================${NC}"
    echo -e "${BLUE}RubyGuardian Memory Dump Capture${NC}"
    echo -e "${BLUE}======================================${NC}"

    check_root
    check_dependencies

    mkdir -p "$OUTPUT_BASE"

    local captured=0

    if [[ -n "$TARGET_PID" ]]; then
        capture_process "$TARGET_PID" && captured=$((captured + 1))

    elif [[ -n "$TARGET_NAME" ]]; then
        log_info "Searching for processes matching: ${TARGET_NAME}"
        while IFS= read -r pid; do
            if [[ -n "$pid" ]]; then
                capture_process "$pid" && captured=$((captured + 1))
            fi
        done < <(pgrep -f "$TARGET_NAME" 2>/dev/null || true)

        if [[ "$captured" -eq 0 ]]; then
            log_error "No processes found matching: ${TARGET_NAME}"
            exit 1
        fi

    elif [[ "$ALL_RUBY" == true ]]; then
        log_info "Searching for all Ruby processes..."
        while IFS= read -r pid; do
            if [[ -n "$pid" ]] && is_ruby_process "$pid"; then
                capture_process "$pid" && captured=$((captured + 1))
            fi
        done < <(pgrep -f ruby 2>/dev/null || true)

        if [[ "$captured" -eq 0 ]]; then
            log_warn "No Ruby processes found"
            exit 0
        fi
    else
        log_error "No target specified. Use --pid, --name, or --all-ruby."
        usage
    fi

    echo ""
    log_success "========================================="
    log_success "Capture complete: ${captured} dump(s) saved"
    log_success "Output directory: ${OUTPUT_BASE}"
    log_success "Log file: ${LOG_FILE}"
    log_success "========================================="
}

main "$@"
