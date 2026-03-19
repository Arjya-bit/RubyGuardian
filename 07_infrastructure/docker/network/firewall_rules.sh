#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Docker Network Firewall Rules
# =============================================================================
# Applies iptables rules to enforce network segmentation between Docker
# bridge networks used by the RubyGuardian lab environment.
#
# Usage:
#   sudo ./firewall_rules.sh apply    # Install rules
#   sudo ./firewall_rules.sh remove   # Remove rules
#   sudo ./firewall_rules.sh status   # Show current rules
#
# Prerequisites:
#   - Docker networks must already exist (run docker-network-config.yml first)
#   - Must be run as root / with sudo
# =============================================================================

set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly CHAIN_PREFIX="RUBYGUARDIAN"

# Network bridge interfaces (must match docker-network-config.yml)
readonly BR_INTERNAL="br-rg-internal"
readonly BR_HONEYPOT="br-rg-honeypot"
readonly BR_MONITOR="br-rg-monitor"
readonly BR_ATTACK="br-rg-attack"

# Subnet CIDRs
readonly SUBNET_INTERNAL="172.28.0.0/16"
readonly SUBNET_HONEYPOT="172.29.0.0/16"
readonly SUBNET_MONITOR="172.30.0.0/16"
readonly SUBNET_ATTACK="172.31.0.0/16"

log_info()  { echo "[INFO]  ${SCRIPT_NAME}: $*"; }
log_warn()  { echo "[WARN]  ${SCRIPT_NAME}: $*" >&2; }
log_error() { echo "[ERROR] ${SCRIPT_NAME}: $*" >&2; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root."
        exit 1
    fi
}

check_interfaces() {
    local missing=0
    for iface in "$BR_INTERNAL" "$BR_HONEYPOT" "$BR_MONITOR" "$BR_ATTACK"; do
        if ! ip link show "$iface" &>/dev/null; then
            log_warn "Interface $iface not found. Create Docker networks first."
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        log_error "One or more bridge interfaces are missing. Aborting."
        exit 1
    fi
}

create_chains() {
    log_info "Creating custom iptables chains..."

    # Create forward chain for inter-segment filtering
    iptables -N "${CHAIN_PREFIX}_FORWARD" 2>/dev/null || true
    iptables -F "${CHAIN_PREFIX}_FORWARD"

    # Insert jump into DOCKER-USER chain (Docker's recommended hook point)
    if ! iptables -C DOCKER-USER -j "${CHAIN_PREFIX}_FORWARD" 2>/dev/null; then
        iptables -I DOCKER-USER 1 -j "${CHAIN_PREFIX}_FORWARD"
    fi
}

apply_rules() {
    local chain="${CHAIN_PREFIX}_FORWARD"

    log_info "Applying RubyGuardian firewall rules..."

    # -------------------------------------------------------------------------
    # Rule 1: BLOCK attack segment -> internal segment
    # Attackers must not reach detection/ML/forensics services directly.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_ATTACK" -o "$BR_INTERNAL" -j DROP \
        -m comment --comment "RG: block attack->internal"

    # -------------------------------------------------------------------------
    # Rule 2: BLOCK attack segment -> monitoring segment
    # Attackers must not access ELK/dashboard.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_ATTACK" -o "$BR_MONITOR" -j DROP \
        -m comment --comment "RG: block attack->monitoring"

    # -------------------------------------------------------------------------
    # Rule 3: ALLOW attack segment -> honeypot segment
    # This is the intended attack surface.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_ATTACK" -o "$BR_HONEYPOT" -j ACCEPT \
        -m comment --comment "RG: allow attack->honeypot"

    # -------------------------------------------------------------------------
    # Rule 4: BLOCK honeypot segment -> internal (except established)
    # Honeypot can send telemetry responses but not initiate to internal.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_HONEYPOT" -o "$BR_INTERNAL" \
        -m state --state NEW -j DROP \
        -m comment --comment "RG: block honeypot->internal new connections"

    iptables -A "$chain" -i "$BR_HONEYPOT" -o "$BR_INTERNAL" \
        -m state --state ESTABLISHED,RELATED -j ACCEPT \
        -m comment --comment "RG: allow honeypot->internal established"

    # -------------------------------------------------------------------------
    # Rule 5: ALLOW internal -> honeypot (telemetry collection)
    # Detection engine pulls telemetry from honeypot.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_INTERNAL" -o "$BR_HONEYPOT" -j ACCEPT \
        -m comment --comment "RG: allow internal->honeypot telemetry"

    # -------------------------------------------------------------------------
    # Rule 6: ALLOW internal <-> monitoring (bidirectional)
    # Services push logs to ELK; dashboard queries ELK.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_INTERNAL" -o "$BR_MONITOR" -j ACCEPT \
        -m comment --comment "RG: allow internal->monitoring"
    iptables -A "$chain" -i "$BR_MONITOR" -o "$BR_INTERNAL" -j ACCEPT \
        -m comment --comment "RG: allow monitoring->internal"

    # -------------------------------------------------------------------------
    # Rule 7: BLOCK honeypot -> monitoring
    # Compromised honeypot must not reach dashboards.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_HONEYPOT" -o "$BR_MONITOR" -j DROP \
        -m comment --comment "RG: block honeypot->monitoring"

    # -------------------------------------------------------------------------
    # Rule 8: Rate-limit connections from attack segment to honeypot
    # Prevents DoS of the honeypot during testing.
    # -------------------------------------------------------------------------
    iptables -A "$chain" -i "$BR_ATTACK" -o "$BR_HONEYPOT" \
        -m conntrack --ctstate NEW \
        -m limit --limit 50/sec --limit-burst 100 -j ACCEPT \
        -m comment --comment "RG: rate-limit attack->honeypot"

    # -------------------------------------------------------------------------
    # Rule 9: Log dropped packets for forensic analysis
    # -------------------------------------------------------------------------
    iptables -A "$chain" -j LOG \
        --log-prefix "[RubyGuardian DROP] " \
        --log-level 4 \
        -m comment --comment "RG: log drops"

    log_info "Firewall rules applied successfully."
}

remove_rules() {
    log_info "Removing RubyGuardian firewall rules..."

    # Remove jump from DOCKER-USER
    iptables -D DOCKER-USER -j "${CHAIN_PREFIX}_FORWARD" 2>/dev/null || true

    # Flush and delete custom chain
    iptables -F "${CHAIN_PREFIX}_FORWARD" 2>/dev/null || true
    iptables -X "${CHAIN_PREFIX}_FORWARD" 2>/dev/null || true

    log_info "Firewall rules removed."
}

show_status() {
    echo "=== RubyGuardian Firewall Rules ==="
    echo ""
    if iptables -L "${CHAIN_PREFIX}_FORWARD" -n -v 2>/dev/null; then
        echo ""
        echo "=== DOCKER-USER chain ==="
        iptables -L DOCKER-USER -n -v --line-numbers 2>/dev/null | \
            grep -E "(${CHAIN_PREFIX}|num)" || echo "(no RubyGuardian rules found)"
    else
        echo "No RubyGuardian chain found. Rules have not been applied."
    fi
}

usage() {
    cat <<EOF
Usage: sudo $SCRIPT_NAME {apply|remove|status}

Commands:
  apply   - Create and apply firewall rules for network segmentation
  remove  - Remove all RubyGuardian firewall rules
  status  - Display current rule state

EOF
}

# =============================================================================
# Main
# =============================================================================
main() {
    check_root

    case "${1:-}" in
        apply)
            check_interfaces
            create_chains
            apply_rules
            ;;
        remove)
            remove_rules
            ;;
        status)
            show_status
            ;;
        *)
            usage
            exit 1
            ;;
    esac
}

main "$@"
