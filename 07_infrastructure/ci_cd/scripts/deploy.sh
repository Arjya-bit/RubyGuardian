#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Deployment Helper Script
# =============================================================================
# Deploys RubyGuardian to a Kubernetes cluster.  Handles image tag
# substitution, config validation, rolling updates, and smoke tests.
#
# Usage:
#   ./deploy.sh staging v1.2.3         # Deploy to staging
#   ./deploy.sh production v1.2.3      # Deploy to production
#   ./deploy.sh staging v1.2.3 --dry   # Dry run (diff only)
#   ./deploy.sh rollback staging       # Roll back to previous revision
# =============================================================================

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
K8S_DIR="${PROJECT_ROOT}/07_infrastructure/kubernetes"
NAMESPACE="rubyguardian"

# ─── Colors ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[PASS]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }
header()  { echo -e "\n${BOLD}=== $* ===${NC}\n"; }

# ─── Argument Parsing ──────────────────────────────────────────────────
COMMAND="${1:-}"
ENVIRONMENT="${2:-}"
VERSION="${3:-}"
DRY_RUN=false

if [ "$COMMAND" = "rollback" ]; then
    ENVIRONMENT="${2:-staging}"
elif [ -z "$COMMAND" ] || [ -z "$ENVIRONMENT" ] || [ -z "$VERSION" ]; then
    echo "Usage:"
    echo "  $0 <environment> <version> [--dry]"
    echo "  $0 rollback <environment>"
    echo ""
    echo "Environments: staging, production"
    echo "Version:      Docker image tag (e.g., v1.2.3, sha-abc1234)"
    exit 1
fi

if [ "${4:-}" = "--dry" ] || [ "${VERSION:-}" = "--dry" ]; then
    DRY_RUN=true
fi

# ─── Prerequisites ──────────────────────────────────────────────────────
check_prerequisites() {
    header "Checking prerequisites"

    for cmd in kubectl jq; do
        if command -v "$cmd" &>/dev/null; then
            info "${cmd} found: $(command -v "$cmd")"
        else
            fail "${cmd} is required but not installed"
        fi
    done

    # Verify cluster connectivity
    if kubectl cluster-info &>/dev/null; then
        info "Cluster is reachable"
        info "Context: $(kubectl config current-context)"
    else
        fail "Cannot connect to Kubernetes cluster"
    fi
}

# ─── Validation ─────────────────────────────────────────────────────────
validate_manifests() {
    header "Validating manifests"

    local errors=0

    # Check that all YAML files parse correctly
    for manifest in "${K8S_DIR}"/**/*.yml; do
        if [ -f "$manifest" ]; then
            if kubectl apply --dry-run=client -f "$manifest" &>/dev/null; then
                info "Valid: $(basename "$manifest")"
            else
                warn "Invalid: $(basename "$manifest")"
                errors=$((errors + 1))
            fi
        fi
    done

    if [ "$errors" -gt 0 ]; then
        fail "${errors} manifest(s) failed validation"
    fi

    success "All manifests are valid"
}

# ─── Image Tag Update ──────────────────────────────────────────────────
update_image_tags() {
    header "Updating image tags to ${VERSION}"

    local tmp_dir
    tmp_dir=$(mktemp -d)
    cp -r "${K8S_DIR}/deployments/"*.yml "$tmp_dir/"

    for manifest in "$tmp_dir"/*.yml; do
        sed -i "s|rubyguardian/\([^:]*\):[^ ]*|rubyguardian/\1:${VERSION}|g" "$manifest"
        info "Updated: $(basename "$manifest")"
    done

    echo "$tmp_dir"
}

# ─── Deploy ─────────────────────────────────────────────────────────────
deploy() {
    header "Deploying to ${ENVIRONMENT} (version: ${VERSION})"

    local action="apply"
    [ "$DRY_RUN" = true ] && action="diff"

    # 1. Namespace
    info "Applying namespace..."
    kubectl "$action" -f "${K8S_DIR}/namespace.yml" 2>/dev/null || true

    # 2. ConfigMaps
    info "Applying configmaps..."
    kubectl "$action" -f "${K8S_DIR}/configmaps/" 2>/dev/null || true

    # 3. Deployments with updated tags
    local deploy_dir
    deploy_dir=$(update_image_tags)

    info "Applying deployments..."
    kubectl "$action" -f "$deploy_dir/" 2>/dev/null || true

    # 4. Services
    info "Applying services..."
    kubectl "$action" -f "${K8S_DIR}/services/" 2>/dev/null || true

    # Cleanup temp files
    rm -rf "$deploy_dir"

    if [ "$DRY_RUN" = true ]; then
        success "Dry run complete — no changes applied"
        return
    fi

    # 5. Wait for rollouts
    header "Waiting for rollouts"
    for deploy in $(kubectl get deploy -n "${NAMESPACE}" -o name 2>/dev/null); do
        info "Waiting for ${deploy}..."
        if kubectl rollout status "$deploy" -n "${NAMESPACE}" --timeout=300s; then
            success "${deploy} is ready"
        else
            warn "${deploy} did not become ready within timeout"
        fi
    done
}

# ─── Rollback ───────────────────────────────────────────────────────────
rollback() {
    header "Rolling back deployments in ${ENVIRONMENT}"

    for deploy in $(kubectl get deploy -n "${NAMESPACE}" -o name 2>/dev/null); do
        info "Rolling back ${deploy}..."
        if kubectl rollout undo "$deploy" -n "${NAMESPACE}"; then
            success "${deploy} rolled back"
        else
            warn "Failed to roll back ${deploy}"
        fi
    done

    header "Waiting for rollback to complete"
    for deploy in $(kubectl get deploy -n "${NAMESPACE}" -o name 2>/dev/null); do
        kubectl rollout status "$deploy" -n "${NAMESPACE}" --timeout=300s || true
    done
}

# ─── Smoke Tests ────────────────────────────────────────────────────────
run_smoke_tests() {
    header "Running smoke tests"

    local passed=0
    local failed=0

    # Check pod status
    info "Checking pod status..."
    kubectl get pods -n "${NAMESPACE}" -o wide

    # Elasticsearch health
    local es_pod
    es_pod=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=elasticsearch \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "$es_pod" ]; then
        if kubectl exec -n "${NAMESPACE}" "$es_pod" -c elasticsearch -- \
            curl -sf http://localhost:9200/_cluster/health 2>/dev/null; then
            success "Elasticsearch is healthy"
            passed=$((passed + 1))
        else
            warn "Elasticsearch health check failed"
            failed=$((failed + 1))
        fi
    fi

    # ML classifier health
    local ml_pod
    ml_pod=$(kubectl get pod -n "${NAMESPACE}" -l app.kubernetes.io/name=ml-classifier \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
    if [ -n "$ml_pod" ]; then
        if kubectl exec -n "${NAMESPACE}" "$ml_pod" -c ml-classifier -- \
            curl -sf http://localhost:8000/health 2>/dev/null; then
            success "ML classifier is healthy"
            passed=$((passed + 1))
        else
            warn "ML classifier health check failed"
            failed=$((failed + 1))
        fi
    fi

    # Detection agent
    local da_pods
    da_pods=$(kubectl get pods -n "${NAMESPACE}" -l app.kubernetes.io/name=detection-agent \
        --field-selector=status.phase=Running -o name 2>/dev/null | wc -l)
    if [ "$da_pods" -gt 0 ]; then
        success "Detection agent: ${da_pods} pod(s) running"
        passed=$((passed + 1))
    else
        warn "Detection agent: no running pods"
        failed=$((failed + 1))
    fi

    echo ""
    info "Smoke test results: ${passed} passed, ${failed} failed"
    [ "$failed" -gt 0 ] && return 1
    return 0
}

# ─── Main ───────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RubyGuardian Deployment"
echo "  Command:     ${COMMAND}"
echo "  Environment: ${ENVIRONMENT}"
echo "  Version:     ${VERSION:-N/A}"
echo "  Dry run:     ${DRY_RUN}"
echo "  Timestamp:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

check_prerequisites

if [ "$COMMAND" = "rollback" ]; then
    rollback
else
    validate_manifests
    deploy

    if [ "$DRY_RUN" = false ]; then
        run_smoke_tests || warn "Some smoke tests failed — review deployment"
    fi
fi

echo ""
success "Done."
