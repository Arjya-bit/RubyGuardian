#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Docker Image Build Script
# =============================================================================
# Builds all Docker images for the RubyGuardian platform.  Supports
# building individual components or the entire stack.
#
# Usage:
#   ./build_images.sh                    # Build all images
#   ./build_images.sh detection-agent    # Build a single component
#   ./build_images.sh --push             # Build and push to registry
#   ./build_images.sh --tag v1.2.3       # Custom tag
# =============================================================================

set -euo pipefail

# ─── Configuration ──────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
REGISTRY="${REGISTRY:-ghcr.io}"
IMAGE_PREFIX="${IMAGE_PREFIX:-rubyguardian}"
TAG="${TAG:-latest}"
PUSH=false
COMPONENT=""
PLATFORM="${PLATFORM:-linux/amd64}"
NO_CACHE=false
BUILD_ARGS=""

# ─── Colors ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[PASS]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ─── Image Definitions ─────────────────────────────────────────────────
# Each entry: name|dockerfile|context|target
declare -a IMAGES=(
    "detection-agent|07_infrastructure/docker/base/Dockerfile.ruby|.|detection-agent"
    "honeypot|07_infrastructure/docker/base/Dockerfile.ruby|.|honeypot"
    "forensics|07_infrastructure/docker/base/Dockerfile.ruby|.|forensics"
    "ml-classifier|07_infrastructure/docker/base/Dockerfile.python|.|"
    "attacker|07_infrastructure/docker/base/Dockerfile.attacker|.|"
    "web-ui|06_dashboard/web_ui/Dockerfile|06_dashboard/web_ui|"
    "honeypot-rails|05_honeypot/decoy_apps/fake_rails_app/Dockerfile|05_honeypot/decoy_apps/fake_rails_app|"
    "honeypot-gems|05_honeypot/decoy_apps/fake_gem_server/Dockerfile|05_honeypot/decoy_apps/fake_gem_server|"
    "honeypot-ci|05_honeypot/decoy_apps/fake_ci_runner/Dockerfile|05_honeypot/decoy_apps/fake_ci_runner|"
)

# ─── Argument Parsing ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --push)
            PUSH=true
            shift
            ;;
        --tag)
            TAG="$2"
            shift 2
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --platform)
            PLATFORM="$2"
            shift 2
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS] [COMPONENT]"
            echo ""
            echo "Options:"
            echo "  --push          Push images to registry after building"
            echo "  --tag TAG       Image tag (default: latest)"
            echo "  --registry REG  Container registry (default: ghcr.io)"
            echo "  --platform PLT  Target platform (default: linux/amd64)"
            echo "  --no-cache      Build without Docker cache"
            echo "  --help          Show this help"
            echo ""
            echo "Components:"
            for entry in "${IMAGES[@]}"; do
                IFS='|' read -r name _ _ _ <<< "$entry"
                echo "  ${name}"
            done
            exit 0
            ;;
        -*)
            fail "Unknown option: $1"
            ;;
        *)
            COMPONENT="$1"
            shift
            ;;
    esac
done

# ─── Build Function ────────────────────────────────────────────────────
build_image() {
    local name="$1"
    local dockerfile="$2"
    local context="$3"
    local target="$4"

    local full_tag="${REGISTRY}/${IMAGE_PREFIX}/${name}:${TAG}"
    local latest_tag="${REGISTRY}/${IMAGE_PREFIX}/${name}:latest"

    info "Building ${full_tag}"
    info "  Dockerfile: ${dockerfile}"
    info "  Context:    ${context}"
    [ -n "$target" ] && info "  Target:     ${target}"

    local build_cmd=(
        docker build
        -f "${PROJECT_ROOT}/${dockerfile}"
        -t "${full_tag}"
        -t "${latest_tag}"
        --label "org.opencontainers.image.source=https://github.com/rubyguardian/rubyguardian"
        --label "org.opencontainers.image.version=${TAG}"
        --label "org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    )

    [ -n "$target" ] && build_cmd+=(--target "$target")
    [ "$NO_CACHE" = true ] && build_cmd+=(--no-cache)

    build_cmd+=("${PROJECT_ROOT}/${context}")

    if "${build_cmd[@]}"; then
        success "Built ${full_tag}"
    else
        fail "Failed to build ${name}"
    fi

    if [ "$PUSH" = true ]; then
        info "Pushing ${full_tag}..."
        docker push "${full_tag}" && success "Pushed ${full_tag}" || fail "Failed to push ${full_tag}"
        docker push "${latest_tag}" && success "Pushed ${latest_tag}" || warn "Failed to push ${latest_tag}"
    fi
}

# ─── Main ───────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  RubyGuardian Docker Image Builder"
echo "  Registry:  ${REGISTRY}/${IMAGE_PREFIX}"
echo "  Tag:       ${TAG}"
echo "  Push:      ${PUSH}"
echo "  Platform:  ${PLATFORM}"
echo "  Component: ${COMPONENT:-all}"
echo "============================================================"
echo ""

cd "${PROJECT_ROOT}"

BUILT=0
FAILED=0

for entry in "${IMAGES[@]}"; do
    IFS='|' read -r name dockerfile context target <<< "$entry"

    # Skip if a specific component was requested and this is not it
    if [ -n "$COMPONENT" ] && [ "$COMPONENT" != "$name" ]; then
        continue
    fi

    # Check that the Dockerfile exists
    if [ ! -f "${PROJECT_ROOT}/${dockerfile}" ]; then
        warn "Dockerfile not found: ${dockerfile} — skipping ${name}"
        continue
    fi

    if build_image "$name" "$dockerfile" "$context" "$target"; then
        BUILT=$((BUILT + 1))
    else
        FAILED=$((FAILED + 1))
    fi

    echo ""
done

echo "============================================================"
echo "  Build Summary"
echo "  Built:  ${BUILT}"
echo "  Failed: ${FAILED}"
echo "============================================================"

[ "$FAILED" -gt 0 ] && exit 1
exit 0
