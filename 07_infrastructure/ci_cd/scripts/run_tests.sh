#!/usr/bin/env bash
# =============================================================================
# RubyGuardian - Test Runner Script
# =============================================================================
# Orchestrates all test suites: Ruby (RSpec), Python (pytest), and
# JavaScript (Vitest).  Supports running individual suites or all at once.
#
# Usage:
#   ./run_tests.sh              # Run all tests
#   ./run_tests.sh ruby         # Ruby tests only
#   ./run_tests.sh python       # Python tests only
#   ./run_tests.sh frontend     # Frontend tests only
#   ./run_tests.sh unit         # Unit tests across all languages
#   ./run_tests.sh integration  # Integration tests only
#   ./run_tests.sh adversarial  # Adversarial tests only
#   ./run_tests.sh performance  # Performance benchmarks
# =============================================================================

set -euo pipefail

# ─── Colors ─────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ─── Configuration ──────────────────────────────────────────────────────
PROJECT_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
RESULTS_DIR="${PROJECT_ROOT}/09_testing/results"
COVERAGE_DIR="${PROJECT_ROOT}/coverage"
SUITE="${1:-all}"
EXIT_CODE=0

# ─── Helpers ────────────────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[PASS]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()    { echo -e "${RED}[FAIL]${NC}  $*"; }

timestamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }

ensure_dir() { mkdir -p "$1"; }

run_with_timing() {
    local label="$1"
    shift
    local start end duration
    start=$(date +%s)
    info "Starting: ${label}"

    if "$@"; then
        end=$(date +%s)
        duration=$((end - start))
        success "${label} completed in ${duration}s"
        return 0
    else
        end=$(date +%s)
        duration=$((end - start))
        fail "${label} failed after ${duration}s"
        return 1
    fi
}

# ─── Ruby Tests ─────────────────────────────────────────────────────────
run_ruby_unit_tests() {
    info "Running Ruby unit tests..."
    cd "${PROJECT_ROOT}"

    bundle exec rspec \
        09_testing/unit/attack_framework/ \
        09_testing/unit/detection_engine/ \
        09_testing/unit/honeypot/ \
        09_testing/unit/forensics/ \
        --format documentation \
        --format json --out "${RESULTS_DIR}/ruby_unit_results.json" \
        --tag ~integration \
        --tag ~slow \
        || return 1
}

run_ruby_integration_tests() {
    info "Running Ruby integration tests..."
    cd "${PROJECT_ROOT}"

    bundle exec rspec \
        09_testing/integration/ \
        --format documentation \
        --format json --out "${RESULTS_DIR}/ruby_integration_results.json" \
        --tag integration \
        || return 1
}

run_ruby_adversarial_tests() {
    info "Running Ruby adversarial tests..."
    cd "${PROJECT_ROOT}"

    bundle exec rspec \
        09_testing/adversarial/ \
        --format documentation \
        --format json --out "${RESULTS_DIR}/ruby_adversarial_results.json" \
        --tag adversarial \
        || return 1
}

run_ruby_performance_tests() {
    info "Running Ruby performance benchmarks..."
    cd "${PROJECT_ROOT}"

    bundle exec rspec \
        09_testing/performance/ \
        --format documentation \
        --format json --out "${RESULTS_DIR}/ruby_performance_results.json" \
        --tag performance \
        || return 1
}

run_all_ruby_tests() {
    run_with_timing "Ruby unit tests" run_ruby_unit_tests || EXIT_CODE=1
    run_with_timing "Ruby integration tests" run_ruby_integration_tests || EXIT_CODE=1
}

# ─── Python Tests ───────────────────────────────────────────────────────
run_python_unit_tests() {
    info "Running Python unit tests..."
    cd "${PROJECT_ROOT}"

    python -m pytest \
        03_ml_classifier/tests/ \
        -v \
        --tb=short \
        --cov=03_ml_classifier \
        --cov-report=html:"${COVERAGE_DIR}/python" \
        --cov-report=xml:"${RESULTS_DIR}/python_coverage.xml" \
        --junitxml="${RESULTS_DIR}/python_unit_results.xml" \
        -m "not integration and not slow" \
        || return 1
}

run_python_integration_tests() {
    info "Running Python integration tests..."
    cd "${PROJECT_ROOT}"

    python -m pytest \
        09_testing/integration/ml_pipeline_test.py \
        -v \
        --tb=short \
        --junitxml="${RESULTS_DIR}/python_integration_results.xml" \
        -m "integration" \
        || return 1
}

run_python_adversarial_tests() {
    info "Running Python adversarial tests..."
    cd "${PROJECT_ROOT}"

    python -m pytest \
        09_testing/adversarial/ml_adversarial_test.py \
        -v \
        --tb=short \
        --junitxml="${RESULTS_DIR}/python_adversarial_results.xml" \
        -m "adversarial" \
        || return 1
}

run_python_performance_tests() {
    info "Running Python performance benchmarks..."
    cd "${PROJECT_ROOT}"

    python -m pytest \
        09_testing/performance/ml_throughput_test.py \
        -v \
        --tb=short \
        --junitxml="${RESULTS_DIR}/python_performance_results.xml" \
        -m "performance" \
        || return 1
}

run_all_python_tests() {
    run_with_timing "Python unit tests" run_python_unit_tests || EXIT_CODE=1
    run_with_timing "Python integration tests" run_python_integration_tests || EXIT_CODE=1
}

# ─── Frontend Tests ─────────────────────────────────────────────────────
run_frontend_tests() {
    info "Running frontend tests..."
    cd "${PROJECT_ROOT}/06_dashboard/web_ui"

    if [ ! -d "node_modules" ]; then
        info "Installing frontend dependencies..."
        npm ci
    fi

    npx vitest run \
        --coverage \
        --reporter=verbose \
        --reporter=json --outputFile="${RESULTS_DIR}/frontend_results.json" \
        || return 1
}

# ─── Suite Dispatcher ───────────────────────────────────────────────────
ensure_dir "${RESULTS_DIR}"
ensure_dir "${COVERAGE_DIR}"

echo ""
echo "============================================================"
echo "  RubyGuardian Test Runner"
echo "  Suite:     ${SUITE}"
echo "  Timestamp: $(timestamp)"
echo "  Project:   ${PROJECT_ROOT}"
echo "============================================================"
echo ""

case "${SUITE}" in
    all)
        run_with_timing "Ruby unit tests"        run_ruby_unit_tests        || EXIT_CODE=1
        run_with_timing "Ruby integration tests"  run_ruby_integration_tests  || EXIT_CODE=1
        run_with_timing "Python unit tests"       run_python_unit_tests       || EXIT_CODE=1
        run_with_timing "Python integration tests" run_python_integration_tests || EXIT_CODE=1
        run_with_timing "Frontend tests"          run_frontend_tests          || EXIT_CODE=1
        ;;
    ruby)
        run_all_ruby_tests
        ;;
    python)
        run_all_python_tests
        ;;
    frontend)
        run_with_timing "Frontend tests" run_frontend_tests || EXIT_CODE=1
        ;;
    unit)
        run_with_timing "Ruby unit tests"   run_ruby_unit_tests   || EXIT_CODE=1
        run_with_timing "Python unit tests" run_python_unit_tests || EXIT_CODE=1
        ;;
    integration)
        run_with_timing "Ruby integration tests"   run_ruby_integration_tests   || EXIT_CODE=1
        run_with_timing "Python integration tests" run_python_integration_tests || EXIT_CODE=1
        ;;
    adversarial)
        run_with_timing "Ruby adversarial tests"   run_ruby_adversarial_tests   || EXIT_CODE=1
        run_with_timing "Python adversarial tests" run_python_adversarial_tests || EXIT_CODE=1
        ;;
    performance)
        run_with_timing "Ruby performance tests"   run_ruby_performance_tests   || EXIT_CODE=1
        run_with_timing "Python performance tests" run_python_performance_tests || EXIT_CODE=1
        ;;
    *)
        fail "Unknown suite: ${SUITE}"
        echo "Usage: $0 {all|ruby|python|frontend|unit|integration|adversarial|performance}"
        exit 1
        ;;
esac

echo ""
echo "============================================================"
if [ ${EXIT_CODE} -eq 0 ]; then
    success "All requested test suites passed."
else
    fail "One or more test suites failed."
fi
echo "  Results: ${RESULTS_DIR}/"
echo "  Coverage: ${COVERAGE_DIR}/"
echo "============================================================"

exit ${EXIT_CODE}
