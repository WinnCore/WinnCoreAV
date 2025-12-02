#!/bin/bash
set -e

# Set user quarantine directory for tests
export WINNCORE_QUARANTINE_DIR="$HOME/.winncore/quarantine"
mkdir -p "$WINNCORE_QUARANTINE_DIR"

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   WinnCoreAV - Comprehensive Behavioral Test Suite        ║${NC}"
echo -e "${BOLD}╚════════════════════════════════════════════════════════════╝${NC}"
echo -e "${BOLD}Quarantine Directory:${NC} $WINNCORE_QUARANTINE_DIR"

TEST_DIR="test_output_$(date +%s)"
mkdir -p "$TEST_DIR"

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local name="$1"
    local cmd="$2"
    echo -e "\n${BOLD}[TEST]${NC} $name"
    if eval "$cmd" > "$TEST_DIR/${name// /_}.log" 2>&1; then
        echo -e "${GREEN}✅ PASS${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        echo -e "${RED}❌ FAIL${NC}"
        tail -5 "$TEST_DIR/${name// /_}.log"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

echo -e "\n${BOLD}═══ 1. BUILD & COMPILATION TESTS ═══${NC}"
run_test "Clean build" "cargo build --release --workspace"
run_test "Clippy lints" "cargo clippy --workspace --all-features --all-targets -- -D warnings"
run_test "Code formatting" "cargo fmt --all -- --check"

echo -e "\n${BOLD}═══ 2. BASIC SCANNING TESTS ═══${NC}"
run_test "Scan benign ARM64 binary" "cargo run --release --bin av-cli -- scan file test_samples/benign_arm64"
run_test "Scan suspicious ARM64 binary" "cargo run --release --bin av-cli -- scan file test_samples/suspicious_arm64"
run_test "Scan directory" "cargo run --release --bin av-cli -- scan dir test_samples/"

echo -e "\n${BOLD}═══ 3. ML DETECTION TESTS ═══${NC}"
run_test "Python ML validation" "python3 tests/validate_ml.py"

cat > "$TEST_DIR/test_benign.py" << 'PYEOF'
import sys
sys.path.insert(0, "tools/ml_pipeline")
from feature_extraction import EnhancedARM64FeatureExtractor
e = EnhancedARM64FeatureExtractor()
f = e.extract_features("test_samples/benign_arm64")
assert len(f) == 14, f"Expected 14 features, got {len(f)}"
assert f["file_size"] > 0, "File size should be positive"
print(f"✓ {len(f)} features: entropy={f['entropy']:.2f}, suspicious={f['suspicious_strings']}")
PYEOF

cat > "$TEST_DIR/test_suspicious.py" << 'PYEOF'
import sys
sys.path.insert(0, "tools/ml_pipeline")
from feature_extraction import EnhancedARM64FeatureExtractor
e = EnhancedARM64FeatureExtractor()
f = e.extract_features("test_samples/suspicious_arm64")
assert len(f) == 14
print(f"✓ suspicious={f['suspicious_strings']}, entropy={f['entropy']:.2f}")
PYEOF

run_test "Extract benign features" "python3 $TEST_DIR/test_benign.py"
run_test "Extract suspicious features" "python3 $TEST_DIR/test_suspicious.py"

echo -e "\n${BOLD}═══ 4. SIGNATURE DETECTION TESTS ═══${NC}"
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > "$TEST_DIR/eicar.txt"
run_test "EICAR detection" "cargo run --release --bin av-cli -- scan file $TEST_DIR/eicar.txt"

echo -e "\n${BOLD}═══ 5. QUARANTINE TESTS ═══${NC}"
run_test "List quarantine (empty)" "cargo run --release --bin av-cli -- quarantine list"
run_test "Quarantine dir exists" "test -d $WINNCORE_QUARANTINE_DIR"

echo -e "\n${BOLD}═══ 6. PERFORMANCE TESTS ═══${NC}"
run_test "Concurrent scanning" "cargo test -p av-core stress_concurrent_scanning_ci_safe --release -- --nocapture"
run_test "Memory regression" "cargo test -p av-core stress_memory_regression_small_loop --release -- --nocapture"

echo -e "\n${BOLD}═══ 7. UNIT TESTS ═══${NC}"
run_test "av-core" "cargo test -p av-core --lib"
run_test "av-signatures" "cargo test -p av-signatures --lib"
run_test "av-quarantine" "cargo test -p av-quarantine --lib"

echo -e "\n${BOLD}═══ 8. INTEGRATION TESTS ═══${NC}"
run_test "Full workspace" "cargo test --workspace --all-features"

echo -e "\n${BOLD}═══ 9. CLI TESTS ═══${NC}"
run_test "Help" "cargo run --release --bin av-cli -- --help"
run_test "Version" "cargo run --release --bin av-cli -- --version"
run_test "JSON output" "cargo run --release --bin av-cli -- scan file test_samples/benign_arm64 --json"

echo -e "\n${BOLD}═══ 10. EDGE CASES ═══${NC}"
mkdir -p "$TEST_DIR/edge_cases"
echo "" > "$TEST_DIR/edge_cases/empty.txt"
dd if=/dev/zero of="$TEST_DIR/edge_cases/zeros.bin" bs=1K count=1 2>/dev/null
dd if=/dev/urandom of="$TEST_DIR/edge_cases/random.bin" bs=1K count=1 2>/dev/null

run_test "Empty file" "cargo run --release --bin av-cli -- scan file $TEST_DIR/edge_cases/empty.txt"
run_test "Binary zeros" "cargo run --release --bin av-cli -- scan file $TEST_DIR/edge_cases/zeros.bin"
run_test "Random data" "cargo run --release --bin av-cli -- scan file $TEST_DIR/edge_cases/random.bin"

echo -e "\n${BOLD}═══ FINAL REPORT ═══${NC}"
TOTAL=$((TESTS_PASSED + TESTS_FAILED))
PASS_RATE=$((TESTS_PASSED * 100 / TOTAL))
echo -e "${GREEN}Passed:${NC} $TESTS_PASSED/$TOTAL (${PASS_RATE}%) | ${RED}Failed:${NC} $TESTS_FAILED"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}${BOLD}🎉 ALL $TOTAL TESTS PASSED! 🎉${NC}"
    exit 0
else
    echo -e "\n${YELLOW}${BOLD}⚠️  $TESTS_FAILED/$TOTAL FAILED${NC}"
    exit 1
fi
