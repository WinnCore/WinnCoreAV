#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

run_category() {
    local name="$1"
    local script="$ROOT_DIR/test_${name}.sh"

    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    printf "║  %-54s ║\n" "$name"
    echo "╚══════════════════════════════════════════════════════════╝"

    if [[ ! -x "$script" ]]; then
        echo "⚠️  Missing script: $script"
        SKIPPED=$((SKIPPED + 1))
        TOTAL=$((TOTAL + 1))
        return
    fi

    if bash "$script"; then
        echo "✅ ${name}: PASS"
        PASSED=$((PASSED + 1))
    else
        echo "❌ ${name}: FAIL"
        FAILED=$((FAILED + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

run_category "malware_detection"
run_category "false_positives"
run_category "performance"
run_category "stability"
run_category "security"
run_category "edge_cases"
run_category "integration"
run_category "behavioral"

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║  Test Summary                                            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo "Total Tests: $TOTAL"
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo "Skipped: $SKIPPED"

if [ $FAILED -eq 0 ]; then
    exit 0
else
    exit 1
fi
