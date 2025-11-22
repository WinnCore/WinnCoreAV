#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 8: Behavioral Detection"

fail=0

if python3 tests/validate_ml.py; then
    echo "  ✅ ML feature extraction sanity"
else
    echo "  ❌ ML validation failed"
    fail=$((fail + 1))
fi

if cargo test -p av-core stress_concurrent_scanning_ci_safe --release -- --nocapture; then
    echo "  ✅ Concurrent scanning behavior"
else
    echo "  ❌ Concurrent scanning behavior failed"
    fail=$((fail + 1))
fi

if cargo test -p av-core stress_memory_regression_small_loop --release -- --nocapture; then
    echo "  ✅ Memory regression micro-loop"
else
    echo "  ❌ Memory regression micro-loop failed"
    fail=$((fail + 1))
fi

if [[ $fail -gt 0 ]]; then
    exit 1
fi

exit 0
