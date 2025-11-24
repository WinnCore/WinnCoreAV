#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "════════════════════════════════════════════"
echo "WinnCore Hardening Validation"
echo "════════════════════════════════════════════"

PASS=0
FAIL=0
check() {
    local name="$1"
    local cmd="$2"
    if eval "$cmd" >/dev/null 2>&1; then
        echo "✅ $name"
        ((PASS++))
    else
        echo "❌ $name"
        ((FAIL++))
    fi
}

check "av-ebpf async-trait declared" "grep -q 'async-trait' av-ebpf/Cargo.toml"
check "av-watchdog reqwest present" "grep -q 'reqwest' av-watchdog/Cargo.toml"
check "av-core sha2 present" "grep -q 'sha2' av-core/Cargo.toml"

check "Workspace builds" "cargo check --workspace"
check "Clippy clean" "cargo clippy --workspace --all-targets -- -D warnings"
check "Fmt clean" "cargo fmt --all -- --check"

check "Integration tests exist" "ls av-core/tests/integration_basic.rs >/dev/null"
check "No todo! macros in tests" "! rg 'todo!\\(\\)' tests av-core/tests"

echo "Pass: $PASS Fail: $FAIL"
exit $FAIL
