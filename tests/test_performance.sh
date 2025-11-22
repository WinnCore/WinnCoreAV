#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/test_common.sh"

header "Category 3: Performance"

PERF_SINGLE_TARGET_MS=${PERF_SINGLE_TARGET_MS:-500}
PERF_DIR_TARGET_MS=${PERF_DIR_TARGET_MS:-10000}

measure_ms() {
    local mode="$1"
    local target="$2"
    python3 - "$ROOT_DIR" "$mode" "$target" <<'PY'
import os
import subprocess
import sys
import time

root = sys.argv[1]
mode = sys.argv[2]
target = sys.argv[3]
env = os.environ.copy()
cmd = ["cargo", "run", "--quiet", "--release", "--bin", "av-cli", "--", "scan", mode, target]
start = time.perf_counter()
result = subprocess.run(cmd, cwd=root, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
elapsed_ms = (time.perf_counter() - start) * 1000
print(f"{elapsed_ms:.2f}")
sys.exit(result.returncode)
PY
}

check_target() {
    local label="$1"
    local path="$2"
    local budget_ms="$3"

    if [[ ! -e "$path" ]]; then
        echo "⚠️  Skipping missing target for ${label}: $path"
        return 0
    fi

    local mode="file"
    [[ -d "$path" ]] && mode="dir"

    local elapsed
    if ! elapsed=$(measure_ms "$mode" "$path"); then
        echo "❌ ${label}: scan command failed"
        return 1
    fi

    echo "  ${label}: ${elapsed} ms (budget ${budget_ms} ms; target 50ms single-file goal)"

    python3 - "$elapsed" "$budget_ms" <<'PY'
import sys
elapsed = float(sys.argv[1])
budget = float(sys.argv[2])
sys.exit(0 if elapsed <= budget else 1)
PY
}

ok=0
fail=0

if check_target "Single file (benign)" "$ROOT_DIR/test_samples/benign_arm64" "$PERF_SINGLE_TARGET_MS"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
if check_target "Single file (malware)" "$ROOT_DIR/malware_testing/samples/arm64/malicious1.elf" "$PERF_SINGLE_TARGET_MS"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi
if check_target "Directory scan (test_samples)" "$ROOT_DIR/test_samples" "$PERF_DIR_TARGET_MS"; then ok=$((ok + 1)); else fail=$((fail + 1)); fi

if [[ $fail -gt 0 ]]; then
    echo "⚠️  Performance checks failed (${fail} failing, ${ok} passing)."
    exit 1
fi

exit 0
