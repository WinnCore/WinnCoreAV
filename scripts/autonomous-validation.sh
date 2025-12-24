#!/usr/bin/env bash
# Autonomous validation loop for WinnCoreAV

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${WINNCORE_VALIDATION_MODE:-fast}"
MAX_RETRIES="${WINNCORE_VALIDATION_RETRIES:-3}"
AUTO_FIX="${WINNCORE_AUTOFIX:-0}"
RESULTS_DIR="$ROOT_DIR/test-results/validation_reports"
REPORT_FILE="$RESULTS_DIR/validation_$(date +%Y%m%d_%H%M%S).jsonl"
SUMMARY_FILE="$RESULTS_DIR/validation_summary_$(date +%Y%m%d_%H%M%S).json"

mkdir -p "$RESULTS_DIR"
cd "$ROOT_DIR"

echo "=== WinnCoreAV Autonomous Validation ==="
echo "Root: $ROOT_DIR"
echo "Mode: $MODE"
echo "Retries: $MAX_RETRIES"
echo "Auto-fix: $AUTO_FIX"

have() { command -v "$1" >/dev/null 2>&1; }

record() {
  local phase="$1" status="$2" details="$3" duration_ms="$4"
  echo "{\"phase\":\"$phase\",\"status\":\"$status\",\"details\":\"$details\",\"duration_ms\":$duration_ms,\"timestamp\":\"$(date -Iseconds)\"}" >> "$REPORT_FILE"
}

run_cmd() {
  local phase="$1" cmd="$2"
  local start end
  start=$(date +%s%3N)
  if bash -c "$cmd" >/dev/null 2>&1; then
    end=$(date +%s%3N)
    record "$phase" "PASS" "" "$((end - start))"
    return 0
  fi
  end=$(date +%s%3N)
  record "$phase" "FAIL" "$cmd" "$((end - start))"
  return 1
}

phase_static() {
  local failed=0
  if ! run_cmd "static:fmt" "cargo fmt --all -- --check"; then
    if [[ "$AUTO_FIX" == "1" ]]; then
      cargo fmt --all >/dev/null 2>&1 || true
      run_cmd "static:fmt" "cargo fmt --all -- --check" || failed=1
    else
      failed=1
    fi
  fi

  if ! run_cmd "static:clippy" "cargo clippy --workspace --all-targets -- -D warnings"; then
    if [[ "$AUTO_FIX" == "1" ]]; then
      cargo clippy --workspace --all-targets --fix --allow-dirty -- -D warnings >/dev/null 2>&1 || true
      run_cmd "static:clippy" "cargo clippy --workspace --all-targets -- -D warnings" || failed=1
    else
      failed=1
    fi
  fi

  if have cargo-audit; then
    run_cmd "static:audit" "cargo audit" || failed=1
  else
    record "static:audit" "SKIP" "cargo-audit not installed" 0
  fi

  if have cargo-deny; then
    run_cmd "static:deny" "cargo deny --config tools/deny.toml check" || failed=1
  else
    record "static:deny" "SKIP" "cargo-deny not installed" 0
  fi

  return $failed
}

phase_tests() {
  local failed=0
  run_cmd "tests:unit" "cargo test --workspace --lib" || failed=1
  run_cmd "tests:integration" "cargo test --workspace --tests" || failed=1

  if [[ "$MODE" == "full" ]]; then
    if have cargo && have rustup; then
      if rustup toolchain list | grep -q nightly; then
        run_cmd "tests:miri" "cargo +nightly miri test --workspace --lib" || failed=1
      else
        record "tests:miri" "SKIP" "nightly toolchain missing" 0
      fi
    fi
  else
    record "tests:miri" "SKIP" "MODE=fast" 0
  fi

  return $failed
}

phase_mutation() {
  if [[ "$MODE" != "full" ]]; then
    record "mutation" "SKIP" "MODE=fast" 0
    return 0
  fi
  if have cargo-mutants; then
    local crate="${WINNCORE_MUTANTS_CRATE:-av-core}"
    run_cmd "mutation" "cargo mutants -p $crate --timeout 60" || return 1
  else
    record "mutation" "SKIP" "cargo-mutants not installed" 0
  fi
  return 0
}

phase_fuzz() {
  if [[ "$MODE" != "full" ]]; then
    record "fuzz" "SKIP" "MODE=fast" 0
    return 0
  fi
  if have cargo-fuzz; then
    local targets="${WINNCORE_FUZZ_TARGETS:-}"
    if [[ -z "$targets" ]]; then
      record "fuzz" "SKIP" "WINNCORE_FUZZ_TARGETS not set" 0
      return 0
    fi
    local failed=0
    for target in $targets; do
      run_cmd "fuzz:$target" "cargo +nightly fuzz run $target -- -max_total_time=120" || failed=1
    done
    return $failed
  fi
  record "fuzz" "SKIP" "cargo-fuzz not installed" 0
  return 0
}

phase_detection() {
  local max_nfr="${WINNCORE_NFR_MAX:-0.01}"
  local results="$ROOT_DIR/test-results/latest_detection_results.json"

  if ! "$ROOT_DIR/scripts/run-detection-suite.sh" --output "$results"; then
    record "detection" "FAIL" "run-detection-suite.sh failed" 0
    return 1
  fi

  if ! python3 "$ROOT_DIR/scripts/check_regression.py" \
      --current "$results" \
      --baseline "$ROOT_DIR/baselines/detection.json" \
      --max-nfr "$max_nfr" \
      --allow-missing-baseline; then
    record "detection" "FAIL" "NFR exceeded" 0
    return 1
  fi

  record "detection" "PASS" "" 0
  return 0
}

phase_perf() {
  if [[ "$MODE" != "full" ]]; then
    record "perf" "SKIP" "MODE=fast" 0
    return 0
  fi
  if have cargo; then
    run_cmd "perf:bench" "cargo bench" || return 1
    python3 "$ROOT_DIR/scripts/check_perf_regression.py" --allow-missing || return 1
    record "perf" "PASS" "" 0
    return 0
  fi
  record "perf" "SKIP" "cargo missing" 0
  return 0
}

phase_compliance() {
  python3 "$ROOT_DIR/scripts/collect_compliance_evidence.py" --output "$RESULTS_DIR/compliance_report.json" || return 1
  record "compliance" "PASS" "" 0
  return 0
}

attempt=1
while [[ $attempt -le $MAX_RETRIES ]]; do
  echo "--- Validation attempt $attempt/$MAX_RETRIES ---"
  failures=0

  phase_static || failures=$((failures + 1))
  phase_tests || failures=$((failures + 1))
  phase_mutation || failures=$((failures + 1))
  phase_fuzz || failures=$((failures + 1))
  phase_detection || failures=$((failures + 1))
  phase_perf || failures=$((failures + 1))
  phase_compliance || failures=$((failures + 1))

  if [[ $failures -eq 0 ]]; then
    echo "All validation phases passed"
    break
  fi

  if [[ $attempt -ge $MAX_RETRIES ]]; then
    echo "Validation failed after $MAX_RETRIES attempts"
    exit 1
  fi

  attempt=$((attempt + 1))
  sleep 1
 done

python3 - << PY
import json
from pathlib import Path

report = Path("$REPORT_FILE")
summary = {
    "report": str(report),
    "phases": [json.loads(line) for line in report.read_text().splitlines() if line.strip()],
}
Path("$SUMMARY_FILE").write_text(json.dumps(summary, indent=2))
print(f"Summary written to $SUMMARY_FILE")
PY
