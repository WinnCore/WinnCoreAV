#!/usr/bin/env bash
#
# WinnCoreAV Detection Validation Script
#
# Builds the daemon + attack simulator, runs a local simulation suite,
# and writes a JSON summary to a timestamped results directory.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/test-results/detection_validation_$(date +%Y%m%d_%H%M%S)"

mkdir -p "${RESULTS_DIR}"

ALERT_LOG="${RESULTS_DIR}/alerts.jsonl"
DAEMON_LOG="${RESULTS_DIR}/av-daemon.log"
SIM_LOG="${RESULTS_DIR}/attack-sim.log"
SIM_RESULTS="${RESULTS_DIR}/attack_sim_results.json"

echo "=== WinnCoreAV Detection Validation ==="
echo "Root:     ${ROOT_DIR}"
echo "Results:  ${RESULTS_DIR}"
echo "Alerts:   ${ALERT_LOG}"
echo

echo "=== Build (release) ==="
cd "${ROOT_DIR}"
cargo build --release -p av-daemon -p av-attack-sim

echo
echo "=== Reset alert log ==="
: >"${ALERT_LOG}"

echo
echo "=== Start av-daemon ==="
WINNCORE_DEBUG=1 \
WINNCORE_LOG_LEVEL=info \
WINNCORE_ALERT_LOG="${ALERT_LOG}" \
  "${ROOT_DIR}/target/release/av-daemon" >"${DAEMON_LOG}" 2>&1 &
DAEMON_PID=$!

cleanup() {
  if kill -0 "${DAEMON_PID}" 2>/dev/null; then
    echo
    echo "=== Stop av-daemon ==="
    kill "${DAEMON_PID}" 2>/dev/null || true
    for _ in {1..50}; do
      if ! ps -p "${DAEMON_PID}" >/dev/null 2>&1; then
        wait "${DAEMON_PID}" 2>/dev/null || true
        return
      fi
      state="$(ps -p "${DAEMON_PID}" -o stat= 2>/dev/null | tr -d ' ' || true)"
      if [[ "${state}" == Z* ]]; then
        wait "${DAEMON_PID}" 2>/dev/null || true
        return
      fi
      sleep 0.1
    done
    echo "av-daemon did not exit after SIGTERM; sending SIGKILL"
    kill -KILL "${DAEMON_PID}" 2>/dev/null || true
    wait "${DAEMON_PID}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

sleep 2
if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
  echo "ERROR: av-daemon failed to start; see ${DAEMON_LOG}"
  exit 1
fi
echo "av-daemon PID: ${DAEMON_PID}"

echo
echo "=== Run attack simulations ==="
export WINNCORE_ALERT_LOG="${ALERT_LOG}"
export WINNCORE_ATTACK_SIM_RESULTS="${SIM_RESULTS}"
"${ROOT_DIR}/target/release/attack-sim" 2>&1 | tee "${SIM_LOG}"

echo
echo "=== Results ==="
python3 - << 'PY'
import json
import os
import sys

results_path = os.environ["WINNCORE_ATTACK_SIM_RESULTS"]

with open(results_path, "r", encoding="utf-8") as f:
    data = json.load(f)

summary = data.get("summary", {})
rate = float(summary.get("detection_rate_percent", 0.0))
detected = int(summary.get("detected", 0))
executed = int(summary.get("executed", 0))
skipped = int(summary.get("skipped", 0))

print(f"Detection rate: {detected}/{executed} ({rate:.1f}%)  skipped={skipped}")

threshold = 80.0
if rate < threshold:
    print(f"WARNING: detection rate below {threshold:.0f}% threshold", file=sys.stderr)
    sys.exit(1)
PY

echo
echo "OK: Results saved to ${RESULTS_DIR}"
