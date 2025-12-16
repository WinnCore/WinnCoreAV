#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

mkdir -p "${RESULTS_DIR}"

ALERT_LOG="${RESULTS_DIR}/alerts.json"
DAEMON_LOG="${RESULTS_DIR}/av-daemon.log"
SIM_LOG="${RESULTS_DIR}/attack-sim.log"

echo "=== WinnCoreAV Attack Simulation Suite ==="
echo "Root: ${ROOT_DIR}"
echo "Results: ${RESULTS_DIR}"
echo "Alert log: ${ALERT_LOG}"

echo
echo "=== Build (release) ==="
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
  if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
    return
  fi

  echo
  echo "=== Stop av-daemon ==="
  kill "${DAEMON_PID}" 2>/dev/null || true

  # Give the daemon a moment to shut down gracefully; fall back to SIGKILL to
  # keep CI/agents from hanging if SIGTERM is trapped but not processed.
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
}
trap cleanup EXIT

sleep 2
if ! kill -0 "${DAEMON_PID}" 2>/dev/null; then
  echo "av-daemon failed to start; see ${DAEMON_LOG}"
  exit 1
fi

echo "av-daemon PID: ${DAEMON_PID}"

echo
echo "=== Run attack simulator ==="
WINNCORE_ALERT_LOG="${ALERT_LOG}" \
WINNCORE_ATTACK_SIM_RESULTS="${RESULTS_DIR}/attack_sim_results.json" \
    "${ROOT_DIR}/target/release/attack-sim" 2>&1 | tee "${SIM_LOG}"

echo
echo "=== Detection Summary ==="
grep -E "Detected:|Detection Rate|RESULTS SUMMARY" -n "${SIM_LOG}" || true

echo
echo "Done."
