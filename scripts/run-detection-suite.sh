#!/usr/bin/env bash
# WinnCoreAV detection suite runner
# Runs attack simulations and optional malware corpus scan.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/test-results/detection_suite_$(date +%Y%m%d_%H%M%S)"
ALERT_LOG="${RESULTS_DIR}/alerts.jsonl"
DAEMON_LOG="${RESULTS_DIR}/av-daemon.log"
SIM_LOG="${RESULTS_DIR}/attack-sim.log"
SIM_RESULTS="${RESULTS_DIR}/attack_sim_results.json"
CORPUS_RESULTS="${RESULTS_DIR}/corpus_results.json"
OUTPUT_JSON="${RESULTS_DIR}/results.json"
CORPUS_DIR=""
START_DAEMON=true

usage() {
  cat << 'USAGE'
Usage: run-detection-suite.sh [options]

Options:
  --corpus <dir>        Malware corpus directory (optional).
  --output <file>       Output JSON (default: test-results/.../results.json).
  --no-daemon           Do not start av-daemon (assume running).
  --help                Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --corpus)
      CORPUS_DIR="$2"; shift 2;;
    --output)
      OUTPUT_JSON="$2"; shift 2;;
    --no-daemon)
      START_DAEMON=false; shift;;
    --help)
      usage; exit 0;;
    *)
      echo "Unknown arg: $1"; usage; exit 1;;
  esac
 done

mkdir -p "$RESULTS_DIR"
mkdir -p "$(dirname "$OUTPUT_JSON")"

cd "$ROOT_DIR"

echo "=== WinnCoreAV Detection Suite ==="
echo "Root:    $ROOT_DIR"
echo "Results: $RESULTS_DIR"

echo "=== Build (release) ==="
if $START_DAEMON; then
  cargo build --release -p av-daemon -p av-attack-sim -p av-cli
else
  cargo build --release -p av-attack-sim -p av-cli
fi

if $START_DAEMON; then
  echo "=== Start av-daemon ==="
  : >"$ALERT_LOG"
  WINNCORE_DEBUG=1 \
  WINNCORE_LOG_LEVEL=info \
  WINNCORE_ALERT_LOG="$ALERT_LOG" \
    "$ROOT_DIR/target/release/av-daemon" >"$DAEMON_LOG" 2>&1 &
  DAEMON_PID=$!

  cleanup() {
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
      kill "$DAEMON_PID" 2>/dev/null || true
      wait "$DAEMON_PID" 2>/dev/null || true
    fi
  }
  trap cleanup EXIT

  sleep 2
  if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "ERROR: av-daemon failed to start; see $DAEMON_LOG" >&2
    exit 1
  fi
fi

echo "=== Run attack simulations ==="
export WINNCORE_ALERT_LOG="$ALERT_LOG"
export WINNCORE_ATTACK_SIM_RESULTS="$SIM_RESULTS"
"$ROOT_DIR/target/release/attack-sim" 2>&1 | tee "$SIM_LOG"

if [[ -n "$CORPUS_DIR" ]]; then
  if [[ ! -d "$CORPUS_DIR" ]]; then
    echo "ERROR: corpus dir not found: $CORPUS_DIR" >&2
    exit 1
  fi
  echo "=== Run corpus scan ==="
  python3 - << PY
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path("$ROOT_DIR")
corpus = Path("$CORPUS_DIR")
out_path = Path("$CORPUS_RESULTS")
cli = root / "target" / "release" / "av-cli"

if not cli.exists():
    print(f"ERROR: av-cli not found at {cli}", file=sys.stderr)
    sys.exit(1)

files = [p for p in corpus.rglob("*") if p.is_file()]
results = []

detected = 0
missed = 0
for path in files:
    try:
        proc = subprocess.run([
            str(cli), "scan", "file", str(path), "--json"
        ], check=False, capture_output=True, text=True)
    except Exception as exc:
        results.append({"path": str(path), "error": str(exc)})
        missed += 1
        continue

    stdout = proc.stdout.strip()
    action = "unknown"
    if stdout:
        try:
            data = json.loads(stdout)
            action = data.get("recommended_action", "unknown")
        except json.JSONDecodeError:
            action = "unknown"

    is_detected = action != "Allow"
    if is_detected:
        detected += 1
    else:
        missed += 1

    results.append({
        "path": str(path),
        "recommended_action": action,
        "detected": is_detected,
    })

total = detected + missed
rate = (detected / total * 100.0) if total else 0.0
payload = {
    "total": total,
    "detected": detected,
    "missed": missed,
    "detection_rate_percent": rate,
    "samples": results,
}

out_path.write_text(json.dumps(payload, indent=2))
PY
fi

echo "=== Write results ==="
python3 - << PY
import json
from pathlib import Path

out_path = Path("$OUTPUT_JSON")
attack_path = Path("$SIM_RESULTS")
corpus_path = Path("$CORPUS_RESULTS")

attack = json.loads(attack_path.read_text()) if attack_path.exists() else {}
corpus = json.loads(corpus_path.read_text()) if corpus_path.exists() else None

payload = {
    "timestamp": attack.get("timestamp"),
    "attack_sim": attack,
    "corpus_scan": corpus,
    "alerts_path": "$ALERT_LOG",
}

out_path.write_text(json.dumps(payload, indent=2))
print(f"Results saved to: {out_path}")
PY
