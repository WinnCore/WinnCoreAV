#!/usr/bin/env bash
set -euo pipefail

echo "=== WinnCoreAV Performance Benchmark Suite ==="

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo
echo "=== Build (release) ==="
CARGO_NET_OFFLINE=true cargo build --release --workspace >/dev/null
echo "Built release binaries."

echo
echo "=== Benchmark 1: Single File Scan Speed ==="
ITERATIONS=100
TOTAL_MS=0

for _ in $(seq 1 "${ITERATIONS}"); do
  START_NS=$(date +%s%N)
  ./target/release/av-cli scan /bin/ls --quiet >/dev/null 2>&1 || true
  END_NS=$(date +%s%N)
  DURATION_MS=$(( (END_NS - START_NS) / 1000000 ))
  TOTAL_MS=$(( TOTAL_MS + DURATION_MS ))
done

AVG_MS=$(( TOTAL_MS / ITERATIONS ))
if [[ "${AVG_MS}" -gt 0 ]]; then
  THROUGHPUT=$(( 1000 / AVG_MS ))
else
  THROUGHPUT=0
fi

echo "Iterations: ${ITERATIONS}"
echo "Average scan time: ${AVG_MS}ms"
echo "Throughput: ~${THROUGHPUT} scans/sec"

echo
echo "=== Benchmark 2: Directory Scan Throughput ==="
TEST_DIR="$(mktemp -d)"
for i in $(seq 1 1000); do
  dd if=/dev/urandom of="${TEST_DIR}/file_${i}.bin" bs=1K count=1 2>/dev/null
done

START_NS=$(date +%s%N)
./target/release/av-cli scan "${TEST_DIR}" --quiet >/dev/null 2>&1 || true
END_NS=$(date +%s%N)
DURATION_MS=$(( (END_NS - START_NS) / 1000000 ))

if [[ "${DURATION_MS}" -gt 0 ]]; then
  FILES_PER_SEC=$(( 1000 * 1000 / DURATION_MS ))
else
  FILES_PER_SEC=0
fi

echo "Files scanned: 1000"
echo "Total time: ${DURATION_MS}ms"
echo "Throughput: ${FILES_PER_SEC} files/sec"

rm -rf "${TEST_DIR}"

echo
echo "=== Benchmark 3: Daemon Memory Footprint ==="
./target/release/av-daemon >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 2

if kill -0 "${DAEMON_PID}" 2>/dev/null; then
  MEM_KB="$(ps -o rss= -p "${DAEMON_PID}" | tr -d ' ')"
  MEM_MB=$(( MEM_KB / 1024 ))
  CPU_PCT="$(ps -o %cpu= -p "${DAEMON_PID}" | tr -d ' ')"
  echo "Daemon PID: ${DAEMON_PID}"
  echo "Resident memory: ${MEM_KB} KB (${MEM_MB} MB)"
  echo "CPU (idle): ${CPU_PCT}%"
  kill "${DAEMON_PID}" 2>/dev/null || true
  wait "${DAEMON_PID}" 2>/dev/null || true
else
  echo "Daemon failed to start."
fi

echo
echo "=== Benchmark 4: Rule Evaluation Speed (synthetic) ==="
RULE_ITERATIONS=10000
START_NS=$(date +%s%N)
for _ in $(seq 1 "${RULE_ITERATIONS}"); do
  echo "test command line with some content" | grep -qE 'base64|nc -e|/dev/tcp' || true
done
END_NS=$(date +%s%N)
DURATION_MS=$(( (END_NS - START_NS) / 1000000 ))

if [[ "${DURATION_MS}" -gt 0 ]]; then
  RULES_PER_SEC=$(( RULE_ITERATIONS * 1000 / DURATION_MS ))
else
  RULES_PER_SEC=0
fi

echo "Rule evaluations: ${RULE_ITERATIONS}"
echo "Total time: ${DURATION_MS}ms"
echo "Throughput: ${RULES_PER_SEC} evals/sec"

echo
echo "=== Benchmark Summary ==="
echo "Single scan avg:     ${AVG_MS}ms"
echo "Single scan rate:    ~${THROUGHPUT} scans/sec"
echo "Directory throughput: ${FILES_PER_SEC} files/sec"
echo "Rule eval:           ${RULES_PER_SEC} evals/sec"

