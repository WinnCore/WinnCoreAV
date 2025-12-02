#!/bin/bash
set -uo pipefail

MAX_ITERATIONS=10
PROJECT_ROOT="$HOME/projects/WinnCoreAV"
LOG_FILE="/tmp/winncore-daemon-test.log"

run_build() {
  local build_log
  build_log=$(mktemp)
  if (cd "$PROJECT_ROOT" && cargo build --release --bin av-daemon >"$build_log" 2>&1); then
    tail -20 "$build_log"
    rm -f "$build_log"
    return 0
  else
    tail -20 "$build_log"
    rm -f "$build_log"
    return 1
  fi
}

check_daemon_pid() {
  local pid="$1"
  if ps -p "$pid" >/dev/null 2>&1; then
    echo "✅ Daemon is running (PID: $pid)"
    return 0
  fi
  echo "❌ Daemon crashed"
  return 1
}

collect_standalone_log() {
  local pattern="$1"
  if grep -q "$pattern" "$LOG_FILE" 2>/dev/null; then
    return 0
  fi
  return 1
}

for ITER in $(seq 1 $MAX_ITERATIONS); do
  echo ""
  echo "═══════════════════════════════════════"
  echo "ITERATION $ITER: Testing Daemon"
  echo "═══════════════════════════════════════"

  echo "📦 Building av-daemon..."
  if ! run_build; then
    echo "❌ Build failed - fixing..."
    continue
  fi

  echo "🧪 Test 1: Daemon starts and runs"
  : >"$LOG_FILE"
  (cd "$PROJECT_ROOT" && timeout 10s ./target/release/av-daemon >>"$LOG_FILE" 2>&1) &
  DAEMON_PID=$!
  sleep 5
  if ! check_daemon_pid "$DAEMON_PID"; then
    continue
  fi
  kill "$DAEMON_PID" >/dev/null 2>&1 || true
  wait "$DAEMON_PID" 2>/dev/null || true

  echo "🧪 Test 2: File monitoring detects changes"
  : >"$LOG_FILE"
  (cd "$PROJECT_ROOT" && ./target/release/av-daemon >>"$LOG_FILE" 2>&1) &
  DAEMON_PID=$!
  sleep 2
  TEST_FILE="/tmp/test_malware_${ITER}_$$"
  cp "$HOME/malware-research/samples/backdoor_0" "$TEST_FILE"
  sleep 3
  if collect_standalone_log "test_malware_${ITER}_$$"; then
    echo "✅ File monitoring working"
  else
    echo "❌ File monitoring not detecting files"
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    rm -f "$TEST_FILE"
    wait "$DAEMON_PID" 2>/dev/null || true
    continue
  fi
  kill "$DAEMON_PID" >/dev/null 2>&1 || true
  rm -f "$TEST_FILE"
  wait "$DAEMON_PID" 2>/dev/null || true

  echo "🧪 Test 3: Systemd service"
  chmod +x "$PROJECT_ROOT/install/install-daemon.sh"
  if ! (cd "$PROJECT_ROOT" && sudo ./install/install-daemon.sh); then
    echo "❌ Systemd installation failed"
    continue
  fi

  sleep 5

  if systemctl is-active --quiet winncore-av; then
    echo "✅ Systemd service is running"
  else
    echo "❌ Systemd service failed to start"
    sudo journalctl -u winncore-av --no-pager -n 50 || true
    continue
  fi

  echo "🧪 Test 4: Real-time malware detection"
  TEST_FILE="/tmp/test_realtime_${ITER}_$$"
  cp "$HOME/malware-research/samples/backdoor_1" "$TEST_FILE"
  sleep 5

  if sudo journalctl -u winncore-av --since "1 minute ago" | grep -q "THREAT DETECTED"; then
    echo "✅ Real-time detection working"
  else
    echo "❌ Real-time detection not working"
    sudo journalctl -u winncore-av --no-pager -n 50 || true
    rm -f "$TEST_FILE"
    continue
  fi

  rm -f "$TEST_FILE"

  echo ""
  echo "═══════════════════════════════════════"
  echo "✅ ALL TESTS PASSED!"
  echo "═══════════════════════════════════════"
  echo "Daemon is production-ready"
  echo ""
  echo "Usage:"
  echo "  sudo systemctl status winncore-av"
  echo "  sudo journalctl -u winncore-av -f"
  exit 0
done

echo ""
echo "❌ FAILED after $MAX_ITERATIONS iterations"
echo "Review errors above"
exit 1
