#!/bin/bash
cd ~/projects/WinnCoreAV

echo "🧪 WinnCoreAV Deduplication Test Suite (FIXED)"
echo "═══════════════════════════════════════"

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Single File Scan Count
echo ""
echo "Test 1: Single file scan count"
echo "─────────────────────────────────"

rm -f /tmp/daemon_test.log
RUST_LOG=debug ./target/release/av-daemon 2>&1 | tee /tmp/daemon_test.log &
DAEMON_PID=$!
sleep 3

if ! ps -p $DAEMON_PID > /dev/null; then
    echo "❌ FAILED: Daemon crashed"
    cat /tmp/daemon_test.log
    exit 1
fi

TEST_FILE="/tmp/dedup_test_$$"
echo "test" > "$TEST_FILE"
sleep 5

SCAN_COUNT=$(grep -a "Scanning.*dedup_test" /tmp/daemon_test.log 2>/dev/null | wc -l)
echo "Scan count: $SCAN_COUNT (expected: 1)"
echo "Debug: Showing scan lines found:"
grep -a "Scanning" /tmp/daemon_test.log 2>/dev/null | tail -5

if [ "$SCAN_COUNT" -eq 1 ]; then
    echo "✅ PASSED: Scanned exactly once"
    TESTS_PASSED=$((TESTS_PASSED + 1))
elif [ "$SCAN_COUNT" -eq 0 ]; then
    echo "⚠️  WARNING: No scans detected"
    TESTS_FAILED=$((TESTS_FAILED + 1))
else
    echo "❌ FAILED: Scanned $SCAN_COUNT times"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null
rm -f "$TEST_FILE"

echo ""
echo "═══════════════════════════════════════"
echo "📊 QUICK TEST SUMMARY"
echo "═══════════════════════════════════════"
echo "Tests passed: $TESTS_PASSED / 1"
echo "Tests failed: $TESTS_FAILED / 1"

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo "✅ Test 1 PASSED!"
else
    echo "❌ Test 1 FAILED - check output above"
fi
