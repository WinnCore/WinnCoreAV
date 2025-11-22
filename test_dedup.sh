#!/bin/bash
cd ~/projects/WinnCoreAV

echo "🧪 Testing Deduplication"
echo "═══════════════════════════════════════"

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Single File Scan Count
echo ""
rm -f /tmp/daemon_test.log
echo "Test 1: Single file scan count"
echo "─────────────────────────────────"

RUST_LOG=debug ./target/release/av-daemon > /tmp/daemon_test.log 2>&1 &
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

SCAN_COUNT=$(grep -c "av_daemon.*Scanning.*dedup_test" /tmp/daemon_test.log || echo 0)
echo "Scan count: $SCAN_COUNT"

if [ "$SCAN_COUNT" -eq 1 ]; then
    echo "✅ PASSED: Scanned exactly once"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "❌ FAILED: Scanned $SCAN_COUNT times"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

kill $DAEMON_PID 2>/dev/null
rm -f "$TEST_FILE"

# Summary
echo ""
echo "═══════════════════════════════════════"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $TESTS_FAILED"

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo "🎉 ALL TESTS PASSED!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
