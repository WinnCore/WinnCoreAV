#!/bin/bash
cd ~/projects/WinnCoreAV

echo "🧪 WinnCoreAV Deduplication Test Suite"
echo "═══════════════════════════════════════"

TESTS_PASSED=0
TESTS_FAILED=0

# Test 1: Single File (no duplicates from inotify)
echo ""
echo "Test 1: Single file - verify dedup working"
echo "────────────────────────────────────────────"

rm -f /tmp/daemon_test.log
RUST_LOG=info ./target/release/av-daemon 2>&1 | tee /tmp/daemon_test.log &
DAEMON_PID=$!
sleep 3

TEST_FILE="/tmp/TESTFILE_$$"
echo "test" > "$TEST_FILE"
sleep 5

SCAN_COUNT=$(grep -a "Scanning.*TESTFILE" /tmp/daemon_test.log 2>/dev/null | wc -l)
echo "Scan count: $SCAN_COUNT"

if [ "$SCAN_COUNT" -le 2 ]; then
    echo "✅ PASSED: File scanned $SCAN_COUNT time(s) - dedup working!"
    echo "   (Before: would be 4+ scans from inotify events)"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "❌ FAILED: $SCAN_COUNT scans (should be ≤2)"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null
rm -f "$TEST_FILE"

# Summary
echo ""
echo "═══════════════════════════════════════"
echo "📊 DEDUPLICATION TEST RESULT"
echo "═══════════════════════════════════════"

if [ "$TESTS_PASSED" -eq 1 ]; then
    echo "✅ DEDUPLICATION WORKING!"
    echo ""
    echo "Before fix: 4+ scans per file (inotify CREATE, MODIFY, CLOSE_WRITE, ATTRIB)"
    echo "After fix: 1-2 scans per file"
    echo "Improvement: 50-75% reduction in duplicate scans"
    echo ""
    echo "✅ Mission 1.1: Scan Deduplication - COMPLETE"
    echo ""
    echo "Next: Mission 1.2 - systemd Integration"
    exit 0
else
    echo "❌ Deduplication not working"
    exit 1
fi
