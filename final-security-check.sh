#!/bin/bash

echo "═══════════════════════════════════════════"
echo "FINAL SECURITY CHECKLIST"
echo "═══════════════════════════════════════════"

PASS=0
FAIL=0

# Test 1: Daemon running
if pgrep av-daemon > /dev/null; then
    echo "✅ Daemon is running"
    ((PASS++))
else
    echo "❌ Daemon is NOT running"
    ((FAIL++))
fi

# Test 2: Port 9090 bound to localhost
if sudo ss -tulpn | grep 9090 | grep -q "127.0.0.1:9090"; then
    echo "✅ Port 9090 bound to localhost (secure)"
    ((PASS++))
elif sudo ss -tulpn | grep -q ":9090"; then
    echo "❌ Port 9090 NOT bound to localhost (insecure)"
    ((FAIL++))
else
    echo "⚠️  Port 9090 not listening"
fi

# Test 3: Localhost access works
if curl -s --connect-timeout 2 http://127.0.0.1:9090/metrics > /dev/null 2>&1; then
    echo "✅ Localhost access works"
    ((PASS++))
else
    echo "❌ Localhost access failed"
    ((FAIL++))
fi

# Test 4: Firewall active
if command -v ufw &> /dev/null; then
    if sudo ufw status | grep -q "Status: active"; then
        echo "✅ Firewall is active"
        ((PASS++))
    else
        echo "⚠️  Firewall is inactive"
    fi
fi

# Test 5: No other WinnCore ports open
OTHER_PORTS=$(sudo ss -tulpn | grep av-daemon | grep -v ":9090" | wc -l)
if [ "$OTHER_PORTS" -eq 0 ]; then
    echo "✅ No unexpected ports open"
    ((PASS++))
else
    echo "⚠️  $OTHER_PORTS other ports detected"
fi

echo "═══════════════════════════════════════════"
echo "Results: $PASS passed, $FAIL failed"

if [ $FAIL -eq 0 ]; then
    echo "🎉 ALL SECURITY CHECKS PASSED!"
else
    echo "⚠️  SOME CHECKS FAILED - REVIEW ABOVE"
fi
echo "═══════════════════════════════════════════"

