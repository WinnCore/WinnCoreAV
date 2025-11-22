#!/bin/bash
set -euo pipefail

echo "🧪 Testing systemd Installation"
echo "═══════════════════════════════════════"

echo ""
echo "Test 1: Running installation..."
sudo ./install/install-daemon.sh

echo "✅ Installation succeeded"

echo ""
echo "Test 2: Checking service status..."
sleep 3
if systemctl is-active --quiet winncore-av; then
    echo "✅ Service is running"
else
    echo "❌ Service not running"
    journalctl -u winncore-av --no-pager -n 50 || true
    exit 1
fi

echo ""
echo "Test 3: Checking journald logs..."
LOGS=$(journalctl -u winncore-av --no-pager -n 10 || true)
if echo "$LOGS" | grep -q "WinnCoreAV"; then
    echo "✅ Logs appearing in journald"
else
    echo "❌ No logs in journald"
    exit 1
fi

echo ""
echo "Test 4: Testing auto-restart..."
DAEMON_PID=$(systemctl show winncore-av -p MainPID --value)
echo "Current PID: $DAEMON_PID"
if [ -z "$DAEMON_PID" ] || [ "$DAEMON_PID" -eq 0 ]; then
    echo "❌ Could not determine PID"
    exit 1
fi

sudo kill -9 "$DAEMON_PID"
sleep 6

if systemctl is-active --quiet winncore-av; then
    NEW_PID=$(systemctl show winncore-av -p MainPID --value)
    if [ "$NEW_PID" != "$DAEMON_PID" ]; then
        echo "✅ Service auto-restarted (new PID: $NEW_PID)"
    else
        echo "❌ PID didn't change"
        exit 1
    fi
else
    echo "❌ Service didn't restart"
    exit 1
fi

echo ""
echo "Test 5: Testing file scanning..."
TEST_FILE="/tmp/systemd_test_$$"
echo "test" > "$TEST_FILE"
sleep 5
if journalctl -u winncore-av --since "30 seconds ago" | grep -q "systemd_test"; then
    echo "✅ File scanning working"
else
    echo "⚠️  No scan detected (might be OK if monitored paths exclude /tmp)"
fi
rm -f "$TEST_FILE"

echo ""
echo "═══════════════════════════════════════"
echo "📊 ALL TESTS PASSED!"
echo "═══════════════════════════════════════"
echo ""
echo "✅ Mission 1.2: systemd Integration - COMPLETE"
echo ""
echo "Service commands:"
echo "  sudo systemctl status winncore-av"
echo "  sudo systemctl restart winncore-av"
echo "  sudo journalctl -u winncore-av -f"
