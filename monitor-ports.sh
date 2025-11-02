#!/bin/bash
# WinnCoreAV Port Monitor
# Run this periodically to check port security

echo "WinnCoreAV Port Monitor - $(date)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check daemon
if pgrep av-daemon > /dev/null; then
    echo "✅ Daemon: Running"
else
    echo "❌ Daemon: Not running"
    exit 1
fi

# Check port 9090
BINDING=$(sudo ss -tulpn | grep 9090 | awk '{print $5}')
if [ -n "$BINDING" ]; then
    if echo "$BINDING" | grep -q "127.0.0.1"; then
        echo "✅ Port 9090: Secure (localhost: $BINDING)"
    else
        echo "⚠️  Port 9090: EXPOSED ($BINDING) - SECURITY RISK!"
    fi
else
    echo "❌ Port 9090: Not listening"
fi

# Check firewall
if command -v ufw &> /dev/null; then
    if sudo ufw status | grep -q "Status: active"; then
        echo "✅ Firewall: Active"
    else
        echo "⚠️  Firewall: Inactive"
    fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
