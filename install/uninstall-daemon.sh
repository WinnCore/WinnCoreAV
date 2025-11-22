#!/bin/bash
set -euo pipefail

echo "🗑️  Uninstalling WinnCoreAV Daemon"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "❌ Please run as root (sudo)"
    exit 1
fi

echo "⏹️  Stopping service..."
systemctl stop winncore-av 2>/dev/null || true

echo "❌ Disabling service..."
systemctl disable winncore-av 2>/dev/null || true

echo "🗑️  Removing service file..."
rm -f /etc/systemd/system/winncore-av.service

systemctl daemon-reload

echo "🗑️  Removing binary..."
rm -f /usr/local/bin/winncore-daemon

echo ""
read -p "Remove data directories (/var/lib/winncore, /etc/winncore, /var/log/winncore-av)? [y/N] " -r CONFIRM
echo
if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "🗑️  Removing data..."
    rm -rf /var/lib/winncore
    rm -rf /etc/winncore
    rm -rf /var/log/winncore-av
else
    echo "📁 Data directories preserved"
fi

echo ""
echo "✅ WinnCoreAV Daemon uninstalled"
