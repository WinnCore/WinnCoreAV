#!/bin/bash
set -euo pipefail

echo "🛡️  Installing WinnCoreAV Daemon"

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "❌ Please run as root (sudo)"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "📦 Building release binary..."
cargo build --release --bin av-daemon

echo "📁 Creating directories..."
mkdir -p /var/lib/winncore/quarantine
mkdir -p /var/lib/winncore/models
mkdir -p /var/log/winncore-av
mkdir -p /etc/winncore

echo "📋 Installing daemon binary..."
cp target/release/av-daemon /usr/local/bin/winncore-daemon
chmod +x /usr/local/bin/winncore-daemon

if [ ! -f /etc/winncore/daemon.toml ]; then
    echo "⚙️  Installing default config..."
    cat > /etc/winncore/daemon.toml <<'CONFIGEOF'
[daemon]
pid_file = "/var/run/winncore-av.pid"
log_file = "/var/log/winncore-av/daemon.log"
working_dir = "/var/lib/winncore"

[monitoring]
watch_paths = ["/home", "/tmp", "/opt"]
ignore_paths = ["/proc", "/sys", "/dev"]
scan_on_create = true
scan_on_modify = true
scan_on_execute = true
debounce_ms = 5000

[response]
enabled = true
auto_kill = false
auto_quarantine = true
auto_block_network = false

[thresholds]
kill_threshold = 0.95
quarantine_threshold = 0.85
alert_threshold = 0.70

[limits]
max_actions_per_minute = 10
max_scan_queue = 1000
scan_timeout_seconds = 30

[logging]
level = "info"
CONFIGEOF
else
    echo "⚠️  Config exists, skipping..."
fi

if [ -f models/gbm_v3_hardened.onnx ]; then
    echo "🧠 Installing ML model..."
    cp models/gbm_v3_hardened.onnx /var/lib/winncore/models/
elif [ -f ../WinnCore-ML-Detector/models/gbm_v3_hardened.onnx ]; then
    echo "🧠 Installing ML model from ML repo..."
    cp ../WinnCore-ML-Detector/models/gbm_v3_hardened.onnx /var/lib/winncore/models/
else
    echo "⚠️  ML model not found - daemon may not work!"
fi

echo "🔒 Setting permissions..."
chown -R root:root /var/lib/winncore
chmod 700 /var/lib/winncore/quarantine
chmod 755 /var/lib/winncore/models
chmod 755 /var/log/winncore-av

if [ -f install/winncore-av.service ]; then
    echo "⚙️  Installing systemd service..."
    cp install/winncore-av.service /etc/systemd/system/winncore-av.service
else
    echo "❌ Service file missing"
    exit 1
fi

echo "🔄 Reloading systemd..."
systemctl daemon-reload

echo "✅ Enabling service..."
systemctl enable winncore-av

echo "🚀 Starting service..."
systemctl start winncore-av

sleep 2

echo ""
echo "═══════════════════════════════════════"
echo "📊 Installation Complete!"
echo "═══════════════════════════════════════"
systemctl status winncore-av --no-pager -l || true

echo ""
echo "✅ WinnCoreAV Daemon installed successfully!"
echo ""
echo "Commands:"
echo "  systemctl status winncore-av"
echo "  systemctl stop winncore-av"
echo "  systemctl restart winncore-av"
echo "  journalctl -u winncore-av -f"
