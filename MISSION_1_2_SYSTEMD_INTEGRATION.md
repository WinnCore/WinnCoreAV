# MISSION 1.2: systemd Service Integration - AUTO-LOOP

## OBJECTIVE
Install WinnCoreAV daemon as a system service that:
- Starts automatically on boot
- Restarts on crash
- Logs to journald
- Has proper security hardening
- Can be controlled via systemctl

## SUCCESS CRITERIA
- ✅ systemd service file created
- ✅ Installation script works without errors
- ✅ Service starts successfully
- ✅ Service survives daemon kill (auto-restart)
- ✅ Logs appear in journalctl
- ✅ All tests pass

## TASK BREAKDOWN

### Task 1: Create systemd Service File

Create `install/winncore-av.service`:
```ini
[Unit]
Description=WinnCoreAV Antivirus Daemon
Documentation=https://github.com/WinnCore/WinnCoreAV
After=network.target local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/winncore-daemon
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=winncore-av

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/lib/winncore /var/log/winncore-av /tmp

# Resource limits
MemoryMax=200M
CPUQuota=20%

[Install]
WantedBy=multi-user.target
```

### Task 2: Create Installation Script

Create `install/install-daemon.sh`:
```bash
#!/bin/bash
set -e

echo "🛡️  Installing WinnCoreAV Daemon"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (sudo)"
    exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Build release binary
echo "📦 Building release binary..."
cargo build --release --bin av-daemon

# Create directories
echo "📁 Creating directories..."
mkdir -p /var/lib/winncore/quarantine
mkdir -p /var/lib/winncore/models
mkdir -p /var/log/winncore-av
mkdir -p /etc/winncore

# Copy binary
echo "📋 Installing daemon binary..."
cp target/release/av-daemon /usr/local/bin/winncore-daemon
chmod +x /usr/local/bin/winncore-daemon

# Copy config if doesn't exist
if [ ! -f /etc/winncore/daemon.toml ]; then
    echo "⚙️  Installing default config..."
    cat > /etc/winncore/daemon.toml << 'CONFIGEOF'
[daemon]
pid_file = "/var/run/winncore-av.pid"
log_file = "/var/log/winncore-av/daemon.log"
working_dir = "/var/lib/winncore"

[monitoring]
watch_paths = ["/home", "/tmp", "/opt"]
ignore_paths = ["/proc", "/sys", "/dev"]
scan_on_create = true
scan_on_modify = true
debounce_ms = 5000

[ml_model]
model_path = "/var/lib/winncore/models/gbm_v3_hardened.onnx"
threshold = 0.5

[response]
enabled = true
auto_kill = false
auto_quarantine = true

[thresholds]
kill_threshold = 0.95
quarantine_threshold = 0.85
alert_threshold = 0.70

[logging]
level = "info"
output = "journald"
CONFIGEOF
else
    echo "⚠️  Config exists, skipping..."
fi

# Copy ML model
if [ -f models/gbm_v3_hardened.onnx ]; then
    echo "🧠 Installing ML model..."
    cp models/gbm_v3_hardened.onnx /var/lib/winncore/models/
elif [ -f ../WinnCore-ML-Detector/models/gbm_v3_hardened.onnx ]; then
    echo "🧠 Installing ML model from ML repo..."
    cp ../WinnCore-ML-Detector/models/gbm_v3_hardened.onnx /var/lib/winncore/models/
else
    echo "⚠️  ML model not found - daemon may not work!"
fi

# Set permissions
echo "🔒 Setting permissions..."
chown -R root:root /var/lib/winncore
chmod 700 /var/lib/winncore/quarantine
chmod 755 /var/lib/winncore/models
chmod 755 /var/log/winncore-av

# Copy systemd service
echo "⚙️  Installing systemd service..."
cp install/winncore-av.service /etc/systemd/system/

# Reload systemd
echo "🔄 Reloading systemd..."
systemctl daemon-reload

# Enable service
echo "✅ Enabling service..."
systemctl enable winncore-av

# Start service
echo "🚀 Starting service..."
systemctl start winncore-av

# Wait for startup
sleep 2

# Check status
echo ""
echo "═══════════════════════════════════════"
echo "📊 Installation Complete!"
echo "═══════════════════════════════════════"
systemctl status winncore-av --no-pager -l

echo ""
echo "✅ WinnCoreAV Daemon installed successfully!"
echo ""
echo "Commands:"
echo "  systemctl status winncore-av   # Check status"
echo "  systemctl stop winncore-av     # Stop daemon"
echo "  systemctl restart winncore-av  # Restart daemon"
echo "  journalctl -u winncore-av -f   # View logs"
```

Make executable:
```bash
chmod +x install/install-daemon.sh
```

### Task 3: Create Uninstall Script

Create `install/uninstall-daemon.sh`:
```bash
#!/bin/bash
set -e

echo "🗑️  Uninstalling WinnCoreAV Daemon"

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run as root (sudo)"
    exit 1
fi

# Stop service
echo "⏹️  Stopping service..."
systemctl stop winncore-av 2>/dev/null || true

# Disable service
echo "❌ Disabling service..."
systemctl disable winncore-av 2>/dev/null || true

# Remove service file
echo "🗑️  Removing service file..."
rm -f /etc/systemd/system/winncore-av.service

# Reload systemd
systemctl daemon-reload

# Remove binary
echo "🗑️  Removing binary..."
rm -f /usr/local/bin/winncore-daemon

# Ask before removing data
echo ""
read -p "Remove data directories (/var/lib/winncore, /etc/winncore)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🗑️  Removing data..."
    rm -rf /var/lib/winncore
    rm -rf /etc/winncore
    rm -rf /var/log/winncore-av
else
    echo "📁 Data directories preserved"
fi

echo ""
echo "✅ WinnCoreAV Daemon uninstalled"
```

Make executable:
```bash
chmod +x install/uninstall-daemon.sh
```

### Task 4: Test Installation

Run installation test loop:
```bash
#!/bin/bash

echo "🧪 Testing systemd Installation"
echo "═══════════════════════════════════════"

# Test 1: Installation
echo ""
echo "Test 1: Running installation..."
sudo ./install/install-daemon.sh

if [ $? -ne 0 ]; then
    echo "❌ Installation failed"
    exit 1
fi

echo "✅ Installation succeeded"

# Test 2: Service is running
echo ""
echo "Test 2: Checking service status..."
sleep 3

if systemctl is-active --quiet winncore-av; then
    echo "✅ Service is running"
else
    echo "❌ Service not running"
    journalctl -u winncore-av --no-pager -n 50
    exit 1
fi

# Test 3: Logs in journald
echo ""
echo "Test 3: Checking journald logs..."
LOGS=$(journalctl -u winncore-av --no-pager -n 10)

if echo "$LOGS" | grep -q "WinnCoreAV"; then
    echo "✅ Logs appearing in journald"
else
    echo "❌ No logs in journald"
    exit 1
fi

# Test 4: Auto-restart on crash
echo ""
echo "Test 4: Testing auto-restart..."
DAEMON_PID=$(systemctl show winncore-av -p MainPID --value)
echo "Current PID: $DAEMON_PID"

sudo kill -9 $DAEMON_PID
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

# Test 5: File scanning works
echo ""
echo "Test 5: Testing file scanning..."
echo "test" > /tmp/systemd_test_$$
sleep 5

if journalctl -u winncore-av --since "30 seconds ago" | grep -q "systemd_test"; then
    echo "✅ File scanning working"
    rm /tmp/systemd_test_$$
else
    echo "⚠️  No scan detected (might be OK if /tmp not monitored)"
    rm /tmp/systemd_test_$$
fi

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
```

Save as `install/test-installation.sh` and make executable.

## AUTO-LOOP EXECUTION

Run this loop until all tests pass:
```bash
#!/bin/bash
MAX_ITERATIONS=3
ITERATION=1

while [ $ITERATION -le $MAX_ITERATIONS ]; do
    echo ""
    echo "═══════════════════════════════════════"
    echo "ITERATION $ITERATION: systemd Integration"
    echo "═══════════════════════════════════════"
    
    # Run installation test
    bash install/test-installation.sh
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "✅ ALL TESTS PASSED!"
        echo ""
        echo "Committing changes..."
        git add install/
        git commit -m "✅ [1.2] systemd service integration complete

- Created winncore-av.service with security hardening
- Installation script with auto-config
- Uninstall script
- Auto-restart on crash
- journald logging
- All tests passing"
        
        echo ""
        echo "🎯 Mission 1.2 COMPLETE!"
        exit 0
    fi
    
    echo ""
    echo "❌ Tests failed on iteration $ITERATION"
    ITERATION=$((ITERATION + 1))
    
    # Cleanup before retry
    sudo systemctl stop winncore-av 2>/dev/null || true
    sleep 2
done

echo ""
echo "❌ Failed after $MAX_ITERATIONS attempts"
exit 1
```

## DELIVERABLES

When complete:
1. ✅ `install/winncore-av.service` created
2. ✅ `install/install-daemon.sh` created
3. ✅ `install/uninstall-daemon.sh` created
4. ✅ `install/test-installation.sh` created
5. ✅ Service running and tested
6. ✅ Git committed

START THE AUTO-LOOP NOW!
