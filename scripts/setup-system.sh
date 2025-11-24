#!/bin/bash
set -euo pipefail

echo "=== WinnCoreAV System Setup ==="

# Create system user (no login shell, no home)
if ! id winncore &>/dev/null; then
    sudo useradd --system --no-create-home --shell /usr/sbin/nologin winncore
    echo "✅ Created winncore user"
fi

# Create directory structure
sudo mkdir -p /etc/winncore/{rules,keys}
sudo mkdir -p /var/lib/winncore/{quarantine,cache,state,hashes}
sudo mkdir -p /var/log/winncore
sudo mkdir -p /usr/lib/winncore/bpf

# Set ownership
sudo chown -R root:winncore /etc/winncore
sudo chmod 750 /etc/winncore
sudo chmod 640 /etc/winncore/*.toml 2>/dev/null || true

sudo chown -R winncore:winncore /var/lib/winncore
sudo chmod 750 /var/lib/winncore
sudo chmod 700 /var/lib/winncore/quarantine

sudo chown -R winncore:winncore /var/log/winncore
sudo chmod 750 /var/log/winncore

echo "✅ Directory structure created"

# Create default config
if [ ! -f /etc/winncore/config.toml ]; then
    sudo tee /etc/winncore/config.toml > /dev/null << 'CONFIG'
[daemon]
user = "winncore"
pid_file = "/run/winncore/av-daemon.pid"
log_level = "info"

[ebpf]
enabled = true
fallback_to_procfs = true
bpf_map_path = "/sys/fs/bpf/winncore"
ring_buffer_size_mb = 64

[scanning]
max_file_size_mb = 100
scan_timeout_seconds = 30
concurrent_scans = 4

[ml]
model_path = "/var/lib/winncore/cache/model.onnx"
threshold = 0.7

[rules]
path = "/etc/winncore/rules"
hot_reload = true
check_interval_seconds = 30

[quarantine]
path = "/var/lib/winncore/quarantine"
encryption_enabled = true
max_size_gb = 10

[metrics]
enabled = true
bind = "127.0.0.1:9090"

[telemetry]
enabled = false
endpoint = ""
format = "jsonl"
CONFIG
    echo "✅ Default config created"
fi

echo "=== Setup Complete ==="
