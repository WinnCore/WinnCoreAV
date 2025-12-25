# WinnCoreAV

**ARM64-Native Endpoint Detection for Linux** - Open Source (Apache-2.0)

> ⚠️ **Development Preview** - This is alpha software. Not recommended for production use without extensive testing in your environment.

## What This Is

WinnCoreAV is an experimental endpoint detection and response (EDR) agent built in Rust, optimized for ARM64 Linux systems (AWS Graviton, Apple Silicon, Raspberry Pi, Qualcomm Snapdragon).

## Current Status

| Component | Status | Notes |
|-----------|--------|-------|
| Process Monitoring | ✅ Working | Polls /proc every 100ms |
| ML Detection | ✅ Working | LightGBM/ONNX inference |
| YARA Scanning | ✅ Working | YARA-X integration |
| Behavioral Rules | ✅ Working | 50+ pattern rules |
| Quarantine | ✅ Working | AES-256-GCM encrypted |
| Response Actions | ✅ Working | Kill process, quarantine file |
| Prometheus Metrics | ✅ Working | Port 9090 |
| Systemd Service | ✅ Working | Watchdog enabled |
| eBPF Hooks | 🚧 Partial | Code exists, not integrated |
| Real-time File Mon | 🚧 Partial | Fanotify scaffolding only |
| Management Console | ❌ Planned | Not started |
| SIEM Integration | ❌ Planned | Not started |

## Performance (Measured)

Tested on Raspberry Pi 4 (4GB RAM) with synthetic workload:

| Metric | Idle | Under Load | Notes |
|--------|------|------------|-------|
| CPU Usage | <1% | 3-8% | Depends on file activity |
| Memory (RSS) | ~8MB | ~32MB peak | Steady-state varies |
| Scan Latency | - | <50ms p95 | Per-file YARA+ML |

## Detection Capabilities

**Honest assessment**: Detection rates depend heavily on the threat landscape and sample set.

- Tested against: ~100 public ARM64 Linux malware samples
- Detection rate: ~70-85% (varies by malware family)
- False positive rate: Not formally measured

We have NOT been evaluated by AV-TEST, VirusTotal, or any third-party lab.

## Installation
```bash
# Build from source (requires Rust 1.70+)
git clone https://github.com/WinnCore/WinnCoreAV.git
cd WinnCoreAV
cargo build --release

# Install (requires root)
sudo cp target/release/av-daemon /usr/local/bin/
sudo cp systemd/winncore.service /etc/systemd/system/
sudo mkdir -p /etc/winncore /var/lib/winncore/quarantine /var/log/winncore
sudo cp config/daemon.toml /etc/winncore/

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable winncore
sudo systemctl start winncore
```

## Required Privileges

WinnCoreAV requires root/CAP_SYS_PTRACE to:
- Read /proc for all processes
- Kill malicious processes
- Move files to quarantine
- (Future) Load eBPF programs

## Architecture
```
winncore-workspace/
├── av-daemon/       # Main service binary
├── av-core/         # Detection orchestration
├── av-behavioral/   # Behavioral rule engine
├── av-ml-detector/  # ML inference (ONNX)
├── av-signatures/   # YARA integration
├── av-quarantine/   # Encrypted file quarantine
├── av-response/     # Kill/quarantine actions
├── av-ebpf*/        # eBPF hooks (WIP)
└── av-cli/          # Command-line interface
```

## Roadmap

See [Issues](https://github.com/WinnCore/WinnCoreAV/issues) for planned features.

**Next priorities:**
1. Wire eBPF hooks into detection pipeline
2. Complete fanotify real-time monitoring
3. Reduce false positives with allowlisting
4. Add basic web console

## Contributing

Contributions welcome! This is a learning project that aims to become production-quality.

## License

Apache-2.0

---

*Built by [WinnCore](https://github.com/WinnCore) - Honest security software.*
