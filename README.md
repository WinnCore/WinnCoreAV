# WinnCoreAV

ARM64-native endpoint detection for Linux. Written in Rust.

Most EDR tools bolt on ARM64 support as an afterthought. This was built for ARM64 from day one - Graviton, Apple Silicon, Snapdragon X, Pi.

## What it does

Monitors processes via `/proc`, runs them through behavioral rules and ML classification, quarantines or kills threats. Ships with a systemd service, Prometheus metrics, and encrypted quarantine storage.

Detection stack:
- **Behavioral rules** - 50 regex patterns covering reverse shells, crypto miners, privilege escalation, persistence mechanisms
- **ML classifier** - LightGBM model exported to ONNX, 14 PE/ELF features
- **YARA signatures** - pattern matching for known malware families

## Current status

**Working:**
- Process monitoring and behavioral pipeline
- ML inference (~10ms per file on Graviton3)
- 90%+ detection rate on ARM64 malware samples
- Quarantine with AES-256-GCM encryption
- Kill/quarantine response actions
- Systemd watchdog integration
- Prometheus metrics on :9090

**In progress:**
- eBPF hooks exist but aren't fully wired into the pipeline yet
- False positive tuning
- Central management console

**Not done:**
- SIEM API
- Threat intel feeds
- Windows/macOS ports

## Building
```bash
# Requires Rust 1.75+, LLVM 15+
cargo build --release

# Run tests
cargo test --workspace

# The daemon
sudo ./target/release/av-daemon
```

## Architecture
```
27 crates, roughly organized as:

av-daemon          - main service, ties everything together
av-core            - scanning engine, file analysis
av-behavioral      - rule definitions and matching
av-ml-detector     - ONNX inference wrapper
av-signatures      - YARA rule loading/matching
av-quarantine      - encrypted threat storage
av-response        - kill/quarantine/alert actions
av-ebpf*           - kernel hooks (WIP)
```

The daemon polls `/proc` every 100ms, extracts process metadata + open files, runs them through the behavioral pipeline. Matches trigger response actions based on severity.

## Config

Lives in `config/daemon.toml`:
```toml
[monitoring]
poll_interval_ms = 100
process_cache_size = 10000

[response]
auto_quarantine = true
auto_kill_severity = "critical"

[metrics]
enabled = true
bind = "0.0.0.0:9090"
```

## Why this exists

I wanted to learn Rust and security engineering. ARM64 servers are everywhere now (half of new AWS instances are Graviton) but security tooling hasn't caught up. Seemed like a good problem to solve while learning.

## Stats

- ~23k lines of Rust
- 27 workspace crates  
- 50 behavioral rules
- 90%+ detection rate
- Sub-5% CPU usage in steady state
- ~4MB memory footprint

## Contact

zw@winncore.com

## License

Apache 2.0

---

Built by Zachary Winn / [WinnCore](https://github.com/WinnCore)
