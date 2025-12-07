# WinnCoreAV

ARM64-native endpoint detection and response for Linux. Built in Rust.

## What this is

An EDR that runs on ARM64 Linux systems - Graviton instances, Apple Silicon, Snapdragon laptops, Raspberry Pi. Most security tools treat ARM as an afterthought. This one doesn't.

## Current state

**Working:**
- Process monitoring via `/proc` with behavioral analysis
- 50 behavioral detection rules (regex-based, case-insensitive)
- ML inference pipeline (LightGBM/ONNX)
- YARA signature matching (3 rules currently)
- Quarantine with AES-256 encryption
- Response actions (kill process, quarantine file)
- Systemd integration with watchdog
- Prometheus metrics endpoint

**In progress:**
- eBPF-based monitoring (kernel hooks exist, integration WIP)
- Detection rate improvements (currently ~50%, targeting 90%+)
- False positive tuning
- Central management console

**Not started:**
- SIEM integration API
- Threat intel feed integration
- Multi-tenancy

## Architecture
```
┌─────────────────────────────────────────────────────────────────┐
│                         av-daemon                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ProcessMonitor│─▶│  Behavioral  │─▶│   ResponseEngine     │  │
│  │  (/proc)     │  │   Pipeline   │  │ (kill/quarantine)    │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                 │                                      │
│         ▼                 ▼                                      │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │   Heuristics │  │  RuleEngine  │                             │
│  │   Analyzer   │  │  (RegexSet)  │                             │
│  └──────────────┘  └──────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  av-behavioral  │  │  av-ml-detector │  │  av-signatures  │
│  (50 rules)     │  │  (ONNX/LightGBM)│  │  (YARA)         │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

27 crates, ~23k lines of Rust.

## Building
```bash
# Requires Rust 1.70+
cargo build --release

# Run the daemon (needs root for /proc access)
sudo ./target/release/av-daemon

# Run in debug mode
WINNCORE_DEBUG=1 RUST_LOG=info cargo run -p av-daemon
```

## Configuration

Edit `config/daemon.toml`:
```toml
[response]
enabled = true
auto_quarantine = true
auto_kill_critical = false
quarantine_dir = "/var/lib/winncore/quarantine"

[metrics]
enabled = true
port = 9090
```

## Testing
```bash
# Build and run the attack simulator
cargo build -p av-attack-sim
./target/debug/av-attack-sim

# Check alerts
cat /var/log/winncore/alerts.json
```

## Project structure
```
av-daemon/          Main daemon process
av-behavioral/      Behavioral rules engine (RegexSet)
av-ml-detector/     ML inference (6 ONNX models)
av-signatures/      YARA integration
av-quarantine/      Encrypted file quarantine
av-response/        Threat response actions
av-ebpf*/           eBPF probes and loader (WIP)
av-core/            Shared types and utilities
av-cli/             Command-line interface
```

## Detection rules

Rules live in `av-behavioral/rules/linux_behavioral.json`. Format:
```json
{
  "id": "crypto_miner_detection",
  "name": "Cryptocurrency Miner",
  "severity": "High",
  "technique": "T1496",
  "tactic": "Impact",
  "condition": {
    "type": "process",
    "cmdline_contains_any": ["xmrig", "stratum+tcp", "cryptonight"]
  }
}
```

Rules are case-insensitive regex patterns matched against process command lines.

## Why ARM64

- AWS Graviton is 40% cheaper than x86 for same performance
- Apple Silicon Macs need native security tools
- Qualcomm Snapdragon X laptops are shipping
- Most EDRs have janky ARM support or none at all

## Known issues

- Some behavioral rules trigger false positives on build tools (cargo, rustc)
- Detection rate needs improvement for obfuscated commands
- eBPF integration incomplete
- No GUI yet

## License

Apache 2.0

## Contributing

Open an issue first. PRs welcome for:
- New detection rules
- ARM64 performance optimizations
- eBPF probe development
- Documentation
