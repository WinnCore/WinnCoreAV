# WinnCoreAV

**ARM64-native Linux Antivirus with Real-time Monitoring & Prometheus Metrics**

[![CI Status](https://github.com/WinnCore/WinnCoreAV/actions/workflows/ci.yml/badge.svg)](https://github.com/WinnCore/WinnCoreAV/actions)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-ARM64%20Linux-orange.svg)]()

---

## What's New in v0.1.1

### Major Features Added
- Prometheus Metrics Integration  
  - Real-time monitoring endpoint at `http://localhost:9090/metrics`  
  - Track scans, threats, performance, and system resources  
  - Production-ready observability

- Enhanced CI/CD Pipeline  
  - 11 comprehensive CI checks  
  - License compliance validation  
  - Multi-architecture support (ARM64 + x86_64)

- License Compliance  
  - Workspace-level MIT OR Apache-2.0 licensing  
  - Full cargo-deny integration  
  - All dependencies approved and validated

- Code Quality Improvements  
  - Auto-formatted with rustfmt  
  - Clippy warnings resolved  
  - Merge conflicts cleaned up  
  - Removed unused dependencies (lazy_static, tiny_http)

---

## Prometheus Metrics

WinnCoreAV exposes metrics for monitoring.

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `av_scans_total` | Counter | Total number of scans performed |
| `av_threats_detected_total` | Counter | Total threats detected and quarantined |
| `av_scan_duration_seconds` | Histogram | Time taken for each scan operation |
| `av_files_scanned_total` | Counter | Total files scanned |
| `av_quarantine_size_bytes` | Gauge | Current size of quarantine directory |
| `av_worker_threads` | Gauge | Number of active worker threads |
| `av_memory_usage_bytes` | Gauge | Current memory usage |

### Accessing Metrics
```bash
# Start the daemon
cargo run --release --bin av-daemon

# Query metrics (in another terminal)
curl http://127.0.0.1:9090/metrics
````

### Integration with Prometheus

```yaml
scrape_configs:
  - job_name: 'winncore-av'
    static_configs:
      - targets: ['localhost:9090']
```

---

## Architecture

```
WinnCoreAV/
├── av-core/          # Core scanning engine with YARA integration
├── av-cli/           # Command-line interface
├── av-daemon/        # Background daemon with metrics server
├── av-signatures/    # Signature management
├── av-quarantine/    # Quarantine management
└── .github/
    └── workflows/    # CI/CD pipelines
```

---

## Installation

### Prerequisites

* Platform: ARM64 Linux (tested on Snapdragon X Elite)
* Rust: 1.70+ (install from [https://rustup.rs](https://rustup.rs))
* YARA: 4.x+ (for signature scanning)

### Quick Install

```bash
git clone https://github.com/WinnCore/WinnCoreAV.git
cd WinnCoreAV

cargo build --release --all

sudo cp target/release/av-cli /usr/local/bin/
sudo cp target/release/av-daemon /usr/local/bin/

av-cli --version
```

---

## Usage

### Command Line Interface

```bash
# Scan a single file
av-cli scan /path/to/file

# Scan a directory recursively
av-cli scan /path/to/directory

# Scan with verbose output
av-cli scan /home/user/Downloads --verbose

# List quarantined files
av-cli quarantine list

# Restore a quarantined file
av-cli quarantine restore <file-id>
```

### Daemon Mode

```bash
# Start the background daemon
av-daemon

# Features:
# - Real-time file monitoring
# - Automatic threat quarantine
# - Prometheus metrics on :9090
# - Desktop notifications

# Stop the daemon
pkill av-daemon
```

---

## Security Features

### Implemented

* YARA-based Signature Scanning

  * Fast pattern matching
  * Custom signature support
  * Regular signature updates

* Real-time File Monitoring

  * Watches Downloads, Desktop, Documents
  * Automatic scanning on file creation/modification
  * Configurable exclusion patterns

* Automatic Quarantine

  * Isolates detected threats
  * Preserves file metadata
  * Safe restoration capability

### Planned

* Heuristic analysis
* Cloud-based threat intelligence
* Scheduled scanning
* Email scanning
* Web traffic inspection

---

## Testing

```bash
# Unit tests
cargo test --all

# Integration tests
cargo test --test '*'
```

### CI/CD Status

All checks must pass before merging:

* Code formatting (rustfmt)
* Linting (clippy)
* Build (ARM64 + x86_64)
* Unit tests
* License compliance
* Security advisories
* Metrics integration test

---

## License

This project is dual-licensed under:

* MIT License ([LICENSE-MIT](LICENSE-MIT) or [http://opensource.org/licenses/MIT](http://opensource.org/licenses/MIT))
* Apache License 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))

You may choose either license.

### Dependency Licenses

Permissive licenses only:

* MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause
* ISC, Unicode-3.0, CC0-1.0, MPL-2.0

See [deny.toml](deny.toml) for complete license policy.

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes
4. Run tests: `cargo test --all`
5. Format code: `cargo fmt --all`
6. Check lints: `cargo clippy --all-targets`
7. Open a pull request

All contributions must pass CI.

---

## Configuration

Create `~/.config/winncore-av/config.toml`:

```toml
[monitoring]
watch_paths = [
    "~/Downloads",
    "~/Desktop",
    "~/Documents"
]

exclude_patterns = [
    "**/node_modules/**",
    "**/.git/**",
    "**/target/**"
]

[quarantine]
path = "~/.local/share/winncore-av/quarantine"
auto_quarantine = true

[notifications]
enabled = true
desktop_notifications = true

[metrics]
enabled = true
port = 9090
host = "127.0.0.1"

[scanning]
worker_threads = 8
max_file_size = "100MB"
```

---

## Performance

Tested on Snapdragon X Elite (ARM64):

| Operation               | Performance        |
| ----------------------- | ------------------ |
| Build Time (release)    | ~30 seconds        |
| Startup Time            | <1 second          |
| Scan Rate               | ~1000 files/second |
| Memory Usage (idle)     | ~50MB              |
| Memory Usage (scanning) | ~200MB             |
| Metrics Overhead        | <1% CPU            |

---

## Known Issues

* ARM64 cross-compilation in CI disabled (native builds only)
* Clippy warnings allowed temporarily (non-blocking)
* Metrics server single-threaded

---

## Documentation

* API Documentation: `cargo doc --open`
* User Guide: [docs/USER_GUIDE.md](docs/USER_GUIDE.md)
* Developer Guide: [docs/DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md)
* Metrics Guide: [docs/METRICS.md](docs/METRICS.md)

---

## Acknowledgments

* YARA — pattern matching
* Tokio — async runtime
* Prometheus — metrics
* notify — file watching
* clap — CLI parsing

---

## Support

* Issues: [https://github.com/WinnCore/WinnCoreAV/issues](https://github.com/WinnCore/WinnCoreAV/issues)
* Discussions: [https://github.com/WinnCore/WinnCoreAV/discussions](https://github.com/WinnCore/WinnCoreAV/discussions)
* Security: report via GitHub Security Advisories

---

## Roadmap

### v0.2.0 (Next Release)

* Web dashboard for metrics
* Signature auto-update service
* Scheduled scanning
* Email integration

### v0.3.0 (Future)

* Machine learning heuristics
* Cloud threat intelligence
* Multi-platform support (x86_64)
* Plugin system

````
