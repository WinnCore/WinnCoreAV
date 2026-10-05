# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Enterprise SIEM integration in `av-daemon` (unified alert schema, CEF/LEEF/JSON formatters, syslog/webhook/file outputs, routing, management API).
- MITRE ATT&CK-aligned detection framework in `av-behavioral` (fileless, persistence, and C2 detectors with comprehensive unit/integration tests).
- Wired technique-level detectors into `av-daemon` behavioral pipeline (reverse shell/C2 connections, memfd/LD_PRELOAD, ptrace injection, kernel module loads).
- Automated detection validation via `scripts/validate_detections.sh` (runs attack simulations and enforces a detection-rate threshold).

### Changed
- Hardening rustflags (overflow checks, PIC, relro/now/noexecstack) now apply on aarch64 too. ARM64 release builds abort on integer overflow instead of wrapping.
- Dropped link args that never affected Rust code (`-fstack-clash-protection`, `-D_FORTIFY_SOURCE=2`, `-mbranch-protection`). See the comment in `.cargo/config.toml`.
- Self-Healing CI is manual-only until autofix.ci is set up.
- Minimum Rust version is 1.89.

### Removed
- Unused dependencies: `daemonize` (av-daemon) and the `libbpf-cargo` build-dependency (av-ebpf-loader).

### Fixed
- Updated Prometheus metrics dependencies to eliminate `protobuf` recursion crash advisory (RUSTSEC-2024-0437).
- `cargo build --workspace` failed: librocksdb-sys build script panic (bindgen/libclang) and E0277 in `av-daemon` (`IocDatabase` had no `Debug`).
- `av-core` didn't build on its own (missing `url` serde feature).
- CI never ran from Dec 17, 2025: the workflows used `ubuntu-24.04-arm64`, which isn't a GitHub runner label. Now `ubuntu-24.04-arm`.
- `cargo fmt` and clippy (`-D warnings`) are clean again.
- COMPLIANCE.md, CONTRIBUTING.md and the PR template said MIT; the project is Apache-2.0.

### Security
- Dependency updates clear 19 RUSTSEC vulnerabilities (bytes, crossbeam-epoch, h2, quinn-proto, rustls, rustls-webpki, tar, time). `cargo audit` reports 0 vulnerabilities.

### Planned
- Comprehensive integration tests for all components
- Performance benchmarks and optimization
- Automated signature update mechanism
- GUI interface
- Windows and macOS support
- Enhanced documentation with architecture diagrams

## [0.1.0] - 2025-10-26

### Added
- Initial alpha release of WinnCore AV Suite
- Core scanning engine (av-core) with multi-language detection framework
- Command-line interface (av-cli) for file scanning operations
- Background daemon (av-daemon) for real-time file monitoring
- Encrypted quarantine system (av-quarantine) using AES-256-GCM
- Signature management system (av-signatures) with YARA integration
- Test samples for JavaScript, Python, and PowerShell pattern validation
- AppArmor and seccomp security profiles for daemon hardening
- Systemd service unit for daemon deployment
- Basic test infrastructure and EICAR test file support
- GitHub Actions CI pipeline with matrix testing (ubuntu-latest, ubuntu-22.04)
- Automated security auditing with cargo-audit
- SBOM generation for supply chain transparency
- Automated GitHub releases with checksums

### Known Limitations
- **Alpha quality** - not recommended for production use
- Limited test coverage on core detection algorithms (~30%)
- Signature database requires manual updates
- No automated threat intelligence feeds
- Performance not yet optimized for large-scale deployments
- No GUI interface
- Linux-only support (tested on Ubuntu 22.04 and Debian 12)

### Security Notes
- User-space operation without kernel module requirements
- Quarantine encryption keys stored on local filesystem
- No network communication from daemon (air-gapped by design)
- AppArmor and seccomp profiles restrict daemon capabilities
- Supply chain security via SBOM and dependency auditing
