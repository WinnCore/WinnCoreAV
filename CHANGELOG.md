# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
