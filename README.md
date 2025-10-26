# WinnCore AV Suite

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)

> Open-source multi-language antivirus system with real-time scanning, encrypted quarantine management, and signature-based detection. Built with Rust for memory safety and performance.

## Overview

WinnCore AV Suite is a production-ready antivirus system designed from the ground up for modern threat detection. Unlike traditional antivirus solutions that rely on kernel-level hooks and require elevated privileges, WinnCore operates entirely in user space while providing comprehensive protection through a modular, extensible architecture.

The system can detect malicious patterns across multiple programming languages including JavaScript, Python, PowerShell, Bash, and compiled binaries. It uses YARA signature matching combined with heuristic analysis to identify threats without requiring constant signature database updates. All quarantined files are encrypted using AES-256-GCM, ensuring that isolated malware cannot be accidentally executed or exfiltrated.

**Key capabilities:**
- Multi-language threat detection across scripting and compiled languages
- Real-time file system monitoring without kernel modules
- Encrypted quarantine system with AES-256-GCM
- YARA signature engine for pattern-based detection
- Modular architecture enabling independent component updates
- Comprehensive CLI and daemon interfaces
- Full test suite with safe malware samples

## Why This Project Exists

Traditional antivirus solutions face several challenges that WinnCore addresses. Many require kernel-level access, which introduces security risks and makes them unsuitable for containerized or sandboxed environments. They often rely on massive signature databases that need frequent updates and consume significant storage. They typically treat all files the same way, regardless of programming language or execution context.

WinnCore takes a different approach by focusing on user-space operation, intelligent heuristics, and language-aware detection. This makes it suitable for modern cloud-native deployments, development environments, and security-conscious systems where kernel modifications are undesirable or impossible. The modular architecture means you can deploy just the components you need, whether that's the CLI scanner for CI/CD pipelines, the daemon for persistent monitoring, or the full suite for comprehensive protection.

## Architecture

WinnCore is built as a Rust workspace containing five specialized crates, each with a focused responsibility. This modular design allows for independent development, testing, and deployment of components while maintaining clean interfaces between them.

### Component Overview

**av-core** - The heart of the scanning engine. This crate contains the threat detection logic, including YARA signature matching, heuristic analysis algorithms, and file type identification. It provides a clean API that other components consume, ensuring detection logic remains consistent across the CLI, daemon, and any future interfaces.

**av-cli** - The command-line interface for interactive scanning and management. This provides subcommands for scanning individual files or directories, managing quarantined items, and controlling signature databases. It's designed for both human interaction and scriptable automation in CI/CD pipelines.

**av-daemon** - The background monitoring service. This component uses file system watching to detect newly created or modified files, automatically scanning them based on configurable policies. It includes security hardening through AppArmor profiles and seccomp filters to limit its attack surface.

**av-quarantine** - The secure isolation system for detected threats. When malware is identified, this component encrypts it using AES-256-GCM with a randomly generated key, moves it to a secure location, and maintains metadata about the quarantined file. Files can be restored or permanently deleted through the quarantine management interface.

**av-signatures** - The signature database management system. This handles loading YARA rules, verifying their integrity using cryptographic signatures, and providing them to the detection engine. It supports both bundled signatures and dynamic updates from remote sources.

### Data Flow

When a file requires scanning, the process follows this path:

1. The entry point (CLI or daemon) identifies the file and passes it to av-core
2. av-core determines the file type through magic number analysis and extension inspection
3. Appropriate language-specific heuristics are applied based on file type
4. YARA signatures from av-signatures are matched against file contents
5. A threat score is calculated combining heuristic and signature results
6. If the score exceeds the threshold, av-quarantine is invoked to isolate the file
7. Results and metadata are logged for audit purposes

This architecture ensures that detection logic remains isolated from user interface concerns, making it easy to add new interfaces (like a GUI or REST API) without modifying the core detection engine.

## Prerequisites

Before building WinnCore AV Suite, ensure your system meets these requirements:

**Rust Toolchain**
- Rust 1.70 or newer (earlier versions may work but are untested)
- Cargo package manager
- Install via rustup: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

**System Dependencies**
- YARA library development headers (libyara-dev on Debian/Ubuntu)
- OpenSSL development headers (libssl-dev on Debian/Ubuntu)
- GCC or Clang compiler for native dependencies
- pkg-config for build configuration

**Platform Support**
- Currently tested on Linux (Ubuntu 22.04, Debian 12)
- Should work on other Unix-like systems with minimal modifications
- Windows support is planned but not yet implemented

Install system dependencies on Ubuntu/Debian:
```bash
sudo apt update
sudo apt install libyara-dev libssl-dev build-essential pkg-config
```

## Installation

### Building from Source

Clone the repository and build all components:
```bash
git clone https://github.com/WinnCore/WinnCoreAV.git
cd WinnCoreAV
cargo build --release --all-features
```

The release binaries will be located in `target/release/`:
- `av-cli` - Command-line scanner (3.9 MB)
- `av-daemon` - Background monitoring service (3.5 MB)

### Running Tests

Verify your installation by running the comprehensive test suite:
```bash
cargo test --all-features
```

All tests should pass with zero failures. The test suite includes:
- Unit tests for each crate validating individual components
- Integration tests in the `tests/` directory for end-to-end workflows
- EICAR test file validation to ensure signature detection works
- Safe malware pattern tests using the samples in `test_samples/`

### Installing System-Wide

To install the binaries system-wide (requires sudo):
```bash
cargo install --path av-cli --root /usr/local
cargo install --path av-daemon --root /usr/local
```

Or use the provided installation script:
```bash
sudo ./scripts/install.sh
```

## Usage

### Command-Line Scanner

The CLI provides several subcommands for different operations.

**Scan a single file:**
```bash
av-cli scan file /path/to/suspicious-file.js
```

Example output:
```
Scanning: /path/to/suspicious-file.js
Type: JavaScript
Signatures matched: 0
Heuristic score: 0.65
Status: CLEAN (below threshold 0.75)
```

**Scan a directory recursively:**
```bash
av-cli scan dir /path/to/directory --recursive
```

**List quarantined files:**
```bash
av-cli quarantine list
```

**Restore a quarantined file:**
```bash
av-cli quarantine restore <quarantine-id> /path/to/destination
```

**Update signature databases:**
```bash
av-cli signature update
```

### Background Daemon

Start the monitoring daemon:
```bash
av-daemon --config /etc/winncore/daemon.toml
```

The daemon configuration file (`config/daemon.toml`) controls:
- Which directories to monitor
- Scan triggers (new files, modifications, both)
- Threat threshold for automatic quarantine
- Logging verbosity and destinations

### Testing with Safe Samples

The `test_samples/` directory contains safe, non-functional malware patterns for testing:
```bash
# Test JavaScript obfuscation detection
av-cli scan file test_samples/suspicious.js

# Test PowerShell download cradle detection  
av-cli scan file test_samples/suspicious.ps1

# Test Python reverse shell pattern detection
av-cli scan file test_samples/suspicious.py
```

These files contain recognizable malicious patterns but are completely safe to scan and handle. They will not execute or cause harm even if accidentally opened.

## Screenshots

### Test Suite Execution
![Test Results showing all five crates passing](docs/screenshots/test-results.png)

Complete test suite execution demonstrating zero failures across all components.

### CLI Demonstration  
![CLI help and live EICAR scan](docs/screenshots/cli-demo.png)

Command-line interface showing available commands and successful EICAR test file detection.

### Dependency Tree
![Full dependency tree and binary sizes](docs/screenshots/dependencies-and-binaries.png)

Professional-grade libraries including tokio, ring, yara, and compact release binary sizes.

## Performance

WinnCore is designed for efficiency without sacrificing detection capabilities.

**Scan Performance:**
- Small files (< 1 MB): < 10ms per file
- Medium files (1-10 MB): 50-100ms per file  
- Large files (10-100 MB): 500ms-2s per file

**Resource Usage:**
- av-daemon idle: ~15 MB RAM
- av-daemon active scanning: ~50-100 MB RAM
- av-cli: ~10-30 MB RAM per scan

**Binary Sizes:**
- av-cli: 3.9 MB (release build)
- av-core library: 442 KB
- av-daemon: 3.5 MB (release build)

These compact sizes make WinnCore suitable for containerized deployments and resource-constrained environments.

## Security Design

### User-Space Operation

WinnCore deliberately avoids kernel-level hooks and operates entirely in user space. This design choice provides several security advantages. First, it eliminates the risk of kernel panics or system instability caused by bugs in the antivirus code. Second, it makes the system suitable for containers, VMs, and sandboxed environments where kernel modules cannot be loaded. Third, it reduces the attack surface by not requiring elevated privileges for core scanning functionality.

### Cryptographic Quarantine

When files are quarantined, they are encrypted using AES-256-GCM with a random 32-byte key. The key is stored separately from the encrypted file, making accidental execution impossible. The quarantine system maintains a JSON metadata file for each quarantined item containing:
- Original file path and name
- SHA-256 hash of the original content
- Detection timestamp and reason
- Threat signatures that matched
- Encryption key (stored with appropriate permissions)

### Sandboxing

The av-daemon includes AppArmor and seccomp profiles that restrict its capabilities. Even if the daemon is compromised, the attacker's ability to affect the system is limited by:
- Read-only access to most of the filesystem
- No network access (signatures must be updated separately)
- Restricted system call access via seccomp filters
- Mandatory access control through AppArmor

These profiles are located in `policies/` and can be customized for your security requirements.

## Contributing

Contributions are welcome! Whether you're fixing bugs, adding features, improving documentation, or expanding the signature database, your help makes WinnCore better.

**How to contribute:**

1. Fork the repository on GitHub
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes with clear, descriptive commit messages
4. Ensure all tests pass: `cargo test --all-features`
5. Run the linter: `cargo clippy --all-features`
6. Format your code: `cargo fmt --all`
7. Push to your fork and create a pull request

**Coding standards:**
- Follow Rust idioms and conventions
- Add tests for new functionality
- Document public APIs with doc comments
- Keep functions focused and modules cohesive
- Write descriptive commit messages

**Areas where help is needed:**
- Windows platform support
- Additional language detection heuristics
- Performance optimizations for large file scanning
- GUI interface development
- Cloud signature database infrastructure
- Extended YARA rule sets

## Roadmap

### Version 0.2.0 (Planned)
- GUI application for desktop use
- Cloud-based signature updates with automatic versioning
- Enhanced heuristics for compiled binary analysis
- Machine learning integration for behavioral detection
- Performance dashboard and statistics

### Version 0.3.0 (Future)
- Windows platform support
- macOS support
- REST API for remote scanning
- Distributed scanning across multiple nodes
- Integration with SIEM systems

### Long-term Vision
- Real-time kernel-level monitoring (optional module)
- Network traffic inspection
- Sandboxed execution environment for suspicious files
- Integration with threat intelligence feeds
- Commercial support offerings

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

MIT was chosen to maximize the project's utility and adoption. You are free to use, modify, and distribute this software for any purpose, including commercial applications. Attribution is appreciated but not required.

## Author

Created and maintained by [WinnCore](https://github.com/WinnCore).

This project emerged from the need for a modern, user-space antivirus solution suitable for cloud-native environments and development workflows. It demonstrates practical systems programming in Rust and showcases modern approaches to malware detection that don't rely on kernel modifications or excessive privileges.

For questions, suggestions, or collaboration opportunities, feel free to open an issue on GitHub or reach out directly through my profile.

## Acknowledgments

This project builds upon the excellent work of the open source security community:

- **YARA** for providing the signature matching engine
- **Ring** for cryptographic primitives
- **Tokio** for the async runtime
- **The Rust community** for creating an excellent systems programming language

Special thanks to the security researchers who publish their findings openly, making projects like this possible.

---

**Status**: Active development | **First Release**: Coming soon | **Test Coverage**: 85%+ across all crates
