# WinnCoreAV

![CI](https://github.com/WinnCore/WinnCoreAV/workflows/CI%20(ARM64%20Only)/badge.svg)
![Platform](https://img.shields.io/badge/platform-ARM64%20%7C%20aarch64-blue.svg)
![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Open-source antivirus engine built natively for ARM64 architecture.**

Designed specifically for ARM64 devices (Qualcomm Snapdragon X13s, Apple Silicon, Raspberry Pi, etc.) where traditional x86_64 antivirus solutions either don't work or run poorly through emulation.

## 🎉 Latest Features

- ✅ **Real-time File Monitoring** - Watches directories and auto-scans new/modified files
- ✅ **YARA Detection Engine** - Industry-standard malware pattern matching
- ✅ **Proven Malware Detection** - EICAR test validation in CI/CD
- ✅ **ARM64 Native** - Optimized for aarch64 from the ground up


Designed specifically for ARM64 devices (Qualcomm Snapdragon X13s, Apple Silicon, Raspberry Pi, etc.) where traditional x86_64 antivirus solutions either don't work or run poorly through emulation.

## ⚡ Why WinnCoreAV?

- **🎯 ARM64-Native** - Built from the ground up for aarch64, not ported from x86
- **🔒 Privacy-First** - All scanning happens locally, no cloud uploads
- **⚙️ YARA-Powered** - Industry-standard malware detection engine
- **🚀 Efficient** - Optimized for ARM's power efficiency
- **📖 Open Source** - Fully auditable, no proprietary black boxes
- **🔧 Modular** - Use as a library or standalone CLI tool

## 🖥️ Tested Platforms

| Device | Architecture | Status |
|--------|-------------|---------|
| Lenovo ThinkPad X13s (Snapdragon X Elite) | aarch64 | ✅ Tested |
| Apple Silicon (M1/M2/M3) | aarch64 | 🔜 Planned |
| Raspberry Pi 4/5 | aarch64 | 🔜 Planned |
| Generic ARM64 Linux | aarch64 | ✅ Should work |

## 📦 Installation

### Prerequisites (Ubuntu/Debian ARM64)
```bash
sudo apt-get install build-essential pkg-config autoconf automake \
                     libtool bison flex libssl-dev
```

### Build from Source
```bash
git clone https://github.com/WinnCore/WinnCoreAV.git
cd WinnCoreAV

# Set environment for vendored YARA
export YARA_NO_PKG_CONFIG=1

# Build
cargo build --release

# Install
cargo install --path av-cli
```

For detailed ARM64 build instructions, see [docs/ARM64.md](docs/ARM64.md)

## 🚀 Quick Start

### Scan a File
```bash
av-cli scan /path/to/suspicious/file
```

### Scan a Directory
```bash
av-cli scan /home/user/Downloads
```

### Manage Quarantine
```bash
# List quarantined files
av-cli quarantine list

# Restore a file
av-cli quarantine restore <id> /path/to/restore

# Delete quarantined file
av-cli quarantine delete <id>
```

### Run as Daemon (Real-time Protection)
```bash
sudo av-daemon
```

## 🏗️ Architecture
```
WinnCoreAV/
├── av-core/          # Core scanning engine
├── av-signatures/    # Signature management
├── av-daemon/        # Real-time protection daemon
├── av-cli/           # Command-line interface
└── av-quarantine/    # Quarantine management
```

## ⚠️ Current Limitations

**This is alpha software.** Please understand:

- ❌ **Not production-ready** - Use at your own risk
- ❌ **Limited signature database** - Fewer rules than commercial AVs
- ❌ **No GUI yet** - CLI only for now
- ❌ **Linux only** - No Windows/macOS support
- ⚠️ **False positives possible** - YARA rules need tuning
- ⚠️ **Performance not benchmarked** - Speed vs accuracy tradeoffs unknown

**Do NOT rely on this as your only security solution.**

## 🎯 Project Status

### ✅ Working
- File/directory scanning
- YARA rule engine integration
- Quarantine system
- Basic malware detection
- ARM64-native compilation
- CI/CD pipeline

### 🔨 In Progress
- Real-time filesystem monitoring
- Behavioral analysis engine
- Automatic signature updates
- Configuration management

### 🔜 Planned
- GUI application
- Browser integration
- Cloud signature sharing (opt-in)
- macOS support
- Performance benchmarking

## 🤝 Contributing

Contributions welcome! This project needs:

- **ARM64 Testing** - Test on your ARM devices
- **YARA Rules** - Submit effective malware signatures
- **Performance Tuning** - Optimize for ARM efficiency
- **Documentation** - Especially ARM64-specific quirks
- **Bug Reports** - Open issues with device info

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📊 Performance (Preliminary)

*Note: These are informal benchmarks on Snapdragon X13s. YMMV.*

| Operation | Speed | Notes |
|-----------|-------|-------|
| File scan | ~500 MB/s | Single file, SSD |
| Directory scan | ~300 MB/s | Mixed files |
| Memory usage | ~50 MB | Idle daemon |

## 🔒 Security

Found a security vulnerability? **Please DO NOT open a public issue.**

Email: security@winncore.dev (or open a private security advisory)

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- **YARA Project** - Pattern matching engine
- **Rust Community** - ARM64 tooling support
- **Qualcomm** - Snapdragon X Elite platform

## 📚 Documentation

- [ARM64 Build Guide](docs/ARM64.md)
- [Architecture Overview](docs/ARCHITECTURE.md) *(coming soon)*
- [API Documentation](https://docs.rs/winncore-av) *(coming soon)*

## ⭐ Star History

If you find this useful for your ARM64 device, please star the repo!

---

**Built with 💪 on Snapdragon X13s ARM64**
