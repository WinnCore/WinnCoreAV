# Contributing to WinnCoreAV

Thanks for your interest in improving ARM64 antivirus!

## How to Contribute

### 1. Testing on ARM64 Devices
We need testing on various ARM64 platforms:
- Document your device specs
- Run the test suite: `cargo test --all`
- Report any platform-specific issues

### 2. YARA Rules
Submit effective malware signatures:
- Test your rules thoroughly
- Minimize false positives
- Document the malware family targeted

### 3. Code Contributions
- Fork the repo
- Create a feature branch
- Write tests for new features
- Ensure `cargo clippy` passes
- Submit a pull request

### 4. Documentation
ARM64-specific documentation is especially valuable:
- Build issues on specific devices
- Performance characteristics
- Power efficiency tips

## Development Setup

See [docs/ARM64.md](docs/ARM64.md) for build instructions.

## Code Style

- Run `cargo fmt` before committing
- Fix all `cargo clippy` warnings
- Add tests for new features

## Questions?

Open an issue or start a discussion!
