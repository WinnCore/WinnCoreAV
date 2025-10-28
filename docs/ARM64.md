# ARM64 Build Guide (Snapdragon X13s)

This guide covers building WinnCoreAV on ARM64 architecture (aarch64), specifically for the Qualcomm Snapdragon X13s running Ubuntu.

## Prerequisites

### System Dependencies
```bash
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  pkg-config \
  autoconf \
  automake \
  libtool \
  bison \
  flex \
  libssl-dev
```

**Important:** Do NOT install `libyara-dev` - we use vendored YARA to avoid ARM64 compatibility issues.

## Building

### Environment Setup
```bash
# Force vendored libyara (no pkg-config detection)
export YARA_NO_PKG_CONFIG=1
export PKG_CONFIG_ALLOW_CROSS=0

# Optional: Enable verbose build output
export CARGO_BUILD_VERBOSE=1
```

### Clean Build
```bash
# Start fresh
cargo clean

# Build with vendored YARA
cargo build --workspace --all-features --verbose

# Run tests with diagnostics
cargo test --workspace --all-features -- --nocapture
```

### Verify Build
```bash
# Check architecture
uname -m  # Should show: aarch64

# Verify YARA version
cargo test print_yara_version_arm64 -- --nocapture --exact

# Expected output:
# ARM64 libyara version: 4.x.y
```

## Troubleshooting

### Error: Missing `_YR_CONFIG_NAME*` symbols

**Symptom:**
```
error: cannot find value `_YR_CONFIG_NAME_YR_CONFIG_STACK_SIZE` in crate `yara_sys`
```

**Solution:**
1. Verify environment variables:
```bash
echo $YARA_NO_PKG_CONFIG  # Should print: 1
```

2. Check no system libyara is installed:
```bash
dpkg -l | grep libyara  # Should return nothing
```

3. Ensure Cargo.toml uses vendored features:
```toml
yara = { version = "0.23.0", default-features = false, features = ["vendored"] }
```

4. If still failing, disable configuration API:
```bash
cargo build --no-default-features --features=""
```

### Error: Build fails with SSL/TLS errors

**Solution:**
```bash
sudo apt-get install -y libssl-dev pkg-config
```

### Error: libtool or autoconf missing

**Solution:**
```bash
sudo apt-get install -y autoconf automake libtool bison flex
```

### Slow Builds

**Solution:** Use parallel compilation:
```bash
export CARGO_BUILD_JOBS=$(nproc)
cargo build --workspace -j $(nproc)
```

## Performance Notes

ARM64 builds are typically:
- **30-40% slower** than x86_64 during initial compilation (vendored libyara)
- **Equivalent performance** at runtime for malware scanning
- **Better power efficiency** on Snapdragon X13s

## Verification Checklist

- [ ] `uname -m` shows `aarch64`
- [ ] `cargo build` completes without errors
- [ ] `cargo test` passes all tests
- [ ] `print_yara_version_arm64` shows version 4.x+
- [ ] No `-lyara` in `ldd target/release/av-cli` output
- [ ] `YARA_NO_PKG_CONFIG=1` is set

## CI/CD

For ARM64 GitHub Actions runners, see `.github/workflows/ci-arm64.yml`.

Note: As of 2025, GitHub doesn't provide hosted ARM64 runners. Use:
- Self-hosted ARM64 runner, OR
- Wait for GitHub to release ARM64 runners, OR  
- Use Cirrus CI, AWS CodeBuild, or Azure Pipelines with ARM64 VMs

## Support

For ARM64-specific issues:
1. Check `docs/ARM64.md` (this file)
2. Verify environment with diagnostic script:
```bash
bash scripts/check-arm64.sh
```
3. Open issue with `[ARM64]` prefix
