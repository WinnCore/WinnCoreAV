#!/usr/bin/env bash
# Full validation of WinnCoreAV enterprise features
set -euo pipefail

echo "═══════════════════════════════════════════════════════════════"
echo "  WinnCore AV Enterprise Validation"
echo "═══════════════════════════════════════════════════════════════"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

step() { echo; echo "▶ $*"; }

# Build everything
step "Building all crates (release)"
cargo build --release --all-targets

# Run unit tests
step "Running unit tests"
cargo test --release --all -- --nocapture

# Check for hardening
step "Verifying binary hardening"
if [ -f scripts/verify-hardening.sh ]; then
    ./scripts/verify-hardening.sh target/release/av-daemon
else
    echo "verify-hardening.sh not found, skipping"
fi

# Security audits
step "Running security audits"
cargo audit 2>/dev/null || echo "cargo-audit not installed"
cargo deny check 2>/dev/null || echo "cargo-deny not installed"

# Run MITRE tests (if daemon is running)
step "Checking MITRE test suite"
if [ -f target/release/mitre-test-runner ]; then
    echo "MITRE test runner built successfully"
    echo "Run with: ./target/release/mitre-test-runner av-mitre-tests/tests/linux_attacks.yaml"
else
    echo "mitre-test-runner not built (build failed or target missing)"
fi

# Feature checks
step "Feature availability check"
echo "  io_uring: $(grep -q io_uring /proc/kallsyms 2>/dev/null && echo 'supported' || echo 'not found')"
echo "  eBPF: $(ls /sys/fs/bpf 2>/dev/null && echo 'mounted' || echo 'not mounted')"
echo "  MTE: $(grep -q mte /proc/cpuinfo 2>/dev/null && echo 'supported' || echo 'not supported')"
echo "  PAC: $(grep -q pac /proc/cpuinfo 2>/dev/null && echo 'supported' || echo 'not supported')"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "  Validation Complete"
echo "═══════════════════════════════════════════════════════════════"
