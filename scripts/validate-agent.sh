#!/usr/bin/env bash
# Comprehensive validation for the WinnCore AV agent
# Build + tests + hardening verification + audits where available.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "══ WinnCore AV Validation ══"

step() { echo; echo "▶ $*"; }

step "Release build (all targets)"
cargo build --release --all-targets

step "Unit/integration tests"
cargo test --release --all -- --nocapture

step "Binary hardening check"
if [ -x scripts/verify-hardening.sh ]; then
  ./scripts/verify-hardening.sh target/release/av-daemon
else
  echo "verify-hardening.sh not found or not executable"
fi

step "Security audits (best effort)"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit || true
else
  echo "cargo-audit not installed; skipping"
fi

if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check || true
else
  echo "cargo-deny not installed; skipping"
fi

echo
echo "✅ Validation complete"
