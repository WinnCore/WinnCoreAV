#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

echo "=== WinnCoreAV Full Validation Suite ==="
echo "Root: ${ROOT_DIR}"

echo
echo "=== Step 1: Formatting (cargo fmt) ==="
cargo fmt --all

echo
echo "=== Step 2: Compile Check (cargo check --workspace) ==="
cargo check --workspace

echo
echo "=== Step 3: Clippy (deny warnings) ==="
cargo clippy --workspace -- -D warnings

echo
echo "=== Step 4: Unit/Integration Tests (cargo test --workspace) ==="
cargo test --workspace

echo
echo "=== Step 5: Release Build (cargo build --workspace --release) ==="
cargo build --workspace --release

echo
echo "=== Step 6: Attack Simulation (optional) ==="
if [[ "${RUN_ATTACK_SIM:-1}" == "1" ]]; then
  bash tests/attack_simulations/run_all_simulations.sh
else
  echo "Skipping attack simulation (set RUN_ATTACK_SIM=1 to enable)"
fi

echo
echo "Validation complete."

