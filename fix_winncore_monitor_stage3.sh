#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/zacharywinn/projects/WinnCoreAV"
cd "$ROOT"

MON_DIR="winncore-monitor"
DAEMON_DIR="av-daemon"
LIB="$MON_DIR/src/lib.rs"
MON_TOML="$MON_DIR/Cargo.toml"

if [ ! -f "$LIB" ]; then
  echo "ERROR: $LIB not found" >&2
  exit 1
fi

if [ ! -f "$MON_TOML" ]; then
  echo "ERROR: $MON_TOML not found" >&2
  exit 1
fi

echo "[*] Ensuring metrics.rs is in winncore-monitor and wired as a module..."

# 1) Move metrics.rs if still in av-daemon
if [ -f "$DAEMON_DIR/src/metrics.rs" ]; then
  echo "    Moving $DAEMON_DIR/src/metrics.rs -> $MON_DIR/src/metrics.rs"
  mv "$DAEMON_DIR/src/metrics.rs" "$MON_DIR/src/metrics.rs"
fi

# 2) Ensure lib.rs declares the module
if [ -f "$MON_DIR/src/metrics.rs" ]; then
  if ! grep -q '^pub mod metrics;' "$LIB"; then
    echo "    Prepending pub mod metrics; to lib.rs"
    tmp="$LIB.tmp"
    {
      echo "pub mod metrics;"
      cat "$LIB"
    } > "$tmp"
    mv "$tmp" "$LIB"
  else
    echo "    lib.rs already declares pub mod metrics;"
  fi
else
  echo "    WARNING: $MON_DIR/src/metrics.rs is missing; crate::metrics will still fail"
fi

echo "[*] Patching winncore-monitor/Cargo.toml with required dependencies..."

python3 - << 'PY'
from pathlib import Path

toml_path = Path("winncore-monitor/Cargo.toml")
lines = toml_path.read_text().splitlines()

# Make sure [dependencies] exists
has_deps = any(l.strip().startswith("[dependencies]") for l in lines)
if not has_deps:
    lines.append("")
    lines.append("[dependencies]")

# Map of TOML key -> full dependency line
deps = {
    "crossbeam-channel": 'crossbeam-channel = "0.5"',
    "filetime":          'filetime = "0.2"',
    "glob":              'glob = "0.3"',
    "lru_time_cache":    'lru_time_cache = "0.11"',
    "notify-rust":       'notify-rust = "4"',
    "sha2":              'sha2 = "0.10"',
    "chrono":            'chrono = "0.4"',
    "libc":              'libc = "0.2"',
    "num_cpus":          'num_cpus = "1.16"',
    "dirs":              'dirs = "5"',
    "ctrlc":             'ctrlc = "3"',
    "hex":               'hex = "0.4"',
}

existing_keys = set()
for l in lines:
    s = l.strip()
    if not s or s.startswith("[") or s.startswith("#"):
        continue
    if "=" in s:
        key = s.split("=", 1)[0].strip()
        existing_keys.add(key)

# Append missing deps at the end
for key, dep_line in deps.items():
    if key not in existing_keys:
        lines.append(dep_line)

toml_path.write_text("\n".join(lines) + "\n")
PY

echo "[*] Building workspace..."
cargo build
