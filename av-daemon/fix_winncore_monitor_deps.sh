#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/zacharywinn/projects/WinnCoreAV"
cd "$ROOT"

MONITOR_DIR="winncore-monitor"
DAEMON_DIR="av-daemon"
MONITOR_TOML="$MONITOR_DIR/Cargo.toml"
DAEMON_TOML="$DAEMON_DIR/Cargo.toml"

if [ ! -f "$MONITOR_TOML" ]; then
  echo "ERROR: $MONITOR_TOML not found" >&2
  exit 1
fi

if [ ! -f "$DAEMON_TOML" ]; then
  echo "ERROR: $DAEMON_TOML not found" >&2
  exit 1
fi

echo "[*] Moving metrics.rs into winncore-monitor (for crate::metrics)..."
if [ -f "$DAEMON_DIR/src/metrics.rs" ] && [ ! -f "$MONITOR_DIR/src/metrics.rs" ]; then
  mv "$DAEMON_DIR/src/metrics.rs" "$MONITOR_DIR/src/metrics.rs"
  echo "    moved $DAEMON_DIR/src/metrics.rs -> $MONITOR_DIR/src/metrics.rs"
else
  echo "    metrics.rs already moved or missing, skipping."
fi

echo "[*] Syncing dependencies from av-daemon into winncore-monitor..."

python3 - << 'PY'
from pathlib import Path

root = Path("/home/zacharywinn/projects/WinnCoreAV")
daemon = root / "av-daemon" / "Cargo.toml"
monitor = root / "winncore-monitor" / "Cargo.toml"

daemon_lines = daemon.read_text().splitlines()
monitor_text = monitor.read_text()
monitor_lines = monitor_text.splitlines()

# crates that lib.rs is complaining about
needed_crates = [
    "anyhow",
    "av_core",
    "crossbeam_channel",
    "filetime",
    "glob",
    "lru_time_cache",
    "notify",
    "notify_rust",
    "tokio",
    "sha2",
    "tracing",
    "serde_json",
    "chrono",
    "libc",
    "num_cpus",
    "dirs",
    "ctrlc",
    "hex",
]

# ensure [dependencies] section exists in monitor toml
if not any(line.strip().startswith("[dependencies]") for line in monitor_lines):
    monitor_lines.append("")
    monitor_lines.append("[dependencies]")

# current keys in monitor dependencies
present_keys = set()
for line in monitor_lines:
    s = line.strip()
    if not s or s.startswith("#") or s.startswith("["):
        continue
    if "=" in s:
        key = s.split("=", 1)[0].strip()
        present_keys.add(key)

def find_dep_line(crate_name: str):
    """Try to find the dependency line for this crate in av-daemon/Cargo.toml."""
    # 1) Exact key match
    for line in daemon_lines:
        s = line.strip()
        if s.startswith(crate_name) and "=" in s:
            return line
    # 2) Dash/underscore variants
    alt1 = crate_name.replace("_", "-")
    alt2 = crate_name.replace("-", "_")
    for line in daemon_lines:
        s = line.strip()
        if s.startswith(alt1) and "=" in s:
            return line
        if s.startswith(alt2) and "=" in s:
            return line
    # 3) Try to locate via package = "name"
    for idx, line in enumerate(daemon_lines):
        if f'package = "{crate_name}"' in line:
            # walk backwards to find the key
            for j in range(idx - 1, -1, -1):
                prev = daemon_lines[j].strip()
                if prev and not prev.startswith("[") and "=" in prev:
                    return daemon_lines[j]
    return None

to_append = []
for crate in needed_crates:
    dep_line = find_dep_line(crate)
    if dep_line is None:
        # leave a commented TODO so you can see if something was missed
        to_append.append(f"# TODO: add dependency for {crate}")
        continue

    key = dep_line.split("=", 1)[0].strip()
    if key in present_keys:
        continue  # already there

    to_append.append(dep_line)

if to_append:
    monitor_lines.append("")
    monitor_lines.extend(to_append)

monitor.write_text("\n".join(monitor_lines) + "\n")
PY

echo "[*] Building workspace..."
cargo build
