#!/usr/bin/env bash
set -euo pipefail

ROOT="/home/zacharywinn/projects/WinnCoreAV"
cd "$ROOT"

echo "[*] Verifying winncore-monitor crate exists..."
if [ ! -d "winncore-monitor" ]; then
  echo "ERROR: winncore-monitor crate not found in $ROOT" >&2
  exit 1
fi

if [ ! -f "av-daemon/Cargo.toml" ]; then
  echo "ERROR: av-daemon/Cargo.toml not found" >&2
  exit 1
fi

if [ ! -f "av-daemon/src/main.rs" ]; then
  echo "ERROR: av-daemon/src/main.rs not found" >&2
  exit 1
fi

echo "[*] Patching av-daemon/Cargo.toml to depend on winncore-monitor..."

# Insert dependency under [dependencies], or create the section if missing.
awk '
  BEGIN { done_dep = 0; injected = 0 }
  /^winncore-monitor\s*=/ { done_dep = 1 }   # already present
  {
    if ($0 ~ /^\[dependencies\]/ && !done_dep && !injected) {
      print $0
      print "winncore-monitor = { path = \"../winncore-monitor\" }"
      injected = 1
      next
    }
    print $0
  }
  END {
    if (!done_dep && !injected) {
      print ""
      print "[dependencies]"
      print "winncore-monitor = { path = \"../winncore-monitor\" }"
    }
  }
' av-daemon/Cargo.toml > av-daemon/Cargo.toml.tmp

mv av-daemon/Cargo.toml.tmp av-daemon/Cargo.toml

echo "[*] Rewriting av-daemon/src/main.rs to use winncore_monitor crate..."

python3 - << 'PY'
from pathlib import Path

p = Path("av-daemon/src/main.rs")
text = p.read_text()

lines = text.splitlines()
new_lines = []
for line in lines:
    # drop any mod monitor; line
    stripped = line.strip()
    if stripped.startswith("mod monitor") or stripped.startswith("pub mod monitor"):
        continue
    new_lines.append(line)

text = "\n".join(new_lines)

# Rewrite use paths and direct calls
replacements = {
    "crate::monitor::": "winncore_monitor::",
    "self::monitor::": "winncore_monitor::",
    "monitor::": "winncore_monitor::",
}

for old, new in replacements.items():
    text = text.replace(old, new)

p.write_text(text)
PY

echo "[*] Running cargo build for the workspace..."
cargo build

echo "[*] Done. Check any compiler errors to see which functions/types need to be marked pub in winncore-monitor/src/lib.rs or have their paths adjusted."
