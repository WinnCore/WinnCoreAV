#!/usr/bin/env bash
set -euo pipefail

if ! command -v rg >/dev/null 2>&1; then
  echo "ripgrep (rg) is required. Install it with:"
  echo "  sudo apt install ripgrep"
  exit 1
fi

WORKSPACE_ROOT="$(pwd)"

echo "Workspace: $WORKSPACE_ROOT"
echo

# Find all Cargo.toml files (each is a crate)
mapfile -t CRATES < <(find . -maxdepth 3 -type f -name Cargo.toml | sort)

for cargo in "${CRATES[@]}"; do
  CRATE_DIR="$(dirname "$cargo")"
  CRATE_NAME="$(basename "$CRATE_DIR")"

  echo "================================================================"
  echo " Crate: $CRATE_NAME  @  $CRATE_DIR"
  echo "================================================================"

  cd "$CRATE_DIR"

  # 1) Biggest Rust files
  echo
  echo "[1] Top Rust files (excluding target/)"
  echo "--------------------------------------"
  find . \
    -type f -name '*.rs' \
    -not -path '*/target/*' \
    -print0 | xargs -0 wc -l 2>/dev/null | sort -nr | head -n 10

  # 2) Public APIs (if lib)
  if [ -d "src" ]; then
    echo
    echo "[2] Public Rust APIs in src/ (pub fn / struct / enum)"
    echo "-----------------------------------------------------"
    rg --glob '*.rs' '^\s*pub\s+(fn|struct|enum)\s+' -n src 2>/dev/null || echo "No public APIs found."

    echo
    echo "[3] Heavily referenced functions (shared logic signals)"
    echo "------------------------------------------------------"
    FUNCS=$(rg --glob '*.rs' -o 'fn\s+([a-zA-Z0-9_]+)\s*\(' -r '$1' src 2>/dev/null | sort -u || true)
    if [ -n "${FUNCS:-}" ]; then
      echo "$FUNCS" | while read -r fname; do
        count=$(rg --glob '*.rs' -w "$fname" src 2>/dev/null | wc -l || echo 0)
        printf "%5d  %s\n" "$count" "$fname"
      done | sort -nr | head -n 25
    else
      echo "No functions found."
    fi
  else
    echo
    echo "[2] No src/ directory here."
  fi

  echo
  echo "=== End of crate: $CRATE_NAME ==="
  echo

  cd "$WORKSPACE_ROOT"
done
