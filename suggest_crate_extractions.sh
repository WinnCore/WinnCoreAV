#!/usr/bin/env bash
set -euo pipefail

THRESHOLD_LINES="${1:-200}"  # default: 200+ LOC

echo "Scanning for Rust files with >= $THRESHOLD_LINES lines..."
echo

find . -type f -name '*.rs' -not -path '*/target/*' \
  -print0 | xargs -0 wc -l 2>/dev/null | sort -nr | while read -r line_count path; do
  # Skip total lines
  if [[ "$path" == "total" ]]; then
    continue
  fi

  if [ "$line_count" -lt "$THRESHOLD_LINES" ]; then
    break
  fi

  # Derive crate dir and module name
  crate_dir="$(echo "$path" | awk -F'/src/' '{print $1}')"
  crate_name="$(basename "$crate_dir")"
  file_name="$(basename "$path" .rs)"

  # Suggested new crate name based on file and crate
  suggested_crate="winncore-${crate_name}-${file_name}"

  echo "--------------------------------------------"
  echo "File:        $path"
  echo "Lines:       $line_count"
  echo "Crate:       $crate_name"
  echo "Suggestion:  Extract into crate: $suggested_crate"
done
