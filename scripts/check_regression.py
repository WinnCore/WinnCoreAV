#!/usr/bin/env python3
"""Compute Negative Flip Rate (NFR) between baseline and current detection results."""

import argparse
import json
import sys
from pathlib import Path


def load_results(path: Path):
    data = json.loads(path.read_text())
    if "attack_sim" in data:
        attack = data.get("attack_sim", {})
        return attack.get("results", [])
    return data.get("results", [])


def parse_args():
    parser = argparse.ArgumentParser(description="Check detection regression (NFR)")
    parser.add_argument("--current", required=True, help="Current results JSON")
    parser.add_argument("--baseline", required=True, help="Baseline results JSON")
    parser.add_argument("--max-nfr", type=float, default=0.01, help="Max NFR (0-1)")
    parser.add_argument(
        "--allow-missing-baseline",
        action="store_true",
        help="Allow missing/empty baseline without failing",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    current_path = Path(args.current)
    baseline_path = Path(args.baseline)

    if not baseline_path.exists():
        msg = f"Baseline not found: {baseline_path}"
        if args.allow_missing_baseline:
            print(f"WARNING: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    if not current_path.exists():
        print(f"ERROR: Current results not found: {current_path}", file=sys.stderr)
        return 1

    baseline_results = load_results(baseline_path)
    current_results = load_results(current_path)

    if not baseline_results:
        msg = "Baseline contains no results; NFR check skipped"
        if args.allow_missing_baseline:
            print(f"WARNING: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    baseline_map = {
        r.get("id"): r
        for r in baseline_results
        if r.get("id") is not None
    }
    current_map = {
        r.get("id"): r
        for r in current_results
        if r.get("id") is not None
    }

    positives = []
    for key, result in baseline_map.items():
        if result.get("skipped"):
            continue
        if not result.get("executed", True):
            continue
        if result.get("detected"):
            positives.append(key)

    if not positives:
        msg = "Baseline has zero detected cases; NFR is 0 by definition"
        if args.allow_missing_baseline:
            print(f"WARNING: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    flips = []
    for key in positives:
        current = current_map.get(key)
        if current is None:
            flips.append(key)
            continue
        if current.get("skipped"):
            flips.append(key)
            continue
        if not current.get("detected", False):
            flips.append(key)

    nfr = len(flips) / len(positives)

    print(f"Baseline positives: {len(positives)}")
    print(f"Negative flips: {len(flips)}")
    print(f"NFR: {nfr:.4f} (threshold {args.max_nfr:.4f})")

    if nfr > args.max_nfr:
        print("ERROR: NFR threshold exceeded", file=sys.stderr)
        if flips:
            print("Flipped IDs:", ", ".join(flips), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
