#!/usr/bin/env python3
"""Compare Criterion benchmark baselines to detect regressions."""

import argparse
import json
import sys
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Check performance regressions")
    parser.add_argument(
        "--criterion-dir",
        default="target/criterion",
        help="Criterion output directory",
    )
    parser.add_argument(
        "--max-regression",
        type=float,
        default=5.0,
        help="Max regression percent allowed (default: 5.0)",
    )
    parser.add_argument(
        "--cpu-threshold",
        type=float,
        help="Alias for --max-regression (percent)",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Allow missing baselines/results",
    )
    return parser.parse_args()


def find_estimates(base: Path):
    baseline = list(base.glob("**/baseline/estimates.json"))
    current = list(base.glob("**/new/estimates.json"))
    return baseline, current


def load_estimate(path: Path):
    data = json.loads(path.read_text())
    mean = data.get("mean", {}).get("point_estimate")
    return mean


def main():
    args = parse_args()
    base = Path(args.criterion_dir)

    if not base.exists():
        msg = f"Criterion dir not found: {base}"
        if args.allow_missing:
            print(f"WARNING: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    if args.cpu_threshold is not None:
        args.max_regression = args.cpu_threshold

    baseline, current = find_estimates(base)
    if not baseline or not current:
        msg = "Missing baseline/current benchmark results"
        if args.allow_missing:
            print(f"WARNING: {msg}")
            return 0
        print(f"ERROR: {msg}", file=sys.stderr)
        return 1

    baseline_map = {p.parent.parent: p for p in baseline}
    current_map = {p.parent.parent: p for p in current}

    regressions = []
    for bench, base_path in baseline_map.items():
        curr_path = current_map.get(bench)
        if curr_path is None:
            continue
        base_val = load_estimate(base_path)
        curr_val = load_estimate(curr_path)
        if base_val is None or curr_val is None or base_val == 0:
            continue
        delta = (curr_val - base_val) / base_val * 100.0
        if delta > args.max_regression:
            regressions.append((bench, delta))

    if regressions:
        print("ERROR: Performance regressions detected:", file=sys.stderr)
        for bench, delta in regressions:
            print(f"  {bench}: +{delta:.2f}%", file=sys.stderr)
        return 1

    print("OK: No performance regressions detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
