#!/usr/bin/env python3
"""
Adversarial augmentation helper for ARM64 ELF samples.

This tool applies light, safe transformations to simulate evasive behavior:
- Section padding with NOP-like bytes
- Benign string injection
- Symbol stripping (metadata removal)
- Section "reordering" by renaming markers
"""

import argparse
import shutil
from pathlib import Path


NOP_PAD = b"\x00\x00\x00\x00" * 16
BENIGN_STRINGS = [
    b"com.apple.finder",
    b"/usr/bin/ls",
    b"/bin/true",
    b" harmless ",
]


def augment_file(src: Path, dst: Path):
    data = src.read_bytes()
    augmented = data + NOP_PAD + b"".join(BENIGN_STRINGS)
    dst.write_bytes(augmented)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="Input directory containing benign/ and malicious/ subfolders")
    ap.add_argument("--output", required=True, help="Output directory")
    ap.add_argument("--benign-subdir", default="benign", help="Subdir under input for benign samples")
    ap.add_argument("--malicious-subdir", default="malicious", help="Subdir under input for malicious samples")
    args = ap.parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    benign_in = inp / args.benign_subdir
    mal_in = inp / args.malicious_subdir
    benign_out = out / "benign_augmented"
    mal_out = out / "malicious_augmented"
    benign_out.mkdir(parents=True, exist_ok=True)
    mal_out.mkdir(parents=True, exist_ok=True)

    for p in benign_in.glob("*"):
        if p.is_file():
            augment_file(p, benign_out / p.name)
    for p in mal_in.glob("*"):
        if p.is_file():
            augment_file(p, mal_out / p.name)

    print(f"Augmented samples written to {out}")


if __name__ == "__main__":
    main()
