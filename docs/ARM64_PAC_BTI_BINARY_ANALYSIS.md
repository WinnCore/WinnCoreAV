# ARM64 PAC/BTI Binary Analysis

Status: **Implemented**  
Owner: Core Engine  
Scope: `av-core/src/arm64_security.rs`, `av-core/src/engine.rs`

## What This Does
- Parses AArch64 ELF GNU property notes to determine whether binaries are built with Pointer Authentication (PAC) and Branch Target Identification (BTI).
- Flags unprotected ARM64 binaries at scan time and tags them with MITRE `T1562` (Defense Evasion) for downstream analytics.
- Keeps runtime-safe: parsing failures degrade gracefully and never panic or block scanning.

## Architecture
- `arm64_security::analyze_elf_protections(bytes)`:
  - Uses `goblin` to parse ELF headers.
  - Scans `PT_NOTE` / `PT_GNU_PROPERTY` segments for `NT_GNU_PROPERTY_TYPE_0`.
  - Looks for `GNU_PROPERTY_AARCH64_FEATURE_1_AND` bitmask: `BTI` (bit0) and `PAC` (bit1).
  - Returns `BinaryProtectionStatus` with booleans and parsing notes.
- Engine integration:
  - Runs analysis on the file head buffer during scan.
  - If AArch64 ELF lacks PAC or BTI marks, adds note `arm64_binary_missing_pac_or_bti`, MITRE tag `T1562`, and escalates action to `Monitor` if previously `Allow`.

## Performance Notes
- Reuses the already-read 256KB file head; no extra I/O.
- Goblin parse happens once per scan and short-circuits on non-ELF or non-AArch64 files.

## Safety and Compatibility
- Zero unwraps on parsing; all errors become notes.
- JSON log schema unchanged; only an additional note and MITRE tag when unprotected binaries are found.
- ScannerConfig untouched, maintaining backward compatibility.

## Usage
```rust
let protections = av_core::arm64_security::analyze_elf_protections(&bytes);
if protections.is_aarch64_elf && (!protections.pac_marked || !protections.bti_marked) {
    // handle as unprotected binary
}
```

JSON logs now include an optional `arm64_protection` block when the scanned file
is an AArch64 ELF:
```json
{
  "arm64_protection": {
    "is_aarch64_elf": true,
    "pac_marked": false,
    "bti_marked": true,
    "has_gnu_property_note": true,
    "parsing_notes": ["..."]
  }
}
```

## Validation
- Unit test `parses_gnu_property_feature_bits` synthesizes an AArch64 ELF note with BTI+PAC bits and asserts detection.
- Run module tests:
  ```bash
  cargo test -p av-core arm64_security -- --nocapture
  ```

## Next Steps
- Surface protection status in JSON output for analyst visibility.
- Use capability detection to skip BTI checks on platforms without BTI support.
- Emit telemetry histogram on protected vs unprotected binaries seen in the field.
