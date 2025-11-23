# ARM64 Capability Detection

Status: **Implemented**  
Owner: Core Engine  
Scope: `av-core/src/arm64_security.rs`

## What This Does
- Detects hardware control-flow protections unique to ARM64: Pointer Authentication (PAC), Branch Target Identification (BTI), and Memory Tagging Extension (MTE).
- Uses inline assembly to read `ID_AA64ISAR1_EL1` and `ID_AA64PFR1_EL1` when running on AArch64.
- Falls back to `/proc/cpuinfo` feature flags when system registers are masked (virtualized/containers).
- Caches results so detection is effectively free on hot paths.

## Architecture
- `capabilities()` returns a cached `Arm64SecurityCapabilities` struct with booleans, detection method, and diagnostic notes.
- Primary path: `mrs` instructions read the two ID registers, bitfields are decoded:
  - PAC: APA/API/GPA/GPI fields in `ID_AA64ISAR1_EL1`.
  - BTI: BT field in `ID_AA64PFR1_EL1`.
  - MTE: MTE field in `ID_AA64PFR1_EL1`.
- Secondary path: parse the CPU feature line for `paca`, `pacg`, `bti`, `mte`.
- Results are merged when both sources are available (`DetectionMethod::Mixed`).

## Performance Notes
- Single register read + one file read on first invocation; subsequent calls are zero allocation.
- No background threads or long-running probes; safe to call during startup validation.

## Safety and Compatibility
- Inline assembly is wrapped in `target_arch = "aarch64"` guards; non-ARM64 builds skip directly to the CPU-info parser.
- All failures degrade to `DetectionMethod::Unknown` with explanatory notes; no panics or unwraps.
- No backward-incompatible changes to existing public structs or JSON schemas.

## Usage
```rust
use av_core::arm64_security;

let caps = arm64_security::capabilities();
println!("PAC: {}, BTI: {}, MTE: {}", caps.has_pac, caps.has_bti, caps.has_mte);
println!("Detected via {:?}: {:?}", caps.detection_method, caps.notes);
```

## Validation
- Unit tests cover register bitfield parsing, CPU feature parsing, and graceful degradation on non-ARM64 targets.
- To run just this module's tests:
  ```bash
  cargo test -p av-core arm64_security -- --nocapture
  ```

## Next Steps
- Wire capability results into binary analysis to flag unprotected binaries.
- Gate PAC/BTI eBPF probes on runtime capability presence.
- Add telemetry emission so daemon startup logs include hardware protection posture.
