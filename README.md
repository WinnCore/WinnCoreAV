# WinnCore ARM64 Antivirus (Scaffold)

This repository bootstraps a user-space antivirus tailored for the Lenovo ThinkPad X13s running Ubuntu 25.10 “Questing Quokka”. The implementation respects stringent safety constraints: unprivileged daemon, opt-in quarantine, layered sandboxing (AppArmor + seccomp, optional Landlock), and graceful degradation across kernel feature sets.

## Workspace Layout

- `av-core`: Shared scanning library with YARA-compatible engine stubs, heuristic fusion, entropy analysis, and telemetry primitives.
- `av-daemon`: Real-time monitoring daemon (fanotify/inotify/eBPF placeholders) that runs unprivileged and installs sandbox policies after startup.
- `av-quarantine`: Copy-on-write, integrity-verified quarantine manager with AES-256-GCM encryption and SHA-256 tagging.
- `av-signatures`: Signed update subsystem with Ed25519 verification, TLS pinning hooks, and bundle validation.
- `av-cli`: JSON-first command-line interface for scanning, toggle realtime mode, managing quarantine, and updating signatures.
- `policies/`: AppArmor profile and seccomp-bpf manifest implementing default-deny strategy.
- `systemd/`: Hardened service unit starting the daemon in audit-only mode by default.
- `config/`: Default daemon configuration (audit-only, fanotify fallback logic, adaptive battery guard).
- `rules/`: Example YARA rule demonstrating metadata/provenance fields.
- `scripts/`: Build/package utilities for aarch64 `.deb` artifacts and safe uninstall helper.

## Safety Model

- **Unprivileged by default**: The daemon is designed to run as the `avdaemon` user. Capability elevation is optional and documented per feature.
- **Read-only scanning**: `av-core::Scanner` reads binaries/scripts without mutating them. Quarantine workflows require explicit CLI/API consent.
- **Quarantine integrity**: Files are copied, double-written, hashed (SHA-256), encrypted per-host, and logged. Restore paths verify hashes before writing.
- **Sandboxing**: AppArmor profile and seccomp policy block access outside monitored directories. Landlock and eBPF are behind feature flags and disabled by default.
- **Graceful fallback**: fanotify, Landlock, and eBPF are probed at runtime; missing features degrade to on-demand scanning rather than blocking file I/O.
- **Resource governance**: Configurable thread pool, future battery/thermal integration (via `heim` and `upower`). Feature flags allow NEON acceleration opting-in.

## Building

Ensure you have Rust 1.74+ and an aarch64 sysroot.

```bash
make build        # Debug build for development
make test         # Runs workspace tests
./scripts/build_deb.sh  # Produce a hardened .deb in artifacts/
```

## Installation (Prototype)

The generated `.deb` installs to `/usr/lib/charmedwoa-av/` and registers the AppArmor profile and systemd unit. Real-time monitoring remains in audit-only mode until explicitly enabled via CLI (`av-cli realtime on`).

## Testing Strategy

- Unit tests cover deterministic parsing and scoring primitives (`av-core`).
- Integration harness exercises `cargo check` and will grow to simulate fanotify/inotify flows on ARM64 hardware.
- Future CI: GitHub Actions with QEMU aarch64, SBOM, `cargo audit`, signed artefacts.

## Roadmap

- Implement fanotify event loop with permission responses where safe.
- Wire seccomp-bpf loader using `libseccomp` FFI and adopt Landlock confinement for helper subprocesses.
- Integrate YARA runtime, Bloom filter acceleration, and heuristic tuning based on baseline datasets.
- Expand CLI to manage allowlists, telemetry export, and update channels.
