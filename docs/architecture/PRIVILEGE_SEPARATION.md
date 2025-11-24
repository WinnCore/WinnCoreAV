# WinnCoreAV Privilege Separation Architecture

## Design Principles

1. **Minimal Root Exposure**: Only `av-ebpf-loader` runs as root, and only during startup.
2. **Capability-Based**: Prefer Linux capabilities (CAP_SYS_ADMIN, CAP_BPF, CAP_PERFMON) over full root.
3. **Process Isolation**: Components run as separate processes with restricted permissions.
4. **Fail-Safe**: If a privileged component dies, the unprivileged daemon continues in a degraded mode.

## Component Responsibilities

### av-ebpf-loader (root, exits after setup)
- Loads eBPF programs into the kernel.
- Pins BPF maps to `/sys/fs/bpf/winncore/`.
- Sets up perf/ring buffers.
- Drops to unprivileged user after setup.

### av-daemon (runs as `winncore` user)
- Reads events from pinned BPF maps.
- Runs rule engine and ML inference.
- Manages quarantine operations.
- Exposes metrics endpoint.
- Needs minimal read capabilities (`CAP_DAC_READ_SEARCH`).

### av-watchdog (runs as root)
- Monitors av-daemon and eBPF health.
- Restarts components on failure.
- Emits health telemetry.

## Filesystem Layout

```
/usr/lib/winncore/
├── av-ebpf-loader      # SUID root or capability-wrapped
├── av-daemon           # Main daemon binary
├── av-watchdog         # Health monitor
└── bpf/
    └── *.o             # Compiled BPF programs

/etc/winncore/
├── config.toml         # Main configuration
├── rules/
│   └── *.json          # Detection rules (versioned)
└── keys/
    └── signing.pub     # Rulepack verification key

/var/lib/winncore/
├── quarantine/         # Isolated malware (encrypted)
├── cache/              # ML model cache, YARA compiled rules
└── state/              # Persistent state

/var/log/winncore/
├── daemon.log          # Operational logs
├── alerts.jsonl        # Detection alerts (JSONL for SIEM)
└── audit.log           # Security audit trail

/sys/fs/bpf/winncore/   # Pinned BPF maps (created by loader)
├── events              # Ring buffer for events
├── config              # Runtime config map
└── stats               # Statistics map
```

## Startup Sequence

1. systemd starts `av-ebpf-loader` as root.
2. Loader validates BPF programs, loads into kernel, pins maps.
3. Loader verifies maps are accessible, then exits.
4. systemd starts `av-daemon` as `winncore` user.
5. Daemon opens pinned maps, begins processing.
6. systemd starts `av-watchdog` as root.
7. Watchdog monitors both components.

## Failure Modes

| Component Dies    | Impact                             | Recovery                          |
|-------------------|------------------------------------|-----------------------------------|
| av-ebpf-loader    | BPF already loaded, no impact      | None needed                       |
| av-daemon         | Events buffered in kernel          | Watchdog restarts, events replayed|
| av-watchdog       | No health monitoring               | systemd restarts                  |
| Kernel BPF maps   | Lose behavioral detection          | Fall back to static scanning      |

