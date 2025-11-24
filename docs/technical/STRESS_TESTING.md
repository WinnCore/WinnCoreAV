# Stress & Benchmark Suite

Location: `av-core/tests/stress_*.rs`, `av-core/benches/*.rs`

## Tests (all `#[ignore]` to avoid accidental long runs)
- `stress_24h_soak`: 24h (configurable) soak with memory/CPU sampling, 8 workers scanning a 10k corpus. Env overrides: `WINNCORE_SOAK_SECS`, `WINNCORE_SOAK_WORKERS`, `WINNCORE_SOAK_CORPUS`.
- `stress_memory_pressure`: Allocates configurable MB (`WINNCORE_MEM_STRESS_MB`, default 2048) then scans 500 files to ensure graceful degradation under pressure.
- `stress_io_heavy`: Creates 50k files and scans with configurable workers (`WINNCORE_IO_FILES`, `WINNCORE_IO_WORKERS`); checks for descriptor leaks and errors.
- `stress_concurrent_scanning_ext`: 100-thread scan fan-out over 4k files; env override `WINNCORE_CONC_THREADS`.

## Benches (Criterion)
- `file_scanning`: Read-head throughput over 200 `/usr/bin` files.
- `hash_performance`: SHA-512 throughput on 1 MiB buffers.

## Running
```bash
# Heavy stress examples (release builds recommended)
cargo test --release -p av-core stress_24h_soak -- --ignored --nocapture
cargo test --release -p av-core stress_memory_pressure -- --ignored --nocapture
cargo test --release -p av-core stress_io_heavy -- --ignored --nocapture
cargo test --release -p av-core stress_concurrent_scanning_ext -- --ignored --nocapture

# Benches
cargo bench -p av-core
```

## Notes
- Corpus defaults to `/usr/bin`; adjust via env vars if unavailable.
- Tests are intentionally long/heavy; keep them manual and monitored.
- Memory/CPU reporting relies on `sysinfo`; soak test prints growth warnings past 50%.
