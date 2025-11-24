# Building WinnCoreAV eBPF Programs (Honest Notes)

Current status:
- The loader checks prerequisites and pins maps but does **not** load bytecode yet.
- Kernel fallback is supported via `/var/lib/winncore/state/ebpf_fallback_reason`.
- Ring buffer consumer wiring is stubbed until map layout is finalized.

Requirements for real eBPF loading:
1. Kernel >= 5.8 with bpffs mounted at `/sys/fs/bpf`.
2. BTF available at `/sys/kernel/btf/vmlinux` for CO-RE (optional but recommended).
3. `clang`, `llvm-strip`, `libbpf` build tooling.
4. A compiled object placed at `/usr/lib/winncore/bpf/winncore.o` (or adjust loader search path).

Suggested build steps (not automated here):
```bash
sudo apt-get install clang llvm libbpf-dev
pushd av-ebpf-loader
# Place C sources under src/bpf/ and build with libbpf-cargo or a Makefile
# Example (if you add a Makefile):
# make -C src/bpf
popd
```

Loader behavior:
- On success: pins maps under `/sys/fs/bpf/winncore` and removes fallback markers.
- On failure: writes fallback marker/reason so the daemon can use procfs polling.
- Exits 0 on fallback to allow systemd to continue starting the daemon.

Known gaps:
- No shipped `.o` files in this repo.
- No verified struct layout tests across C/Rust yet.
- No perf/epoll wiring for the consumer until maps are defined.

Recommendation:
- Treat current eBPF path as “in-progress”. Use procfs fallback for functional demos.
