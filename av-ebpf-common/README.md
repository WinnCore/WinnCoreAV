# av-ebpf-common

Shared `repr(C)` types used by WinnCoreAV eBPF probes and userspace consumers. Keep layouts stable to ensure kernel/userspace compatibility.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_ebpf_common::{EventType, MAX_PATH_LEN};

fn main() {
    let _ = (EventType::ProcessExec, MAX_PATH_LEN);
}
```

## License

Apache-2.0

