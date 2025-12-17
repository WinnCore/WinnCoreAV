# av-rootkit

Rootkit and kernel tampering detection helpers for WinnCoreAV. Provides checks for hidden processes, suspicious kernel modules, and other kernel-level indicators.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_rootkit::scan_kernel_modules;

fn main() {
    let _ = scan_kernel_modules();
}
```

## License

Apache-2.0

