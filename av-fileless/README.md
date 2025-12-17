# av-fileless

Fileless malware detection helpers for WinnCoreAV. Includes checks for memfd execution, `/dev/shm` execution, and other fileless techniques common on Linux.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_fileless::scan_for_fileless;

fn main() {
    let _ = scan_for_fileless();
}
```

## License

Apache-2.0

