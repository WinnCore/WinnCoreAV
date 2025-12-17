# av-iouring

io_uring attack detection scaffolding for WinnCoreAV. io_uring can bypass syscall-level monitoring; this crate provides a detector that ingests events and scores risk.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_iouring::IoUringDetector;

fn main() {
    let _detector = IoUringDetector::new();
}
```

## License

Apache-2.0

