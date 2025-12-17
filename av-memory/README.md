# av-memory

Memory scanning primitives for WinnCoreAV to help spot fileless threats. Provides helpers to scan memory regions and detect shellcode-like patterns.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_memory::MemoryScanner;

fn main() {
    let _scanner = MemoryScanner::default();
}
```

## License

Apache-2.0

