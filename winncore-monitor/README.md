# winncore-monitor

Realtime file monitoring and scanning runtime used by WinnCoreAV components. Provides an owned Tokio runtime, file watching, queueing, and scanning orchestration.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use winncore_monitor::FileMonitor;

fn main() {
    // See crate docs for configuration options and runtime ownership details.
    let _ = FileMonitor;
}
```

## License

Apache-2.0

