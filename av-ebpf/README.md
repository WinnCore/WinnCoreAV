# av-ebpf

eBPF collection and helpers for WinnCoreAV telemetry and detections. Provides a behavioral monitor that can consume eBPF events when available and fall back to procfs polling.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_ebpf::BehavioralMonitor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let monitor = BehavioralMonitor::new();
    monitor.start().await?;
    monitor.stop();
    Ok(())
}
```

## License

Apache-2.0

