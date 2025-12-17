# av-quarantine

Encrypted quarantine manager for WinnCoreAV with metadata tracking. Stores files with AES-256-GCM encryption and maintains an index for restore workflows.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_quarantine::{QuarantineConfig, QuarantineManager};

fn main() -> anyhow::Result<()> {
    let manager = QuarantineManager::new(QuarantineConfig::default())?;
    let _ = manager;
    Ok(())
}
```

## License

Apache-2.0

