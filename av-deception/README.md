# av-deception

Deception helpers for WinnCoreAV, including canary file generation and monitoring. Canary signals provide near-zero false positives for intrusion detection.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_deception::deploy_default_canaries;

fn main() -> anyhow::Result<()> {
    deploy_default_canaries()?;
    Ok(())
}
```

## License

Apache-2.0

