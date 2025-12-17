# av-core

Core scanning primitives for WinnCoreAV. Provides the `Scanner` API, signature evaluation hooks, and heuristic scoring used by the daemon and CLI.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_core::{Scanner, ScannerConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let scanner = Scanner::new(ScannerConfig::default())?;
    let outcome = scanner.scan_path("/path/to/file").await?;
    println!("{:?}", outcome.recommended_action);
    Ok(())
}
```

## License

Apache-2.0

