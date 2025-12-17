# av-signatures

Signature bundle fetching and verification for WinnCoreAV. Supports retrieving signed signature bundles, verifying Ed25519 signatures, and updating local YARA rule caches.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_signatures::{SignatureManager, SignatureSource};

fn main() -> anyhow::Result<()> {
    let sources: Vec<SignatureSource> = Vec::new();
    let mut mgr = SignatureManager::new(sources, std::path::PathBuf::from("./signatures"))?;
    let _ = mgr;
    Ok(())
}
```

## License

Apache-2.0

