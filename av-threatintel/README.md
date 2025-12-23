# av-threatintel

Threat intelligence integration for WinnCoreAV, including IOC storage, lookup, and feed clients (TAXII, MISP, VirusTotal).

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use std::sync::Arc;

use av_threatintel::{IocDatabase, LookupEngine};

fn main() -> anyhow::Result<()> {
    let db = Arc::new(IocDatabase::open("/var/lib/winncore/threatintel")?);
    let engine = LookupEngine::new(db).with_min_confidence(50);

    let _match = engine.lookup_auto("example.com", Default::default());
    Ok(())
}
```

## Feeds

Feed configs are loaded externally (e.g. daemon config) and API keys are read from environment variables.

- TAXII/MISP/VirusTotal API keys must be provided via `*_env` fields (e.g. `api_key_env`) and resolved from the environment.
- Feed updates are logged via `tracing`.

## License

Apache-2.0
