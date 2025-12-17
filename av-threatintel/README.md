# av-threatintel

Threat intelligence helpers for WinnCoreAV, including IOC storage and matching. Supports matching hashes and other indicators against a local database.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_threatintel::{IocDatabase, IocMatcher};

fn main() {
    let db = IocDatabase::default();
    let _matcher = IocMatcher::new(db);
}
```

## License

Apache-2.0

