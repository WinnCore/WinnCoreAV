# av-behavioral

Behavioral detection rules engine for WinnCoreAV. Loads rule definitions and evaluates process and file events with MITRE ATT&CK mappings.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_behavioral::RuleEngine;

fn main() {
    let mut engine = RuleEngine::new();
    // engine.load_rules(...);
    let _ = engine;
}
```

## License

Apache-2.0

