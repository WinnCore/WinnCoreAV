# av-response

Automated response helpers for WinnCoreAV. Provides an executor abstraction for actions like process termination and other remediation steps.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_response::{ResponseAction, ResponseExecutor};

fn main() {
    let _ = (ResponseAction::Alert, ResponseExecutor::default());
}
```

## License

Apache-2.0

