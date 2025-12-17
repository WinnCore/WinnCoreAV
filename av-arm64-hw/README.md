# av-arm64-hw

ARM64 hardware security feature monitoring for WinnCoreAV. This crate provides helpers to detect and record signals related to PAC/BTI/MTE and optional PMU sampling where available.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_arm64_hw::{is_bti_supported, is_mte_supported, is_pac_supported};

fn main() {
    println!("PAC supported: {}", is_pac_supported());
    println!("BTI supported: {}", is_bti_supported());
    println!("MTE supported: {}", is_mte_supported());
}
```

## License

Apache-2.0

