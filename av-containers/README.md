# av-containers

Container and Kubernetes escape detection helpers for WinnCoreAV. Detects risky container contexts and common escape indicators such as Docker socket access or namespace abuse.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_containers::ContainerDetector;

fn main() {
    let detector = ContainerDetector::new();
    println!("In container: {}", detector.in_container());
}
```

## License

Apache-2.0

