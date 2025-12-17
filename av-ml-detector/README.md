# av-ml-detector

ML-based malware scoring and feature extraction for WinnCoreAV. Loads an ONNX model, extracts ELF features (with ARM64 focus), and produces a detection score with confidence.

Part of [WinnCoreAV](https://github.com/WinnCore/WinnCoreAV) - ARM64-native endpoint detection for Linux.

## Usage

```rust
use av_ml_detector::MlDetector;

fn main() -> anyhow::Result<()> {
    let detector = MlDetector::new("models/model.onnx")?;
    let _ = detector;
    Ok(())
}
```

## License

Apache-2.0

