use av_ml_detector::MlDetector;
use std::env;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <binary-file>", args[0]);
        std::process::exit(1);
    }
    
    let file = &args[1];
    let model = "models/gbm_v3_hardened.onnx";
    
    println!("Loading model: {}", model);
    let detector = MlDetector::new(model)?;
    
    println!("Scanning: {}", file);
    let result = detector.scan(file)?;
    
    println!("\n📊 ML Detection Result:");
    println!("  Score: {:.4}", result.score);
    println!("  Malicious: {}", result.is_malicious);
    println!("  Confidence: {:?}", result.confidence);
    
    Ok(())
}
