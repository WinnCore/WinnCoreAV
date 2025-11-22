use ndarray::Array2;
use ort::session::builder::{GraphOptimizationLevel, SessionBuilder};
use ort::value::Value;

fn main() -> anyhow::Result<()> {
    println!("🔍 Debugging model outputs...\n");

    let mut session = SessionBuilder::new()?
        .with_optimization_level(GraphOptimizationLevel::Level3)?
        .commit_from_file("models/gbm_v3_hardened.onnx")?;

    let features = vec![0.0f32; 26];
    let arr = Array2::from_shape_vec((1, 26), features)?;
    let input = Value::from_array(arr)?;

    let outputs = session.run(ort::inputs![input])?;

    println!("Number of outputs: {}", outputs.len());

    for (i, (name, output)) in outputs.iter().enumerate() {
        let shape = output.shape();
        println!("\nOutput {} (name: {}):", i, name);
        println!("  Shape: {:?}", shape);

        if let Ok((_, data)) = output.try_extract_tensor::<f32>() {
            println!("  Type: f32");
            println!("  Values: {:?}", &data[..data.len().min(10)]);
        } else if let Ok((_, data)) = output.try_extract_tensor::<i64>() {
            println!("  Type: i64");
            println!("  Values: {:?}", &data[..data.len().min(10)]);
        } else if let Ok((_, data)) = output.try_extract_tensor::<f64>() {
            println!("  Type: f64");
            println!("  Values: {:?}", &data[..data.len().min(10)]);
        }
    }

    Ok(())
}
