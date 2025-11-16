use ort::session::builder::{GraphOptimizationLevel, SessionBuilder};
use ort::value::Value;
use ndarray::Array2;

fn main() -> anyhow::Result<()> {
    let mut session = SessionBuilder::new()?
        .with_optimization_level(GraphOptimizationLevel::Level3)?
        .commit_from_file("models/gbm_v3_hardened.onnx")?;
    
    let features = vec![0.0f32; 26];
    let arr = Array2::from_shape_vec((1, 26), features)?;
    let input = Value::from_array(arr)?;
    let outputs = session.run(ort::inputs![input])?;
    
    println!("Total outputs: {}", outputs.len());
    
    for i in 0..outputs.len() {
        println!("\n--- Output {} ---", i);
        let val = &outputs[i];
        println!("Shape: {:?}", val.shape());
        
        if let Ok((_, data)) = val.try_extract_tensor::<f32>() {
            println!("Type: f32");
            println!("Data: {:?}", &data[..data.len().min(5)]);
        } else if let Ok((_, data)) = val.try_extract_tensor::<f64>() {
            println!("Type: f64");
            println!("Data: {:?}", &data[..data.len().min(5)]);
        } else if let Ok((_, data)) = val.try_extract_tensor::<i64>() {
            println!("Type: i64");
            println!("Data: {:?}", &data[..data.len().min(5)]);
        }
    }
    
    Ok(())
}
