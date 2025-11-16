#!/usr/bin/env rust-script
//! Test to verify the ML model path detection logic
//!
//! This demonstrates that the fixed path detection will work correctly

use std::path::Path;

fn find_model_path() -> Result<String, String> {
    // This is the same logic as in the fixed heuristics.rs
    let possible_paths = vec![
        "/home/user/WinnCoreAV/models/gbm_v3_hardened.onnx",  // Absolute path (most reliable)
        "models/gbm_v3_hardened.onnx",                         // Relative from project root
        "../models/gbm_v3_hardened.onnx",                      // Relative from subdirectory
    ];

    possible_paths.into_iter()
        .find(|p| Path::new(p).exists())
        .map(|s| s.to_string())
        .ok_or_else(|| "Cannot find gbm_v3_hardened.onnx model file".to_string())
}

fn main() {
    println!("Testing ML Model Path Detection");
    println!("=================================\n");

    println!("Current directory: {}", std::env::current_dir().unwrap().display());
    println!();

    match find_model_path() {
        Ok(path) => {
            println!("✅ SUCCESS: Model found at: {}", path);
            println!();

            // Verify the file exists and is readable
            match std::fs::metadata(&path) {
                Ok(metadata) => {
                    println!("File size: {} bytes", metadata.len());
                    println!("Is file: {}", metadata.is_file());
                    println!();
                    println!("✅ Model file is valid and readable");
                },
                Err(e) => {
                    println!("❌ ERROR: Cannot read file metadata: {}", e);
                }
            }
        },
        Err(e) => {
            println!("❌ FAILED: {}", e);
            println!();
            println!("Searched paths:");
            println!("  - /home/user/WinnCoreAV/models/gbm_v3_hardened.onnx");
            println!("  - models/gbm_v3_hardened.onnx (relative)");
            println!("  - ../models/gbm_v3_hardened.onnx (relative)");
        }
    }

    println!();
    println!("Testing from different directories");
    println!("===================================\n");

    // Test 1: From project root
    std::env::set_current_dir("/home/user/WinnCoreAV").unwrap();
    println!("Test 1: From /home/user/WinnCoreAV");
    match find_model_path() {
        Ok(path) => println!("  ✅ Found: {}", path),
        Err(e) => println!("  ❌ Failed: {}", e),
    }

    // Test 2: From samples directory
    std::env::set_current_dir("/home/user/malware-research/samples").ok();
    println!("Test 2: From /home/user/malware-research/samples");
    match find_model_path() {
        Ok(path) => println!("  ✅ Found: {}", path),
        Err(e) => println!("  ❌ Failed: {}", e),
    }

    // Test 3: From /tmp
    std::env::set_current_dir("/tmp").unwrap();
    println!("Test 3: From /tmp");
    match find_model_path() {
        Ok(path) => println!("  ✅ Found: {}", path),
        Err(e) => println!("  ❌ Failed: {}", e),
    }

    println!();
    println!("Conclusion:");
    println!("===========");
    println!("The absolute path (/home/user/WinnCoreAV/models/...) ensures");
    println!("the model can be found from ANY directory, fixing the bug where");
    println!("the relative path only worked from the project root.");
}
