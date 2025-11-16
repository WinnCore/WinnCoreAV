//! Machine Learning malware detection for WinnCoreAV
//! Feature extraction matches WinnCore-ML-Detector Python training pipeline

use anyhow::{anyhow, Context, Result};
use log::info;
use ndarray::Array2;
use ort::memory::Allocator;
use ort::session::{Session, builder::{GraphOptimizationLevel, SessionBuilder}};
use ort::value::{DynValueTypeMarker, Value, ValueType};
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MlError {
    #[error("Model not found: {0}")]
    ModelNotFound(String),
    
    #[error("Feature extraction failed: {0}")]
    FeatureExtraction(String),
    
    #[error("Inference failed: {0}")]
    InferenceFailed(String),
    
    #[error("Invalid ELF file: {0}")]
    InvalidElf(String),
}

#[derive(Debug, Clone)]
pub struct MlDetection {
    pub score: f32,
    pub is_malicious: bool,
    pub confidence: ConfidenceLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfidenceLevel {
    Low,
    Medium,
    High,
}

impl MlDetection {
    fn from_score(score: f32, threshold: f32) -> Self {
        let is_malicious = score >= threshold;
        let confidence = if score < 0.7 {
            ConfidenceLevel::Low
        } else if score < 0.9 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::High
        };
        
        Self {
            score,
            is_malicious,
            confidence,
        }
    }
}

pub struct MlDetector {
    session: Arc<Mutex<Session>>,
    threshold: f32,
}

impl MlDetector {
    pub fn new<P: AsRef<Path>>(model_path: P) -> Result<Self> {
        Self::with_threshold(model_path, 0.5)
    }
    
    pub fn with_threshold<P: AsRef<Path>>(model_path: P, threshold: f32) -> Result<Self> {
        let model_path = model_path.as_ref();
        
        if !model_path.exists() {
            return Err(MlError::ModelNotFound(
                model_path.to_string_lossy().to_string()
            ).into());
        }
        
        info!("Loading ML model: {:?}", model_path);
        
        let session = SessionBuilder::new()?
            .with_optimization_level(GraphOptimizationLevel::Level3)?
            .with_intra_threads(4)?
            .commit_from_file(model_path)?;
        
        info!("ML model loaded successfully (threshold: {})", threshold);
        
        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            threshold,
        })
    }
    
    /// Extract 14 features matching Python training pipeline
    /// 
    /// Feature order (MUST match Python):
    /// 1. file_size - Total binary size in bytes
    /// 2. entropy - Shannon entropy (0-8, higher = more random/packed)
    /// 3. entry_point - Program entry address
    /// 4. num_sections - Number of ELF sections
    /// 5. num_segments - Number of program segments
    /// 6. text_size - Size of .text section (executable code)
    /// 7. data_size - Size of .data section (initialized data)
    /// 8. rodata_size - Size of .rodata section (read-only data)
    /// 9. bss_size - Size of .bss section (uninitialized data)
    /// 10. num_dynsym - Number of dynamic symbols
    /// 11. num_symtab - Number of symbol table entries
    /// 12. is_stripped - Whether debug symbols are stripped (0 or 1)
    /// 13. is_pie - Position Independent Executable (0 or 1)
    /// 14. suspicious_strings - Count of suspicious string patterns
    fn extract_features(&self, file_path: &Path) -> Result<Vec<f32>> {
        // Read file
        let bytes = std::fs::read(file_path)
            .context("Failed to read file")?;
        
        // Basic validation
        if bytes.len() < 64 {
            return Err(MlError::InvalidElf("File too small".to_string()).into());
        }
        
        // Parse ELF
        let elf = goblin::elf::Elf::parse(&bytes)
            .map_err(|e| MlError::InvalidElf(format!("{}", e)))?;
        
        // For non-ARM64 binaries, return neutral features
        if elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
            return Ok(vec![0.0; 14]);
        }
        
        // Extract features in EXACT order as Python
        let mut features = Vec::with_capacity(14);
        
        // 1. file_size
        features.push(bytes.len() as f32);
        
        // 2. entropy
        features.push(calculate_entropy(&bytes));
        
        // 3. entry_point
        features.push(elf.entry as f32);
        
        // 4. num_sections
        features.push(elf.section_headers.len() as f32);
        
        // 5. num_segments
        features.push(elf.program_headers.len() as f32);
        
        // 6. text_size
        features.push(find_section_size(&elf, ".text"));
        
        // 7. data_size
        features.push(find_section_size(&elf, ".data"));
        
        // 8. rodata_size
        features.push(find_section_size(&elf, ".rodata"));
        
        // 9. bss_size
        features.push(find_section_size(&elf, ".bss"));
        
        // 10. num_dynsym
        features.push(elf.dynsyms.len() as f32);
        
        // 11. num_symtab
        features.push(elf.syms.len() as f32);
        
        // 12. is_stripped (1 if no symbol table, 0 otherwise)
        features.push(if elf.syms.is_empty() { 1.0 } else { 0.0 });
        
        // 13. is_pie (1 if Position Independent Executable)
        features.push(
            if elf.header.e_type == goblin::elf::header::ET_DYN { 1.0 } else { 0.0 }
        );
        
        // 14. suspicious_strings
        features.push(count_suspicious_strings(&bytes) as f32);
        
        Ok(features)
    }
    
    pub fn scan<P: AsRef<Path>>(&self, file_path: P) -> Result<MlDetection> {
        let file_path = file_path.as_ref();
        
        // Extract features
        let features = self.extract_features(file_path)?;
        
        // Create input tensor (1 sample, 14 features)
        let input_array = Array2::from_shape_vec((1, 14), features)?;
        let input = Value::from_array(input_array)?;
        
        // Run inference
        let mut session = self.session.lock()
            .map_err(|e| MlError::InferenceFailed(format!("Mutex lock: {}", e)))?;
        
        let outputs = session.run(ort::inputs![input])?;
        
        // Extract prediction
        let value = &outputs[0];
        let (_, label_data) = value.try_extract_tensor::<i64>()?;
        let predicted_class = label_data[0];
        
        // Extract probability if available
        let probability = if outputs.len() > 1 {
            Self::extract_probability(&outputs[1])?
        } else {
            predicted_class as f32
        };
        
        Ok(MlDetection::from_score(probability, self.threshold))
    }
    
    fn extract_probability(prob_value: &Value) -> Result<f32> {
        // Try tensor extraction first (most common)
        if prob_value.is_tensor() {
            return Self::probability_from_tensor(prob_value);
        }
        
        // Try map-like extraction
        if let Some(prob) = Self::probability_from_map_like(prob_value) {
            return Ok(prob.clamp(0.0, 1.0));
        }
        
        // Try sequence extraction
        if matches!(prob_value.dtype(), ValueType::Sequence(_)) {
            return Self::probability_from_sequence(prob_value);
        }
        
        Err(anyhow!(
            "Unsupported probability output type: {:?}",
            prob_value.dtype()
        ))
    }
    
    fn probability_from_tensor(prob_value: &Value) -> Result<f32> {
        // Try f32 tensor
        if let Ok((_, probs)) = prob_value.try_extract_tensor::<f32>() {
            return Self::pick_probability_from_slice(&probs, |v| v)
                .context("Probability tensor was empty")
                .map(|prob| prob.clamp(0.0, 1.0));
        }
        
        // Try f64 tensor
        if let Ok((_, probs)) = prob_value.try_extract_tensor::<f64>() {
            return Self::pick_probability_from_slice(&probs, |v| v as f32)
                .context("Probability tensor was empty")
                .map(|prob| prob.clamp(0.0, 1.0));
        }
        
        Err(anyhow!("Unsupported tensor element type for probability output"))
    }
    
    fn probability_from_sequence(prob_value: &Value) -> Result<f32> {
        let allocator = Allocator::default();
        let values = prob_value.try_extract_sequence::<DynValueTypeMarker>(&allocator)?;
        
        let first = values
            .into_iter()
            .next()
            .context("Probability sequence was empty")?;
        
        Self::probability_from_map_like(&first)
            .map(|prob| prob.clamp(0.0, 1.0))
            .context("Failed to parse probability map from sequence entry")
    }
    
    fn probability_from_map_like(value: &Value) -> Option<f32> {
        // Try i64 -> f32 map
        if let Ok(map) = value.try_extract_map::<i64, f32>() {
            if let Some(prob) = map.get(&1).copied().or_else(|| map.get(&0).map(|p| 1.0 - p)) {
                return Some(prob);
            }
        }
        
        // Try String -> f32 map
        if let Ok(map) = value.try_extract_map::<String, f32>() {
            for key in ["1", "malicious"] {
                if let Some(prob) = map.get(key).copied() {
                    return Some(prob);
                }
            }
            for key in ["0", "benign"] {
                if let Some(prob) = map.get(key) {
                    return Some(1.0 - *prob);
                }
            }
        }
        
        None
    }
    
    fn pick_probability_from_slice<T: Copy>(
        data: &[T],
        convert: impl Fn(T) -> f32,
    ) -> Option<f32> {
        if data.len() >= 2 {
            Some(convert(data[1]))
        } else {
            data.first().copied().map(convert)
        }
    }
}

/// Calculate Shannon entropy of binary data
/// Returns value between 0.0 (no randomness) and 8.0 (maximum randomness)
/// High entropy often indicates packed/encrypted malware
fn calculate_entropy(bytes: &[u8]) -> f32 {
    let mut counts = [0u32; 256];
    
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    
    let len = bytes.len() as f32;
    let mut entropy = 0.0;
    
    for &count in &counts {
        if count > 0 {
            let probability = count as f32 / len;
            entropy -= probability * probability.log2();
        }
    }
    
    entropy
}

/// Find section size by name
/// Returns size in bytes, or 0.0 if section not found
fn find_section_size(elf: &goblin::elf::Elf, name: &str) -> f32 {
    for section in &elf.section_headers {
        if let Some(section_name) = elf.shdr_strtab.get_at(section.sh_name) {
            if section_name == name {
                return section.sh_size as f32;
            }
        }
    }
    0.0
}

/// Count suspicious string patterns
/// These patterns are common in malware (shells, downloaders, privilege escalation)
fn count_suspicious_strings(bytes: &[u8]) -> usize {
    let patterns: &[&[u8]] = &[
        b"/tmp/",         // Temp directory - droppers
        b"/dev/shm",      // Shared memory - persistence
        b"wget",          // Download tools
        b"curl",          // Download tools
        b"chmod",         // Permission changes
        b"sh -c",         // Shell execution
        b"/bin/sh",       // Direct shell
        b"exec",          // Process replacement
        b"LD_PRELOAD",    // Library injection
        b"setuid",        // Privilege escalation
        b"ptrace",        // Anti-analysis
    ];
    
    patterns
        .iter()
        .map(|pattern| {
            bytes
                .windows(pattern.len())
                .filter(|window| *window == *pattern)
                .count()
        })
        .sum()
}
