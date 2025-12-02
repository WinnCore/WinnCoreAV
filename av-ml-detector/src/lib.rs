//! Machine Learning malware detection for WinnCoreAV
//! Feature extraction matches WinnCore-ML-Detector Python training pipeline

use anyhow::{anyhow, Context, Result};
use capstone::{arch, prelude::*, Insn};
use ndarray::Array2;
use ort::memory::Allocator;
use ort::session::{
    builder::{GraphOptimizationLevel, SessionBuilder},
    Session,
};
use ort::value::{DynValueTypeMarker, Value, ValueType};
use serde::Serialize;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, warn};

pub mod update;
use update::{select_model_from_manifest, ModelManifest};

/// Sampling + rate limiting interface for logging
pub trait MlLogSampler: Send + Sync {
    fn should_log_ml_inference(&self) -> bool;
    fn check_rate_limit(&self) -> bool;
}

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

#[derive(Debug, Clone, Serialize)]
pub struct MlDetection {
    pub score: f32,
    pub is_malicious: bool,
    pub confidence: ConfidenceLevel,
    pub feature_importance: Option<Vec<FeatureAttribution>>,
    pub adversarial_hint: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
            feature_importance: None,
            adversarial_hint: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FeatureAttribution {
    pub name: String,
    pub value: f32,
    pub rank: usize,
}

pub struct MlDetector {
    session: Arc<Mutex<Session>>,
    threshold: f32,
    log_sampler: Option<Arc<dyn MlLogSampler>>,
}

impl MlDetector {
    pub fn new<P: AsRef<Path>>(model_path: P) -> Result<Self> {
        Self::with_threshold(model_path, 0.5)
    }

    pub fn new_with_sampler<P: AsRef<Path>>(
        model_path: P,
        log_sampler: Option<Arc<dyn MlLogSampler>>,
    ) -> Result<Self> {
        Self::with_threshold_and_sampler(model_path, 0.5, log_sampler)
    }

    /// Resolve model using a manifest if present. If `lock_version` is set, prefer that version.
    pub fn from_manifest<P: AsRef<Path>>(
        manifest_path: P,
        lock_version: Option<&str>,
        threshold: f32,
    ) -> Result<Self> {
        Self::from_manifest_with_sampler(manifest_path, lock_version, threshold, None)
    }

    pub fn from_manifest_with_sampler<P: AsRef<Path>>(
        manifest_path: P,
        lock_version: Option<&str>,
        threshold: f32,
        log_sampler: Option<Arc<dyn MlLogSampler>>,
    ) -> Result<Self> {
        let manifest = ModelManifest::load(manifest_path.as_ref())?;
        let entry = select_model_from_manifest(&manifest, lock_version)
            .ok_or_else(|| anyhow!("No model entries in manifest"))?;
        let model_path = if let Some(p) = entry.path.as_ref() {
            Path::new(p).to_path_buf()
        } else {
            Path::new(&format!("models/{}.onnx", entry.model_name)).to_path_buf()
        };
        let detector = Self::with_threshold_and_sampler(&model_path, threshold, log_sampler)?;
        info!(
            "Selected model from manifest: {} version {} path {:?}",
            entry.model_name, entry.version, model_path
        );
        Ok(detector)
    }

    pub fn with_threshold<P: AsRef<Path>>(model_path: P, threshold: f32) -> Result<Self> {
        Self::with_threshold_and_sampler(model_path, threshold, None)
    }

    pub fn with_threshold_and_sampler<P: AsRef<Path>>(
        model_path: P,
        threshold: f32,
        log_sampler: Option<Arc<dyn MlLogSampler>>,
    ) -> Result<Self> {
        let model_path = model_path.as_ref();

        if !model_path.exists() {
            return Err(MlError::ModelNotFound(model_path.to_string_lossy().to_string()).into());
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
            log_sampler,
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
        let bytes = std::fs::read(file_path).context("Failed to read file")?;

        // Basic validation
        if bytes.len() < 64 || !bytes.starts_with(b"\x7FELF") {
            return Ok(neutral_features(&bytes));
        }

        // Parse ELF
        let elf = match goblin::elf::Elf::parse(&bytes) {
            Ok(elf) => elf,
            Err(e) => {
                warn!("Treating invalid ELF as neutral sample: {}", e);
                return Ok(neutral_features(&bytes));
            }
        };

        // For non-ARM64 binaries, return neutral features
        if elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
            return Ok(neutral_features(&bytes));
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
        features.push(if elf.header.e_type == goblin::elf::header::ET_DYN {
            1.0
        } else {
            0.0
        });

        // 14. suspicious_strings
        features.push(count_suspicious_strings(&bytes) as f32);

        Ok(features)
    }

    pub fn scan<P: AsRef<Path>>(&self, file_path: P) -> Result<MlDetection> {
        let file_path = file_path.as_ref();
        let start = Instant::now();

        // Extract features
        let features = self.extract_features(file_path)?;

        // Create input tensor (1 sample, 14 features)
        let input_array = Array2::from_shape_vec((1, 14), features.clone())?;
        let input = Value::from_array(input_array)?;

        // Run inference
        let mut session = self
            .session
            .lock()
            .map_err(|e| MlError::InferenceFailed(format!("Mutex lock: {}", e)))?;

        let outputs = session.run(ort::inputs![input])?;

        // Extract prediction
        let value = &outputs[0];
        let (_, label_data) = value.try_extract_tensor::<i64>()?;
        let predicted_class = 1 - label_data[0]; // FIX: Model inverted

        // Extract probability if available
        let probability = if outputs.len() > 1 {
            Self::extract_probability(&outputs[1])?
        } else {
            predicted_class as f32
        };

        let mut detection = MlDetection::from_score(1.0 - probability, self.threshold); // FIX: Model predictions inverted
        detection.feature_importance =
            Some(build_feature_attribution(&features, &BASE_FEATURE_NAMES));
        detection.adversarial_hint = adversarial_hint(&features);
        let elapsed = start.elapsed();

        if let Some(ref sampler) = self.log_sampler {
            if sampler.should_log_ml_inference() && sampler.check_rate_limit() {
                debug!(
                    target: "ml_inference",
                    file = %file_path.display(),
                    threat_score = detection.score,
                    inference_ms = elapsed.as_millis(),
                    "ML inference complete"
                );
            }
        }

        if detection.score > 0.8 {
            warn!(
                file = %file_path.display(),
                threat_score = detection.score,
                malicious = detection.is_malicious,
                "High-threat detection"
            );
        }
        Ok(detection)
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
            return Self::pick_probability_from_slice(probs, |v| v)
                .context("Probability tensor was empty")
                .map(|prob| prob.clamp(0.0, 1.0));
        }

        // Try f64 tensor
        if let Ok((_, probs)) = prob_value.try_extract_tensor::<f64>() {
            return Self::pick_probability_from_slice(probs, |v| v as f32)
                .context("Probability tensor was empty")
                .map(|prob| prob.clamp(0.0, 1.0));
        }

        Err(anyhow!(
            "Unsupported tensor element type for probability output"
        ))
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
            if let Some(prob) = map
                .get(&1)
                .copied()
                .or_else(|| map.get(&0).map(|p| 1.0 - p))
            {
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

    fn pick_probability_from_slice<T: Copy>(data: &[T], convert: impl Fn(T) -> f32) -> Option<f32> {
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

pub const BASE_FEATURE_NAMES: [&str; 14] = [
    "file_size",
    "entropy",
    "entry_point",
    "num_sections",
    "num_segments",
    "text_size",
    "data_size",
    "rodata_size",
    "bss_size",
    "num_dynsym",
    "num_symtab",
    "is_stripped",
    "is_pie",
    "suspicious_strings",
];

fn build_feature_attribution(features: &[f32], names: &[&str]) -> Vec<FeatureAttribution> {
    let mut pairs: Vec<(String, f32)> = features
        .iter()
        .zip(names.iter())
        .map(|(v, n)| (n.to_string(), *v))
        .collect();
    pairs.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    pairs
        .into_iter()
        .enumerate()
        .map(|(idx, (name, value))| FeatureAttribution {
            name,
            value,
            rank: idx + 1,
        })
        .collect()
}

fn adversarial_hint(features: &[f32]) -> bool {
    let entropy = features.get(1).copied().unwrap_or(0.0);
    let file_size = features.first().copied().unwrap_or(0.0);
    (entropy > 7.9 && file_size < 10_000.0) || entropy == 0.0 && file_size > 5_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adversarial_detects_high_entropy_small() {
        let mut feats = vec![5_000.0, 8.0];
        feats.resize(14, 0.0);
        assert!(adversarial_hint(&feats));
    }

    #[test]
    fn adversarial_detects_zero_entropy_large() {
        let mut feats = vec![6_000_000.0, 0.0];
        feats.resize(14, 0.0);
        assert!(adversarial_hint(&feats));
    }

    #[test]
    fn adversarial_normal_sample() {
        let mut feats = vec![50_000.0, 5.0];
        feats.resize(14, 0.0);
        assert!(!adversarial_hint(&feats));
    }
}

fn neutral_features(bytes: &[u8]) -> Vec<f32> {
    let mut features = vec![0.0; 14];
    if !bytes.is_empty() {
        features[0] = bytes.len() as f32;
        features[1] = calculate_entropy(bytes);
    }
    features
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
        b"/tmp/",      // Temp directory - droppers
        b"/dev/shm",   // Shared memory - persistence
        b"wget",       // Download tools
        b"curl",       // Download tools
        b"chmod",      // Permission changes
        b"sh -c",      // Shell execution
        b"/bin/sh",    // Direct shell
        b"exec",       // Process replacement
        b"LD_PRELOAD", // Library injection
        b"setuid",     // Privilege escalation
        b"ptrace",     // Anti-analysis
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

// ---------------------------------------------------------------------------
// Enhanced 52-feature extractor + ensemble inference
// ---------------------------------------------------------------------------

/// Ordered list of the enhanced feature set used by the Python training
/// pipeline. The Rust extractor fills values in this order to keep ONNX input
/// shapes aligned across languages.
pub const ENHANCED_FEATURE_ORDER: [&str; 52] = [
    "entry_point_va",
    "num_segments",
    "num_sections",
    "file_size_mb",
    "has_nx_stack",
    "has_pie",
    "has_relro",
    "has_canary",
    "suspicious_entry",
    "overlapping_sections",
    "unusual_section_count",
    "stripped_binary",
    "mean_section_entropy",
    "max_section_entropy",
    "std_section_entropy",
    "entropy_variance",
    "num_high_entropy_sections",
    "mean_executable_entropy",
    "max_executable_entropy",
    "mean_data_entropy",
    "max_data_entropy",
    "has_encrypted_section",
    "entropy_anomaly_score",
    "packed_section_ratio",
    "low_entropy_section_ratio",
    "text_section_entropy",
    "rodata_section_entropy",
    "imports_count",
    "exports_count",
    "dynsym_count",
    "symtab_count",
    "plt_got_entries",
    "suspicious_import_ratio",
    "stripped_dynamic",
    "string_table_size",
    "relocation_entries",
    "weak_symbol_ratio",
    "total_instructions",
    "syscall_density",
    "branch_density",
    "crypto_instruction_density",
    "memory_access_density",
    "abnormal_control_flow",
    "avg_basic_block_len",
    "indirect_branch_density",
    "ascii_string_density",
    "suspicious_string_count",
    "printable_ratio",
    "url_like_strings",
    "high_entropy_strings",
    "embedded_path_strings",
    "config_string_count",
];

/// Enhanced 52-feature extractor that mirrors the Python pipeline. It prefers
/// robustness over completeness: if a subsection fails to parse, zeros are
/// emitted so that inference can continue rather than panic.
pub struct EnhancedFeatureExtractor {
    disassembler: Capstone,
}

impl EnhancedFeatureExtractor {
    pub fn new() -> Result<Self> {
        let disassembler = Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .context("Failed to initialize capstone for ARM64")?;

        Ok(Self { disassembler })
    }

    pub fn extract_features<P: AsRef<Path>>(&self, path: P) -> Result<Vec<f32>> {
        let bytes = std::fs::read(path.as_ref())
            .with_context(|| format!("Failed to read {:?}", path.as_ref()))?;

        if bytes.len() < 64 {
            return Ok(vec![0.0; ENHANCED_FEATURE_ORDER.len()]);
        }

        let elf = goblin::elf::Elf::parse(&bytes).context("Failed to parse ELF")?;

        // Only process ARM64 binaries
        if elf.header.e_machine != goblin::elf::header::EM_AARCH64 {
            return Ok(vec![0.0; ENHANCED_FEATURE_ORDER.len()]);
        }

        let mut features: HashMap<&str, f32> = HashMap::new();

        self.header_features(&elf, &bytes, &mut features);
        self.entropy_features(&elf, &bytes, &mut features);
        self.symbol_features(&elf, &bytes, &mut features);
        self.instruction_features(&elf, &bytes, &mut features);
        self.string_features(&elf, &bytes, &mut features);

        let ordered = ENHANCED_FEATURE_ORDER
            .iter()
            .map(|k| *features.get(k).unwrap_or(&0.0))
            .collect();

        Ok(ordered)
    }

    fn header_features(
        &self,
        elf: &goblin::elf::Elf,
        bytes: &[u8],
        out: &mut HashMap<&'static str, f32>,
    ) {
        out.insert(
            "entry_point_va",
            (elf.entry as f64 / (2u64.pow(32) as f64)) as f32,
        );
        out.insert("num_segments", elf.program_headers.len() as f32);
        out.insert("num_sections", elf.section_headers.len() as f32);
        out.insert("file_size_mb", bytes.len() as f32 / (2f32.powi(20)));

        out.insert("has_nx_stack", if has_nx_stack(elf) { 1.0 } else { 0.0 });
        out.insert(
            "has_pie",
            if elf.header.e_type == goblin::elf::header::ET_DYN {
                1.0
            } else {
                0.0
            },
        );
        out.insert("has_relro", if has_relro(elf) { 1.0 } else { 0.0 });
        out.insert("has_canary", if has_stack_canary(elf) { 1.0 } else { 0.0 });

        out.insert(
            "suspicious_entry",
            if is_suspicious_entry(elf) { 1.0 } else { 0.0 },
        );
        out.insert("overlapping_sections", overlapping_sections(elf) as f32);
        out.insert(
            "unusual_section_count",
            if elf.section_headers.len() > 50 {
                1.0
            } else {
                0.0
            },
        );
        out.insert(
            "stripped_binary",
            if elf.syms.is_empty() { 1.0 } else { 0.0 },
        );
    }

    fn entropy_features(
        &self,
        elf: &goblin::elf::Elf,
        bytes: &[u8],
        out: &mut HashMap<&'static str, f32>,
    ) {
        let mut entropies = Vec::new();
        let mut exec_entropies = Vec::new();
        let mut data_entropies = Vec::new();

        for sh in &elf.section_headers {
            if sh.sh_size == 0 {
                continue;
            }
            if let Some(slice) = section_bytes(bytes, sh) {
                let e = calculate_entropy(slice);
                entropies.push(e);

                let flags = sh.sh_flags;
                if flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
                    exec_entropies.push(e);
                } else if flags & goblin::elf::section_header::SHF_WRITE as u64 != 0 {
                    data_entropies.push(e);
                }

                if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    if name == ".text" {
                        out.insert("text_section_entropy", e);
                    } else if name == ".rodata" {
                        out.insert("rodata_section_entropy", e);
                    }
                }
            }
        }

        out.insert("mean_section_entropy", safe_mean(&entropies));
        out.insert("max_section_entropy", safe_max(&entropies));
        out.insert("std_section_entropy", safe_std(&entropies));
        out.insert("entropy_variance", safe_variance(&entropies));
        out.insert(
            "num_high_entropy_sections",
            entropies.iter().filter(|e| **e > 7.5).count() as f32,
        );
        out.insert("mean_executable_entropy", safe_mean(&exec_entropies));
        out.insert("max_executable_entropy", safe_max(&exec_entropies));
        out.insert("mean_data_entropy", safe_mean(&data_entropies));
        out.insert("max_data_entropy", safe_max(&data_entropies));
        out.insert(
            "has_encrypted_section",
            if exec_entropies.iter().any(|e| *e > 7.8) {
                1.0
            } else {
                0.0
            },
        );
        out.insert("entropy_anomaly_score", entropy_anomaly(&entropies));

        if !entropies.is_empty() {
            let total = entropies.len() as f32;
            let packed = entropies.iter().filter(|e| **e >= 7.2).count() as f32;
            let low = entropies.iter().filter(|e| **e <= 5.0).count() as f32;
            out.insert("packed_section_ratio", packed / total);
            out.insert("low_entropy_section_ratio", low / total);
        } else {
            out.insert("packed_section_ratio", 0.0);
            out.insert("low_entropy_section_ratio", 0.0);
        }
    }

    fn symbol_features(
        &self,
        elf: &goblin::elf::Elf,
        _bytes: &[u8],
        out: &mut HashMap<&'static str, f32>,
    ) {
        let imports: Vec<&str> = elf
            .dynsyms
            .iter()
            .filter_map(|s| elf.dynstrtab.get_at(s.st_name))
            .collect();
        let exports: Vec<&str> = elf
            .syms
            .iter()
            .filter(|s| {
                s.st_bind() == goblin::elf::sym::STB_GLOBAL
                    && s.st_shndx != goblin::elf::section_header::SHN_UNDEF as usize
            })
            .filter_map(|s| elf.strtab.get_at(s.st_name))
            .collect();

        out.insert("imports_count", imports.len() as f32);
        out.insert("exports_count", exports.len() as f32);
        out.insert("dynsym_count", elf.dynsyms.len() as f32);
        out.insert("symtab_count", elf.syms.len() as f32);
        out.insert("plt_got_entries", elf.pltrelocs.len() as f32);

        let suspicious = [
            "ptrace", "system", "execve", "socket", "connect", "kill", "dlopen",
        ];
        let suspicious_hits = imports
            .iter()
            .filter(|name| suspicious.iter().any(|marker| name.contains(marker)))
            .count();
        out.insert(
            "suspicious_import_ratio",
            if imports.is_empty() {
                0.0
            } else {
                suspicious_hits as f32 / imports.len() as f32
            },
        );

        out.insert(
            "stripped_dynamic",
            if elf.dynsyms.is_empty() && !imports.is_empty() {
                1.0
            } else {
                0.0
            },
        );

        let string_table_size = elf.strtab.to_vec().map(|v| v.len()).unwrap_or(0) as f32;
        out.insert("string_table_size", string_table_size);

        let relocation_entries = elf.pltrelocs.len() + elf.dynrelas.len() + elf.dynrels.len();
        out.insert("relocation_entries", relocation_entries as f32);

        let weak_symbols = elf
            .syms
            .iter()
            .filter(|s| s.st_bind() == goblin::elf::sym::STB_WEAK)
            .count();
        out.insert(
            "weak_symbol_ratio",
            if elf.syms.is_empty() {
                0.0
            } else {
                weak_symbols as f32 / elf.syms.len() as f32
            },
        );
    }

    fn instruction_features(
        &self,
        elf: &goblin::elf::Elf,
        bytes: &[u8],
        out: &mut HashMap<&'static str, f32>,
    ) {
        let text_section = elf.section_headers.iter().find(|sh| {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                name == ".text"
            } else {
                false
            }
        });

        let text = match text_section.and_then(|sh| section_bytes(bytes, sh)) {
            Some(t) => t,
            None => {
                self.zero_instruction_features(out);
                return;
            }
        };

        let base = text_section.map(|sh| sh.sh_addr).unwrap_or(0);
        let insns = match self.disassembler.disasm_all(text, base) {
            Ok(list) => list,
            Err(_) => {
                self.zero_instruction_features(out);
                return;
            }
        };

        if insns.is_empty() {
            self.zero_instruction_features(out);
            return;
        }

        let mut syscall_count = 0usize;
        let mut branch_count = 0usize;
        let mut crypto_count = 0usize;
        let mut memory_access_count = 0usize;
        let mut indirect_branch_count = 0usize;
        let mut basic_block_lengths = Vec::new();
        let mut current_block = 0usize;

        let branch_mnemonics = ["b", "bl", "br", "blr", "ret", "cbz", "cbnz", "tbz", "tbnz"];

        for insn in insns.iter() {
            current_block += 1;
            let mnemonic = insn.mnemonic().unwrap_or_default();
            if mnemonic == "svc" {
                syscall_count += 1;
            }
            if branch_mnemonics.contains(&mnemonic) {
                branch_count += 1;
                basic_block_lengths.push(current_block);
                current_block = 0;
            }
            if mnemonic.starts_with("aes")
                || mnemonic.starts_with("sha")
                || mnemonic.starts_with("pmull")
            {
                crypto_count += 1;
            }
            if ["ldr", "str", "ldp", "stp"].contains(&mnemonic) {
                memory_access_count += 1;
            }
            if ["br", "blr"].contains(&mnemonic) {
                indirect_branch_count += 1;
            }
        }

        if current_block > 0 {
            basic_block_lengths.push(current_block);
        }

        let total = insns.len() as f32;
        out.insert("total_instructions", total);
        out.insert("syscall_density", syscall_count as f32 / total);
        out.insert("branch_density", branch_count as f32 / total);
        out.insert("crypto_instruction_density", crypto_count as f32 / total);
        out.insert("memory_access_density", memory_access_count as f32 / total);
        out.insert(
            "indirect_branch_density",
            indirect_branch_count as f32 / total,
        );
        out.insert("avg_basic_block_len", safe_mean_f64(&basic_block_lengths));
        out.insert(
            "abnormal_control_flow",
            if detect_control_flow_anomaly(&insns) {
                1.0
            } else {
                0.0
            },
        );
    }

    fn string_features(
        &self,
        elf: &goblin::elf::Elf,
        bytes: &[u8],
        out: &mut HashMap<&'static str, f32>,
    ) {
        let mut blob = Vec::new();
        for sh in &elf.section_headers {
            let flags = sh.sh_flags;
            let alloc = flags & goblin::elf::section_header::SHF_ALLOC as u64 != 0;
            let exec = flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0;
            if alloc && !exec {
                if let Some(slice) = section_bytes(bytes, sh) {
                    blob.extend_from_slice(slice);
                }
            }
        }

        if blob.is_empty() {
            self.zero_string_features(out);
            return;
        }

        let ascii_strings = extract_ascii_strings(&blob, 4);
        let printable = blob.iter().filter(|b| **b >= 32 && **b <= 126).count() as f32;
        let total_len = blob.len() as f32;

        let markers = ["/tmp/", "/dev/shm", "curl", "wget", "chmod", "/bin/sh"];
        let suspicious_hits = ascii_strings
            .iter()
            .map(|s| markers.iter().map(|m| s.matches(m).count()).sum::<usize>())
            .sum::<usize>() as f32;

        let high_entropy_strings = ascii_strings
            .iter()
            .filter(|s| calculate_entropy(s.as_bytes()) > 4.5)
            .count() as f32;
        let url_like = ascii_strings
            .iter()
            .filter(|s| s.contains("://") || s.starts_with("www."))
            .count() as f32;
        let embedded_paths = ascii_strings
            .iter()
            .filter(|s| s.contains('/') && s.len() > 5)
            .count() as f32;
        let config_strings = ascii_strings
            .iter()
            .filter(|s| s.contains('=') && s.len() < 128)
            .count() as f32;

        out.insert(
            "ascii_string_density",
            ascii_strings.len() as f32 / total_len,
        );
        out.insert("suspicious_string_count", suspicious_hits);
        out.insert("printable_ratio", printable / total_len);
        out.insert("url_like_strings", url_like);
        out.insert("high_entropy_strings", high_entropy_strings);
        out.insert("embedded_path_strings", embedded_paths);
        out.insert("config_string_count", config_strings);
    }

    fn zero_instruction_features(&self, out: &mut HashMap<&'static str, f32>) {
        for key in [
            "total_instructions",
            "syscall_density",
            "branch_density",
            "crypto_instruction_density",
            "memory_access_density",
            "abnormal_control_flow",
            "avg_basic_block_len",
            "indirect_branch_density",
        ] {
            out.insert(key, 0.0);
        }
    }

    fn zero_string_features(&self, out: &mut HashMap<&'static str, f32>) {
        for key in [
            "ascii_string_density",
            "suspicious_string_count",
            "printable_ratio",
            "url_like_strings",
            "high_entropy_strings",
            "embedded_path_strings",
            "config_string_count",
        ] {
            out.insert(key, 0.0);
        }
    }
}

pub struct EnsembleDetector {
    lgb_session: Arc<Mutex<Session>>,
    xgb_session: Arc<Mutex<Session>>,
    mlp_session: Arc<Mutex<Session>>,
    threshold: f32,
    feature_count: usize,
}

#[derive(Debug, Clone)]
pub struct EnsembleResult {
    pub is_malware: bool,
    pub confidence: f32,
    pub lgb_probability: f32,
    pub xgb_probability: f32,
    pub mlp_probability: f32,
    pub model_agreement: f32,
}

impl EnsembleDetector {
    pub fn new<P: AsRef<Path>>(lgb_path: P, xgb_path: P, mlp_path: P) -> Result<Self> {
        let lgb_session = Arc::new(Mutex::new(
            SessionBuilder::new()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(4)?
                .commit_from_file(lgb_path.as_ref())?,
        ));
        let xgb_session = Arc::new(Mutex::new(
            SessionBuilder::new()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(4)?
                .commit_from_file(xgb_path.as_ref())?,
        ));
        let mlp_session = Arc::new(Mutex::new(
            SessionBuilder::new()?
                .with_optimization_level(GraphOptimizationLevel::Level3)?
                .with_intra_threads(4)?
                .commit_from_file(mlp_path.as_ref())?,
        ));

        Ok(Self {
            lgb_session,
            xgb_session,
            mlp_session,
            threshold: 0.5,
            feature_count: ENHANCED_FEATURE_ORDER.len(),
        })
    }

    pub fn predict(&self, features: &[f32]) -> Result<EnsembleResult> {
        if features.len() != self.feature_count {
            return Err(anyhow!(
                "Feature length mismatch: expected {}, got {}",
                self.feature_count,
                features.len()
            ));
        }

        let array = Array2::from_shape_vec((1, features.len()), features.to_vec())
            .context("Failed to build feature tensor")?;

        let lgb_prob = self.run_model(&self.lgb_session, &array)?;
        let xgb_prob = self.run_model(&self.xgb_session, &array)?;
        let mlp_prob = self.run_model(&self.mlp_session, &array)?;

        let weighted = (lgb_prob * 2.0 + xgb_prob + mlp_prob) / 4.0;
        let agreement = model_agreement(&[lgb_prob, xgb_prob, mlp_prob]);

        Ok(EnsembleResult {
            is_malware: weighted >= self.threshold,
            confidence: weighted,
            lgb_probability: lgb_prob,
            xgb_probability: xgb_prob,
            mlp_probability: mlp_prob,
            model_agreement: agreement,
        })
    }

    fn run_model(&self, session: &Mutex<Session>, array: &Array2<f32>) -> Result<f32> {
        let mut session = session
            .lock()
            .map_err(|e| anyhow!("Session lock poisoned: {e}"))?;
        let input = Value::from_array(array.clone())?;
        let outputs = session.run(ort::inputs![input])?;

        let owned_outputs: Vec<Value> = outputs
            .values()
            .map(|v| {
                v.try_upgrade()
                    .map_err(|_| anyhow!("failed to upgrade output value"))
            })
            .collect::<Result<_>>()?;

        probability_from_outputs(&owned_outputs)
    }
}

fn probability_from_outputs(outputs: &[Value]) -> Result<f32> {
    // Try each output until one yields a usable probability vector.
    for value in outputs {
        if let Ok(prob) = probability_from_value(value) {
            return Ok(prob.clamp(0.0, 1.0));
        }
    }
    Err(anyhow!("No probability output found"))
}

fn probability_from_value(prob_value: &Value) -> Result<f32> {
    if prob_value.is_tensor() {
        if let Ok(prob) = probability_from_tensor(prob_value) {
            return Ok(prob);
        }
    }

    if matches!(prob_value.dtype(), ValueType::Sequence(_)) {
        if let Ok(prob) = probability_from_sequence(prob_value) {
            return Ok(prob);
        }
    }

    if let Some(prob) = probability_from_map_like(prob_value) {
        return Ok(prob);
    }

    Err(anyhow!(
        "Unsupported probability output type: {:?}",
        prob_value.dtype()
    ))
}

fn probability_from_tensor(prob_value: &Value) -> Result<f32> {
    if let Ok((_, probs)) = prob_value.try_extract_tensor::<f32>() {
        return pick_probability_from_slice(probs, |v| v)
            .context("Probability tensor was empty")
            .map(|p| p.clamp(0.0, 1.0));
    }
    if let Ok((_, probs)) = prob_value.try_extract_tensor::<f64>() {
        return pick_probability_from_slice(probs, |v| v as f32)
            .context("Probability tensor was empty")
            .map(|p| p.clamp(0.0, 1.0));
    }
    if let Ok((_, probs)) = prob_value.try_extract_tensor::<i64>() {
        return pick_probability_from_slice(probs, |v| v as f32)
            .context("Probability tensor was empty")
            .map(|p| p.clamp(0.0, 1.0));
    }
    Err(anyhow!(
        "Unsupported tensor element type for probability output"
    ))
}

fn probability_from_sequence(prob_value: &Value) -> Result<f32> {
    let allocator = Allocator::default();
    let values = prob_value.try_extract_sequence::<DynValueTypeMarker>(&allocator)?;
    let first = values
        .into_iter()
        .next()
        .context("Probability sequence was empty")?;
    probability_from_value(&first)
}

fn probability_from_map_like(value: &Value) -> Option<f32> {
    if let Ok(map) = value.try_extract_map::<i64, f32>() {
        if let Some(prob) = map
            .get(&1)
            .copied()
            .or_else(|| map.get(&0).map(|p| 1.0 - p))
        {
            return Some(prob);
        }
    }
    if let Ok(map) = value.try_extract_map::<String, f32>() {
        for key in ["1", "malicious"] {
            if let Some(prob) = map.get(key) {
                return Some(*prob);
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

fn pick_probability_from_slice<T: Copy>(data: &[T], convert: impl Fn(T) -> f32) -> Option<f32> {
    if data.len() >= 2 {
        Some(convert(data[1]))
    } else {
        data.first().copied().map(convert)
    }
}

fn safe_mean(values: &[f32]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    }
}

fn safe_std(values: &[f32]) -> f32 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = safe_mean(values);
    let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f32>() / values.len() as f32;
    variance.sqrt()
}

fn safe_variance(values: &[f32]) -> f32 {
    if values.len() < 2 {
        0.0
    } else {
        safe_std(values).powi(2)
    }
}

fn safe_max(values: &[f32]) -> f32 {
    values.iter().cloned().fold(0.0, f32::max)
}

fn entropy_anomaly(entropies: &[f32]) -> f32 {
    if entropies.is_empty() {
        return 0.0;
    }
    let mean = safe_mean(entropies);
    let std = safe_std(entropies);
    (std / (mean + 1e-3)).min(5.0)
}

fn has_nx_stack(elf: &goblin::elf::Elf) -> bool {
    elf.program_headers.iter().any(|ph| {
        ph.p_type == goblin::elf::program_header::PT_GNU_STACK
            && (ph.p_flags & goblin::elf::program_header::PF_X == 0)
    })
}

fn has_relro(elf: &goblin::elf::Elf) -> bool {
    elf.program_headers
        .iter()
        .any(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_RELRO)
}

fn has_stack_canary(elf: &goblin::elf::Elf) -> bool {
    elf.dynsyms.iter().any(|s| {
        if let Some(name) = elf.dynstrtab.get_at(s.st_name) {
            name.contains("__stack_chk_fail")
        } else {
            false
        }
    })
}

fn is_suspicious_entry(elf: &goblin::elf::Elf) -> bool {
    let ep = elf.entry;
    let text = elf.section_headers.iter().find(|sh| {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
            name == ".text"
        } else {
            false
        }
    });

    if let Some(sh) = text {
        !(sh.sh_addr <= ep && ep < sh.sh_addr + sh.sh_size)
    } else {
        ep < 0x1000
    }
}

fn overlapping_sections(elf: &goblin::elf::Elf) -> usize {
    let mut sections = elf.section_headers.clone();
    sections.sort_by_key(|s| s.sh_addr);
    let mut count = 0;
    for pair in sections.windows(2) {
        if let [first, second] = pair {
            if first.sh_size > 0 && first.sh_addr + first.sh_size > second.sh_addr {
                count += 1;
            }
        }
    }
    count
}

fn section_bytes<'a>(bytes: &'a [u8], sh: &goblin::elf::SectionHeader) -> Option<&'a [u8]> {
    let start = sh.sh_offset as usize;
    let end = start.checked_add(sh.sh_size as usize)?;
    bytes.get(start..end)
}

fn detect_control_flow_anomaly(insns: &[Insn]) -> bool {
    if insns.is_empty() {
        return false;
    }
    let svc_ratio = insns
        .iter()
        .filter(|i| i.mnemonic().unwrap_or_default() == "svc")
        .count() as f32
        / insns.len() as f32;
    let ret_ratio = insns
        .iter()
        .filter(|i| i.mnemonic().unwrap_or_default() == "ret")
        .count() as f32
        / insns.len() as f32;
    svc_ratio > 0.05 || ret_ratio > 0.3
}

fn safe_mean_f64(values: &[usize]) -> f32 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<usize>() as f32 / values.len() as f32
    }
}

fn model_agreement(probs: &[f32]) -> f32 {
    if probs.is_empty() {
        return 0.0;
    }
    let mean = probs.iter().sum::<f32>() / probs.len() as f32;
    let variance = probs.iter().map(|p| (p - mean).powi(2)).sum::<f32>() / probs.len() as f32;
    let std = variance.sqrt();
    (1.0 - (std / 0.5).min(1.0)).max(0.0)
}

fn extract_ascii_strings(blob: &[u8], min_length: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for b in blob {
        if (32..=126).contains(b) {
            current.push(*b);
        } else if current.len() >= min_length {
            if let Ok(s) = String::from_utf8(current.clone()) {
                result.push(s);
            }
            current.clear();
        } else {
            current.clear();
        }
    }

    if current.len() >= min_length {
        if let Ok(s) = String::from_utf8(current.clone()) {
            result.push(s);
        }
    }

    result
}
