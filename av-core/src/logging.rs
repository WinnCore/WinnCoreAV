use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Serialize)]
pub struct DetectionLog<'a> {
    pub ts: String,
    pub host: String,
    pub path: &'a str,
    pub sha256: Option<String>,
    pub model_version: Option<&'a str>,
    pub model_checksum: Option<&'a str>,
    pub score: f32,
    pub action: &'a str,
    pub mitre: &'a [String],
    pub notes: &'a [String],
    pub yara_matches: &'a [String],
    pub ioc_hits: &'a [String],
    pub adversarial_hint: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arm64_protection: Option<Arm64ProtectionLog<'a>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Arm64ProtectionLog<'a> {
    pub is_aarch64_elf: bool,
    pub pac_marked: bool,
    pub bti_marked: bool,
    pub has_gnu_property_note: bool,
    pub parsing_notes: &'a [String],
}

static NON_ELF_SKIP_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn emit_detection_log(log: &DetectionLog, json: bool) {
    if json {
        if let Ok(serialized) = serde_json::to_string(log) {
            println!("{serialized}");
        }
    } else {
        println!(
            "[{}] path={} sha256={:?} score={:.3} action={} mitre={:?} notes={:?}",
            log.ts, log.path, log.sha256, log.score, log.action, log.mitre, log.notes
        );
    }
}

pub fn sha256_file(path: &Path) -> IoResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn iso_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Returns true if a non-ELF skip log should be emitted based on verbosity and counters.
pub fn log_non_elf_skip_should_emit(verbose: bool) -> bool {
    if verbose {
        return true;
    }
    let count = NON_ELF_SKIP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    count == 1 || count.is_multiple_of(500)
}

pub fn non_elf_skip_count() -> usize {
    NON_ELF_SKIP_COUNT.load(Ordering::Relaxed)
}

pub fn host_id() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.is_empty() {
            return h;
        }
    }
    if let Ok(contents) = std::fs::read_to_string("/etc/hostname") {
        let trimmed = contents.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    "unknown".to_string()
}
