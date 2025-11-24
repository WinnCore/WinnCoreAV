#![allow(dead_code)]
#![allow(unused_variables)]

use crate::arm64_security;
use crate::config::ScannerConfig;
use crate::heuristics::{self};
use crate::logging::{emit_detection_log, iso_timestamp, sha256_file};
use crate::threat_intel::{load_ioc_cache, scan_with_yara};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone)]
pub struct ScanContext {
    pub target: PathBuf,
}

impl ScanContext {
    pub fn new(target: PathBuf) -> Self {
        Self { target }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    pub rule: String,
    pub namespace: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntropyReport {
    pub mean_entropy: f32,
    pub suspicious_regions: Vec<(u64, u64)>,
}

pub async fn scan_path(
    config: &ScannerConfig,
    ctx: &ScanContext,
) -> anyhow::Result<crate::ScanOutcome> {
    let data = read_head(&ctx.target).await?;

    // Allowlist by path
    if config.allowlist_paths.iter().any(|p| p == &ctx.target) {
        return Ok(crate::ScanOutcome {
            path: ctx.target.display().to_string(),
            signatures: Vec::new(),
            heuristic_score: heuristics::Score(0.0),
            entropy: EntropyReport::default(),
            recommended_action: crate::RecommendedAction::Allow,
            mitre_tags: Vec::new(),
            ioc_hits: Vec::new(),
            yara_matches: Vec::new(),
            arm64_protection: None,
        });
    }

    let sha = sha256_file(&ctx.target).ok();

    // Allowlist by hash
    if let (Some(ref s), true) = (&sha, !config.allowlist_hashes.is_empty()) {
        if config
            .allowlist_hashes
            .iter()
            .any(|h| h.eq_ignore_ascii_case(s))
        {
            return Ok(crate::ScanOutcome {
                path: ctx.target.display().to_string(),
                signatures: Vec::new(),
                heuristic_score: heuristics::Score(0.0),
                entropy: EntropyReport::default(),
                recommended_action: crate::RecommendedAction::Allow,
                mitre_tags: Vec::new(),
                ioc_hits: Vec::new(),
                yara_matches: Vec::new(),
                arm64_protection: None,
            });
        }
    }

    // Threat intel: YARA
    let yara_verdict = scan_with_yara(&ctx.target, config).unwrap_or_default();
    let signatures = yara_verdict
        .matched_rules
        .iter()
        .map(|r| crate::engine::SignatureMatch {
            rule: r.clone(),
            namespace: "yara".to_string(),
            metadata: serde_json::json!({ "source": "yara" }),
        })
        .collect::<Vec<_>>();

    let protections = arm64_security::analyze_elf_protections(&data);

    let heuristic_score = heuristics::score(&ctx.target, &data, config);

    let entropy = if config.enable_entropy_analysis {
        entropy(&data)
    } else {
        EntropyReport::default()
    };

    let mut recommended_action = heuristics::recommend(&signatures, heuristic_score, config);

    // Detect EICAR test string
    let mut mitre_tags = Vec::new();
    let mut notes = Vec::new();
    if config.eicar_detection && data.windows(EICAR_TEST.len()).any(|w| w == EICAR_TEST) {
        mitre_tags.push("T1204".to_string()); // User Execution (test mapping)
        recommended_action = crate::RecommendedAction::Quarantine;
    }

    // IoC cache
    let mut ioc_hits = Vec::new();
    if let Some(cache) = load_ioc_cache(config) {
        if let Some(ref s) = sha {
            if cache.sha256.iter().any(|h| h.eq_ignore_ascii_case(s)) {
                ioc_hits.push(s.clone());
                recommended_action = crate::RecommendedAction::Quarantine;
            }
        }
    }

    if protections.is_aarch64_elf && (!protections.pac_marked || !protections.bti_marked) {
        notes.push("arm64_binary_missing_pac_or_bti".to_string());
        mitre_tags.push("T1562".to_string()); // Defense Evasion: weaken protections
        if recommended_action == crate::RecommendedAction::Allow {
            recommended_action = crate::RecommendedAction::Monitor;
        }
    }

    if config.log_json {
        let protection_notes = protections.parsing_notes.clone();
        let protection_log =
            protections
                .is_aarch64_elf
                .then(|| crate::logging::Arm64ProtectionLog {
                    is_aarch64_elf: protections.is_aarch64_elf,
                    pac_marked: protections.pac_marked,
                    bti_marked: protections.bti_marked,
                    has_gnu_property_note: protections.has_gnu_property_note,
                    parsing_notes: &protection_notes,
                });
        if !signatures.is_empty() {
            notes.push("signature_match".to_string());
        }
        let log = crate::logging::DetectionLog {
            ts: iso_timestamp(),
            host: crate::logging::host_id(),
            path: &ctx.target.display().to_string(),
            sha256: sha.clone(),
            model_version: Some("gbm_v3_hardened"),
            model_checksum: None,
            score: heuristic_score.0,
            action: match recommended_action {
                crate::RecommendedAction::Allow => "allow",
                crate::RecommendedAction::Monitor => "monitor",
                crate::RecommendedAction::Quarantine => "quarantine",
            },
            mitre: &mitre_tags,
            notes: &notes,
            yara_matches: &yara_verdict.matched_rules,
            ioc_hits: &ioc_hits,
            adversarial_hint: false,
            arm64_protection: protection_log,
        };
        emit_detection_log(&log, true);
    }

    Ok(crate::ScanOutcome {
        path: ctx.target.display().to_string(),
        signatures,
        heuristic_score,
        entropy,
        recommended_action,
        mitre_tags,
        ioc_hits,
        yara_matches: yara_verdict.matched_rules,
        arm64_protection: protections.is_aarch64_elf.then_some(protections),
    })
}

async fn read_head(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let file = File::open(path).await?;
    let mut buffer = Vec::with_capacity(256 * 1024);
    file.take(256 * 1024).read_to_end(&mut buffer).await?;
    Ok(buffer)
}

fn entropy(_data: &[u8]) -> EntropyReport {
    EntropyReport::default()
}

const EICAR_TEST: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
