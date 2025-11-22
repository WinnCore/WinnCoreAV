use crate::config::ScannerConfig;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::RwLock;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ThreatIntelError {
    #[error("YARA unavailable: {0}")]
    YaraUnavailable(String),
    #[error("YARA compile failed: {0}")]
    YaraCompile(String),
    #[error("YARA scan failed: {0}")]
    YaraScan(String),
    #[error("IoC cache parse failed: {0}")]
    IocParse(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct YaraVerdict {
    pub matched_rules: Vec<String>,
    pub severity_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocCache {
    pub sha256: Vec<String>,
}

struct CachedRules {
    dir: std::path::PathBuf,
    mtime: SystemTime,
    rules: std::sync::Arc<yara::Rules>,
}

static RULE_CACHE: Lazy<RwLock<Option<CachedRules>>> = Lazy::new(|| RwLock::new(None));

fn dir_mtime(dir: &Path) -> Option<SystemTime> {
    let mut newest: Option<SystemTime> = None;
    for entry in std::fs::read_dir(dir).ok()? {
        let entry = entry.ok()?;
        if entry.path().extension().and_then(|e| e.to_str()) == Some("yar") {
            if let Ok(md) = entry.metadata() {
                if let Ok(mt) = md.modified() {
                    newest = Some(newest.map_or(mt, |n| n.max(mt)));
                }
            }
        }
    }
    newest
}

fn compile_rules(dir: &Path) -> Result<std::sync::Arc<yara::Rules>, ThreatIntelError> {
    let mut blob = String::new();
    for entry in std::fs::read_dir(dir).map_err(|e| ThreatIntelError::YaraUnavailable(e.to_string()))? {
        let entry = entry.map_err(|e| ThreatIntelError::YaraUnavailable(e.to_string()))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yar") {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| ThreatIntelError::YaraUnavailable(e.to_string()))?;
            blob.push_str(&content);
            blob.push('\n');
        }
    }

    let compiler = yara::Compiler::new().map_err(|e| ThreatIntelError::YaraUnavailable(e.to_string()))?;
    let compiler = if !blob.is_empty() {
        compiler
            .add_rules_str(&blob)
            .map_err(|e| ThreatIntelError::YaraCompile(e.to_string()))?
    } else {
        compiler
    };

    let rules = compiler
        .compile_rules()
        .map_err(|e| ThreatIntelError::YaraCompile(e.to_string()))?;

    Ok(std::sync::Arc::new(rules))
}

pub fn scan_with_yara(path: &Path, config: &ScannerConfig) -> Result<YaraVerdict, ThreatIntelError> {
    let rules_dir = match &config.threat_intel.yara_rules_dir {
        Some(p) => p,
        None => return Ok(YaraVerdict::default()),
    };
    if !rules_dir.exists() {
        return Ok(YaraVerdict::default());
    }

    let cache_mtime = dir_mtime(rules_dir);
    let arc_rules = {
        let mut guard = RULE_CACHE.write().unwrap();
        let needs_rebuild = guard
            .as_ref()
            .map(|c| c.dir != *rules_dir || cache_mtime.map(|m| m > c.mtime).unwrap_or(false))
            .unwrap_or(true);
        if needs_rebuild {
            let rules = compile_rules(rules_dir)?;
            let cached = CachedRules {
                dir: rules_dir.clone(),
                mtime: cache_mtime.unwrap_or(SystemTime::now()),
                rules,
            };
            *guard = Some(cached);
        }
        guard.as_ref().unwrap().rules.clone()
    };

    let results = arc_rules
        .scan_file(path, 0)
        .map_err(|e| ThreatIntelError::YaraScan(e.to_string()))?;

    let mut matched = Vec::new();
    for m in results {
        matched.push(m.identifier.to_string());
    }

    let severity_hint = if matched.iter().any(|r| r.contains("critical") || r.contains("ransom")) {
        Some("high".to_string())
    } else {
        None
    };

    Ok(YaraVerdict {
        matched_rules: matched,
        severity_hint,
    })
}

pub fn load_ioc_cache(config: &ScannerConfig) -> Option<IocCache> {
    let path = config.threat_intel.ioc_cache_path.as_ref()?;
    if !path.exists() {
        return None;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<IocCache>(&s).ok())
}
