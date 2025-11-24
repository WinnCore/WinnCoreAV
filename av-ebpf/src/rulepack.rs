//! Versioned rulepack management with checksum verification (SIGHUP reload only).

use crate::rules::BehavioralRule;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulepackMeta {
    pub version: String,
    pub name: String,
    pub description: String,
    pub author: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub checksum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rulepack {
    pub meta: RulepackMeta,
    pub rules: Vec<BehavioralRule>,
}

impl Rulepack {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let pack: Rulepack = serde_json::from_str(&content)?;
        pack.verify_checksum()?;
        Ok(pack)
    }

    pub fn verify_checksum(&self) -> anyhow::Result<()> {
        use sha2::{Digest, Sha256};
        let rules_json = serde_json::to_string(&self.rules)?;
        let computed = format!("{:x}", Sha256::digest(rules_json.as_bytes()));
        if computed != self.meta.checksum {
            anyhow::bail!(
                "Rulepack checksum mismatch: expected {}, got {}",
                self.meta.checksum,
                computed
            );
        }
        Ok(())
    }
}

/// Rule manager supporting SIGHUP-triggered reloads (no file watcher to avoid blocking in async).
pub struct RuleManager {
    rules_dir: std::path::PathBuf,
    current_rules: tokio::sync::RwLock<Vec<BehavioralRule>>,
    reload_tx: watch::Sender<u64>,
    reload_rx: watch::Receiver<u64>,
    reload_count: AtomicU64,
}

impl RuleManager {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> Self {
        let (tx, rx) = watch::channel(0);
        Self {
            rules_dir: dir.into(),
            current_rules: tokio::sync::RwLock::new(Vec::new()),
            reload_tx: tx,
            reload_rx: rx,
            reload_count: AtomicU64::new(0),
        }
    }

    /// Load all rules; call on startup and SIGHUP.
    pub async fn load_all(&self) -> anyhow::Result<usize> {
        let mut combined = crate::rules::get_default_rules();
        if self.rules_dir.exists() {
            for entry in std::fs::read_dir(&self.rules_dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map(|e| e == "json").unwrap_or(false) {
                    match Rulepack::from_file(&path) {
                        Ok(pack) => {
                            info!(
                                name = %pack.meta.name,
                                version = %pack.meta.version,
                                rules = pack.rules.len(),
                                "Loaded rulepack"
                            );
                            combined.extend(pack.rules);
                        }
                        Err(e) => {
                            error!(path = %path.display(), error = %e, "Failed to load rulepack");
                        }
                    }
                }
            }
        }

        let count = combined.len();
        *self.current_rules.write().await = combined;
        let new_count = self.reload_count.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.reload_tx.send(new_count);
        info!(total_rules = count, reloads = new_count, "Rules loaded");
        Ok(count)
    }

    pub async fn get_rules(&self) -> Vec<BehavioralRule> {
        self.current_rules.read().await.clone()
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.reload_rx.clone()
    }
}
