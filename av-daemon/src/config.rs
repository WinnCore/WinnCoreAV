//! Daemon configuration - loads from TOML file

use serde::Deserialize;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::siem::SiemConfig;
use av_threatintel::FeedConfig;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DaemonConfig {
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub response: ResponseConfig,
    #[serde(default)]
    pub behavioral: BehavioralFileConfig,
    #[serde(default)]
    pub threat_intel: ThreatIntelConfig,
    #[serde(default)]
    pub siem: SiemConfig,
}

impl DaemonConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut config: DaemonConfig = toml::from_str(&content)?;
        config.siem.resolve_env();
        info!(path = %path.display(), "Loaded daemon configuration");
        Ok(config)
    }

    pub fn load_or_default() -> Self {
        let paths = [
            PathBuf::from("/etc/winncore/daemon.toml"),
            PathBuf::from("config/daemon.toml"),
            PathBuf::from("daemon.toml"),
        ];

        for path in &paths {
            if path.exists() {
                match Self::load(path) {
                    Ok(cfg) => {
                        info!(
                            auto_quarantine = cfg.response.auto_quarantine,
                            auto_kill = cfg.response.auto_kill_critical,
                            "Config loaded"
                        );
                        return cfg;
                    }
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Config parse failed");
                    }
                }
            }
        }

        warn!("No config file found, using defaults with auto_quarantine=true");
        Self::default()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

fn default_true() -> bool {
    true
}
fn default_metrics_port() -> u16 {
    9090
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResponseConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_kill_critical: bool,
    #[serde(default = "default_true")]
    pub auto_quarantine: bool,
    #[allow(dead_code)]
    #[serde(default = "default_threshold")]
    pub quarantine_threshold: f32,
    #[serde(default = "default_quarantine_dir")]
    pub quarantine_dir: PathBuf,
}

fn default_threshold() -> f32 {
    0.85
}
fn default_quarantine_dir() -> PathBuf {
    PathBuf::from("/var/lib/winncore/quarantine")
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            auto_kill_critical: false,
            auto_quarantine: true, // KEY FIX: was false
            quarantine_threshold: 0.85,
            quarantine_dir: PathBuf::from("/var/lib/winncore/quarantine"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BehavioralFileConfig {
    pub external_rules_dir: Option<PathBuf>,
    #[serde(default = "default_alert_log")]
    pub alert_log_path: PathBuf,
}

fn default_alert_log() -> PathBuf {
    PathBuf::from("/var/log/winncore/alerts.json")
}

impl Default for BehavioralFileConfig {
    fn default() -> Self {
        Self {
            external_rules_dir: Some(PathBuf::from("/etc/winncore/rules")),
            alert_log_path: PathBuf::from("/var/log/winncore/alerts.json"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ThreatIntelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_threatintel_db_path")]
    pub db_path: PathBuf,
    #[serde(default)]
    pub min_confidence: u8,
    #[serde(default = "default_true")]
    pub subdomain_matching: bool,
    #[serde(default)]
    pub feeds: Vec<FeedConfig>,
}

fn default_threatintel_db_path() -> PathBuf {
    PathBuf::from("/var/lib/winncore/threatintel")
}

impl Default for ThreatIntelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            db_path: default_threatintel_db_path(),
            min_confidence: 0,
            subdomain_matching: true,
            feeds: Vec::new(),
        }
    }
}
