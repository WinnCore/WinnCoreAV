use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonConfig {
    pub daemon: DaemonSection,
    pub monitoring: MonitoringSection,
    pub response: ResponseSection,
    pub thresholds: ThresholdsSection,
    pub limits: LimitsSection,
    pub logging: LoggingSection,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DaemonSection {
    pub pid_file: String,
    pub log_file: String,
    pub working_dir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MonitoringSection {
    pub watch_paths: Vec<String>,
    pub ignore_paths: Vec<String>,
    pub scan_on_create: bool,
    pub scan_on_modify: bool,
    pub scan_on_execute: bool,
    pub debounce_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseSection {
    pub enabled: bool,
    pub auto_kill: bool,
    pub auto_quarantine: bool,
    pub auto_block_network: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThresholdsSection {
    pub kill_threshold: f32,
    pub quarantine_threshold: f32,
    pub alert_threshold: f32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsSection {
    pub max_actions_per_minute: u32,
    pub max_scan_queue: usize,
    pub scan_timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingSection {
    pub level: String,
}

impl DaemonConfig {
    pub fn load() -> Result<Self> {
        if let Ok(custom) = std::env::var("WINNCORE_DAEMON_CONFIG") {
            if Path::new(&custom).exists() {
                return Self::from_path(custom);
            }
        }

        let system_path = Path::new("/etc/winncore/daemon.toml");
        if system_path.exists() {
            return Self::from_path(system_path);
        }

        Ok(Self::default())
    }

    fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Unable to read config {}", path.as_ref().display()))?;
        let config: DaemonConfig = toml::from_str(&contents)
            .with_context(|| format!("Unable to parse {}", path.as_ref().display()))?;
        Ok(config)
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            daemon: DaemonSection {
                pid_file: "/tmp/winncore-av.pid".into(),
                log_file: "/tmp/winncore-av.log".into(),
                working_dir: "/tmp/winncore".into(),
            },
            monitoring: MonitoringSection {
                watch_paths: vec!["/tmp".into()],
                ignore_paths: vec!["/proc".into(), "/sys".into(), "/dev".into()],
                scan_on_create: true,
                scan_on_modify: true,
                scan_on_execute: true,
                debounce_ms: 100,
            },
            response: ResponseSection {
                enabled: true,
                auto_kill: false,
                auto_quarantine: true,
                auto_block_network: false,
            },
            thresholds: ThresholdsSection {
                kill_threshold: 0.95,
                quarantine_threshold: 0.85,
                alert_threshold: 0.70,
            },
            limits: LimitsSection {
                max_actions_per_minute: 10,
                max_scan_queue: 1000,
                scan_timeout_seconds: 30,
            },
            logging: LoggingSection {
                level: "info".into(),
            },
        }
    }
}
