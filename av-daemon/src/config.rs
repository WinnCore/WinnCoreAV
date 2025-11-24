use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tracing::{error, info, warn};

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
    #[allow(dead_code)]
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

/// Async configuration manager with SIGHUP reload support.
pub struct ConfigManager {
    config_path: std::path::PathBuf,
    current: tokio::sync::RwLock<DaemonConfig>,
    change_tx: watch::Sender<DaemonConfig>,
    _change_rx: watch::Receiver<DaemonConfig>,
}

impl ConfigManager {
    pub fn load_default() -> Result<Self> {
        let path = if let Ok(custom) = std::env::var("WINNCORE_DAEMON_CONFIG") {
            std::path::PathBuf::from(custom)
        } else {
            std::path::PathBuf::from("/etc/winncore/daemon.toml")
        };

        let initial = if path.exists() {
            DaemonConfig::from_path(&path)?
        } else {
            DaemonConfig::default()
        };

        let (tx, rx) = watch::channel(initial.clone());
        Ok(Self {
            config_path: path,
            current: tokio::sync::RwLock::new(initial),
            change_tx: tx,
            _change_rx: rx,
        })
    }

    pub async fn get(&self) -> DaemonConfig {
        self.current.read().await.clone()
    }

    pub async fn reload(&self) -> anyhow::Result<()> {
        info!(path = %self.config_path.display(), "Reloading daemon configuration");
        let config = if self.config_path.exists() {
            DaemonConfig::from_path(&self.config_path)?
        } else {
            DaemonConfig::default()
        };
        self.validate(&config)?;
        *self.current.write().await = config.clone();
        let _ = self.change_tx.send(config);
        Ok(())
    }

    fn validate(&self, cfg: &DaemonConfig) -> anyhow::Result<()> {
        if cfg.monitoring.debounce_ms == 0 {
            anyhow::bail!("monitoring.debounce_ms must be > 0");
        }
        if cfg.thresholds.kill_threshold < 0.0 || cfg.thresholds.kill_threshold > 1.0 {
            anyhow::bail!("kill_threshold must be between 0 and 1");
        }
        Ok(())
    }

    pub fn spawn_sighup_handler(self: std::sync::Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut sighup = match signal(SignalKind::hangup()) {
                Ok(s) => s,
                Err(e) => {
                    error!("Failed to register SIGHUP handler: {}", e);
                    return;
                }
            };
            loop {
                sighup.recv().await;
                info!("Received SIGHUP - reloading daemon config");
                if let Err(e) = self.reload().await {
                    warn!("Config reload failed: {}", e);
                }
            }
        })
    }
}
