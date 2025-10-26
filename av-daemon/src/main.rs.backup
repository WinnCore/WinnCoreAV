//! User-space real-time monitoring daemon.
//!
//! Runs unprivileged by default. Capabilities, if needed, are attached via
//! systemd unit overrides and documented in the security guide.

use std::time::Duration;

use anyhow::Context;
use tokio::signal;
use tokio::sync::Notify;
use tracing::{error, info};

use av_core::{config::ScannerConfig, monitoring::MonitoringReport, Scanner};

mod security;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logging();

    let config = load_config().context("failed to load daemon config")?;
    let scanner = Scanner::new(config.clone()).context("failed to init scanner")?;

    // Apply sandboxing as early as possible in the process lifetime. The
    // actual policies are shipped separately; here we merely invoke the
    // helper so the scaffold documents the flow.
    security::install_seccomp_filter();
    security::load_apparmor_profile();

    let shutdown = Notify::new();
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        if let Err(err) = watch_shutdown(shutdown_signal).await {
            error!(error = %err, "shutdown watcher failed");
        }
    });

    run_monitor_loop(scanner, &config, &shutdown).await?;
    info!("daemon exiting cleanly");
    Ok(())
}

fn init_logging() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
}

fn load_config() -> anyhow::Result<ScannerConfig> {
    let mut settings = config::Config::builder();
    settings = settings.set_default("heuristic_threshold", 0.8)?;
    let cfg: ScannerConfig = settings.build()?.try_deserialize()?;
    Ok(cfg)
}

async fn run_monitor_loop(
    scanner: Scanner,
    _config: &ScannerConfig,
    shutdown: &Notify,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                break;
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                let report = MonitoringReport { events: vec![], degraded_mode: true };
                info!(?report, "monitoring report placeholder");
            }
        }
    }
    Ok(())
}

async fn watch_shutdown(shutdown: Notify) -> anyhow::Result<()> {
    signal::ctrl_c().await?;
    shutdown.notify_waiters();
    Ok(())
}
