//! WinnCoreAV Daemon - ARM64-native endpoint detection and response
//!
//! Detection pipeline:
//!   ProcessMonitor (procfs) → BehavioralPipeline (rules) → AlertLogger (JSON)
//!
//! Design decisions:
//!   - procfs polling over eBPF for ARM64 portability (Graviton, M-series, Snapdragon)
//!   - Tokio async runtime for concurrent event processing
//!   - JSON-lines alert format for SIEM integration
//!
//! Performance targets: <5% CPU, <50MB RAM, <500ms detection latency

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use sd_notify::NotifyState;
use tokio::io::{stderr, stdout, AsyncWriteExt};
use tracing::{info, warn};

mod aslr_verify;
mod behavioral_pipeline;
mod circuit_breaker;
mod config;
mod error;
mod hardening;
mod health;
mod heuristics;
mod integrity;
mod landlock;
mod memory_audit;
mod metrics;
mod namespaces;
#[cfg(feature = "behavior_monitor")]
mod ebpf_monitor;
mod process_monitor;
mod response;
mod security;
mod shutdown;
mod siem;
mod watchdog;

use behavioral_pipeline::{log_alert, start_behavioral_pipeline, BehavioralConfig};
use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use error::Subsystem;
use hardening::{init_all_hardening, start_background_hardening, HardeningConfig};
use health::HealthChecker;
use metrics::register_metrics;
use process_monitor::{spawn_process_monitor, ProcessMonitorConfig};
use security::start_security_tasks;
use shutdown::install_signal_handlers;
use siem::SiemOutput;

#[tokio::main]
async fn main() -> Result<()> {
    // Load daemon configuration
    let daemon_cfg = crate::config::DaemonConfig::load_or_default();

    let mut harden_cfg = if std::env::var("WINNCORE_DEBUG").is_ok() {
        HardeningConfig::development()
    } else {
        HardeningConfig::default()
    };

    // Allow log level override via env.
    if let Ok(level) = std::env::var("WINNCORE_LOG_LEVEL") {
        harden_cfg.log_config.level = level;
    }

    let _hardening =
        init_all_hardening(&harden_cfg).map_err(|e| anyhow::anyhow!("Hardening failed: {}", e))?;

    let _auditor = start_background_hardening(&harden_cfg).await;

    // Initialize health checker and circuits for subsystems.
    let health = Arc::new(HealthChecker::new());
    let cb_cfg = CircuitBreakerConfig::default();
    let ml_cb = Arc::new(CircuitBreaker::new("ml_detection", cb_cfg.clone()));
    let sig_cb = Arc::new(CircuitBreaker::new("signature_matching", cb_cfg.clone()));
    let ebpf_cb = Arc::new(CircuitBreaker::new("ebpf_monitoring", cb_cfg.clone()));
    let quarantine_cb = Arc::new(CircuitBreaker::new("quarantine", cb_cfg));

    health
        .register_subsystem(Subsystem::MlDetection, ml_cb.clone())
        .await;
    health
        .register_subsystem(Subsystem::SignatureMatching, sig_cb.clone())
        .await;
    health
        .register_subsystem(Subsystem::EbpfMonitoring, ebpf_cb.clone())
        .await;
    health
        .register_subsystem(Subsystem::Quarantine, quarantine_cb.clone())
        .await;

    // Metrics registration (ignore errors for now).
    let _ = register_metrics();
    if daemon_cfg.metrics.enabled {
        let addr: SocketAddr = ([0, 0, 0, 0], daemon_cfg.metrics.port).into();
        tokio::spawn(async move {
            if let Err(e) = crate::metrics::start_metrics_server(addr).await {
                warn!(error = %e, "Metrics server exited");
            }
        });
    }

    let shutdown = shutdown::ShutdownCoordinator::new(std::time::Duration::from_secs(30));
    shutdown
        .register_handler("flush_logs", 100, || async {
            if let Err(e) = stdout().flush().await {
                warn!(error = %e, "Failed to flush stdout during shutdown");
            }
            if let Err(e) = stderr().flush().await {
                warn!(error = %e, "Failed to flush stderr during shutdown");
            }
        })
        .await;
    install_signal_handlers(shutdown.clone()).await;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "WinnCore AV Daemon starting (hardened)"
    );
    // Supplemental security tasks (container context + rootkit sweeps).
    let _responder = start_security_tasks().await;

    // Start behavioral pipeline (rules + alerts).
    let alert_log_path = std::env::var("WINNCORE_ALERT_LOG")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| daemon_cfg.behavioral.alert_log_path.clone());
    let external_rules_dir = std::env::var("WINNCORE_RULES_DIR")
        .ok()
        .map(PathBuf::from)
        .or_else(|| daemon_cfg.behavioral.external_rules_dir.clone());
    let behavioral_cfg = BehavioralConfig {
        response: daemon_cfg.response.clone(),
        external_rules_dir,
        alert_log_path,
    };
    let behavioral_runtime = start_behavioral_pipeline(behavioral_cfg).await?;
    let mut alert_rx = behavioral_runtime.alert_rx;
    let siem_output = SiemOutput::new(daemon_cfg.siem.clone());

    #[cfg(feature = "behavior_monitor")]
    let mut ebpf_active = false;
    #[cfg(not(feature = "behavior_monitor"))]
    let ebpf_active = false;

    #[cfg(feature = "behavior_monitor")]
    let mut _ebpf_handle: Option<ebpf_monitor::EbpfMonitorHandle> = None;

    #[cfg(feature = "behavior_monitor")]
    {
        let enabled = std::env::var("WINNCORE_ENABLE_EBPF")
            .ok()
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(true);

        if enabled && ebpf_monitor::ebpf_available() && ebpf_monitor::has_ebpf_permissions() {
            match ebpf_monitor::EbpfMonitor::new(
                ebpf_monitor::EbpfMonitorConfig::default(),
                behavioral_runtime.event_tx.clone(),
            )
            .start()
            .await
            {
                Ok(handle) => {
                    info!("eBPF monitor started; disabling procfs polling monitor");
                    ebpf_active = true;
                    _ebpf_handle = Some(handle);
                }
                Err(e) => {
                    warn!(error = %e, "eBPF monitor failed to start; falling back to procfs polling");
                }
            }
        } else {
            warn!("eBPF unavailable/disabled; using procfs polling only");
        }
    }

    if !ebpf_active {
        // Procfs monitor to generate execution events.
        info!("Starting process monitor...");
        let process_monitor_cfg = ProcessMonitorConfig::default();
        let _process_monitor_handle =
            spawn_process_monitor(process_monitor_cfg, behavioral_runtime.event_tx.clone());
        info!("Process monitor spawned");
    }

    // Periodic eBPF program integrity/rootkit monitor (best effort).
    let ebpf_detect_tx = behavioral_runtime.event_tx.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(600));
        let baseline = av_ebpf_detect::BpfBaseline::create_from_current();
        loop {
            ticker.tick().await;
            let programs = av_ebpf_detect::enumerate_bpf_programs();
            if programs.is_empty() {
                continue;
            }

            let analysis = av_ebpf_detect::analyze_bpf_programs(&programs, &baseline);
            if !analysis.possible_rootkit && analysis.risk_score < 100 {
                continue;
            }

            let severity = if analysis.possible_rootkit {
                "critical"
            } else if analysis.risk_score >= 200 {
                "high"
            } else {
                "medium"
            };

            let description = format!(
                "eBPF program anomaly: risk_score={} total={} unknown={} high_risk={} suspicious_combos={} possible_rootkit={}",
                analysis.risk_score,
                analysis.total_programs,
                analysis.unknown_programs.len(),
                analysis.high_risk_programs.len(),
                analysis.suspicious_combinations.len(),
                analysis.possible_rootkit
            );

            let _ = ebpf_detect_tx
                .send(behavioral_pipeline::BehavioralEvent::EbpfProgramThreat {
                    severity: severity.to_string(),
                    description,
                })
                .await;
        }
    });

    tokio::spawn(async move {
        info!("Alert receiver started");
        while let Some(alert) = alert_rx.recv().await {
            log_alert(&alert);
            if let Err(e) = siem_output.send_behavioral_alert(&alert) {
                warn!(error = %e, "SIEM output failed");
            }
        }
    });

    if let Err(e) = sd_notify::notify(true, &[NotifyState::Ready]) {
        warn!(error = %e, "Failed to send systemd READY=1");
    } else {
        info!("Systemd notified: READY=1");
    }

    // Periodic health reporting.
    let health_clone = health.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            ticker.tick().await;
            let report = health_clone.report().await;
            info!(
                status = ?report.status,
                uptime = report.uptime_seconds,
                degraded = ?report.degraded_subsystems,
                "Health report"
            );
        }
    });

    let mut shutdown_rx = shutdown.subscribe();
    let _ = shutdown_rx.recv().await;
    info!("Shutdown signal received");

    shutdown.wait_for_completion().await;
    info!("Daemon shutdown complete");
    Ok(())
}
