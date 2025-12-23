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

mod alert;
mod api;
mod aslr_verify;
mod behavioral_pipeline;
mod circuit_breaker;
mod config;
#[cfg(feature = "behavior_monitor")]
mod ebpf_monitor;
mod error;
mod hardening;
mod health;
mod heuristics;
mod integrity;
mod landlock;
mod memory_audit;
mod metrics;
mod namespaces;
mod process_monitor;
mod response;
mod security;
mod shutdown;
mod siem;
mod watchdog;

use behavioral_pipeline::{
    log_alert, start_behavioral_pipeline, BehavioralAlert, BehavioralConfig,
};
use circuit_breaker::{CircuitBreaker, CircuitBreakerConfig};
use error::Subsystem;
use hardening::{init_all_hardening, start_background_hardening, HardeningConfig};
use health::HealthChecker;
use metrics::register_metrics;
use process_monitor::{spawn_process_monitor, ProcessMonitorConfig};
use security::start_security_tasks;
use shutdown::install_signal_handlers;

fn behavioral_alert_to_unified(alert: &BehavioralAlert) -> crate::alert::Alert {
    use crate::alert::{Alert, DetectionSource, ProcessContext, Severity};

    let severity = alert
        .severity
        .parse::<Severity>()
        .unwrap_or(Severity::Medium);

    let proc_name = alert
        .cmdline
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string();

    let proc_ctx = ProcessContext {
        pid: alert.pid,
        ppid: Some(alert.ppid),
        name: proc_name,
        exe_path: None,
        cmdline: Some(alert.cmdline.clone()),
        username: None,
        uid: None,
        cwd: None,
        start_time: None,
    };

    let mut out = Alert::new(
        &alert.rule_id,
        &alert.name,
        &alert.description,
        severity,
        DetectionSource::Behavioral,
    )
    .with_mitre(&alert.technique)
    .with_process(proc_ctx);

    // Prefer pipeline-provided tactic when available.
    if let Some(ref mut mitre) = out.mitre {
        if (mitre.tactic == "Unknown" || mitre.tactic.is_empty()) && !alert.tactic.trim().is_empty()
        {
            mitre.tactic = alert.tactic.trim().to_string();
        }
    }

    out.tags.push(format!("pipeline_source:{}", alert.source));
    if !alert.matched.is_empty() {
        out.custom_fields.insert(
            "matched".to_string(),
            serde_json::Value::Array(
                alert
                    .matched
                    .iter()
                    .cloned()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
    }
    out.raw_event = serde_json::to_string(alert).ok();

    out
}

async fn setup_siem(config: &crate::config::DaemonConfig) -> Arc<crate::siem::AlertRouter> {
    use crate::siem::{
        AlertFormatter, AlertRouter, AlertSender, BatchingWebhookSender, CefFormatter,
        FileAlertSender, JsonFormatter, LeefFormatter, RouteConfig, SyslogSender, SyslogTransport,
        WebhookAuth, WebhookSender,
    };
    use std::time::Duration;

    let mut router = AlertRouter::new(config.siem.local_log);

    // Optional last-resort buffering.
    if let Some(ref buffer_path) = config.siem.buffer_path {
        let buffer = FileAlertSender::new(buffer_path.clone(), Box::new(JsonFormatter::default()));
        router = router.with_buffer_sender(Arc::new(buffer));
    }

    let router = Arc::new(router);

    if !config.siem.enabled {
        info!("SIEM integration disabled");
        return router;
    }

    for output in &config.siem.outputs {
        let format = output
            .format
            .as_deref()
            .unwrap_or("json")
            .trim()
            .to_lowercase();

        let formatter: Box<dyn AlertFormatter> = match format.as_str() {
            "cef" => Box::new(CefFormatter::new()),
            "leef" => Box::new(LeefFormatter::new()),
            "json_pretty" | "jsonpretty" => Box::new(JsonFormatter::new(true)),
            _ => Box::new(JsonFormatter::default()),
        };

        let sender: Arc<dyn AlertSender> = match output.output_type.trim().to_lowercase().as_str() {
            "syslog" => {
                let Some(address) = output.address.as_deref() else {
                    warn!(route = %output.name, "Syslog output missing address");
                    continue;
                };

                let addr = match address.parse() {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(route = %output.name, error = %e, "Invalid syslog address");
                        continue;
                    }
                };

                let transport = match output.transport.as_deref().map(|t| t.trim().to_lowercase()) {
                    Some(t) if t == "tcp" => SyslogTransport::Tcp,
                    Some(t) if t == "tcp_tls" => SyslogTransport::TcpTls { ca_cert: None },
                    _ => SyslogTransport::Udp,
                };

                Arc::new(SyslogSender::new(addr, transport, formatter))
            }
            "webhook" => {
                let Some(url) = output.url.as_deref() else {
                    warn!(route = %output.name, "Webhook output missing url");
                    continue;
                };

                let auth = match output.auth_type.as_deref().map(|t| t.trim().to_lowercase()) {
                    Some(t) if t == "splunk_hec" => {
                        WebhookAuth::SplunkHec(output.auth_token.clone().unwrap_or_default())
                    }
                    Some(t) if t == "bearer" => {
                        WebhookAuth::Bearer(output.auth_token.clone().unwrap_or_default())
                    }
                    Some(t) if t == "basic" => WebhookAuth::Basic {
                        username: output.auth_username.clone().unwrap_or_default(),
                        password: output.auth_password.clone().unwrap_or_default(),
                    },
                    Some(t) if t == "custom" => WebhookAuth::Custom {
                        header_name: output.header_name.clone().unwrap_or_default(),
                        header_value: output.header_value.clone().unwrap_or_default(),
                    },
                    _ => WebhookAuth::None,
                };

                let inner = WebhookSender::new(url.to_string(), formatter, auth);

                if output.batch_size.unwrap_or(0) > 0 {
                    let batch_size = output.batch_size.unwrap_or(100);
                    let batch_timeout = Duration::from_secs(output.batch_timeout_secs.unwrap_or(5));
                    Arc::new(BatchingWebhookSender::new(
                        output.name.clone(),
                        inner,
                        batch_size,
                        batch_timeout,
                    ))
                } else {
                    Arc::new(inner)
                }
            }
            "file" => {
                let Some(path) = output.path.as_ref() else {
                    warn!(route = %output.name, "File output missing path");
                    continue;
                };

                let rotate_bytes = output
                    .rotate_size_mb
                    .map(|mb| mb.saturating_mul(1024).saturating_mul(1024));
                let rotate_keep = output.rotate_keep.unwrap_or(0);

                Arc::new(
                    FileAlertSender::new(path.clone(), formatter)
                        .with_rotation(rotate_bytes, rotate_keep),
                )
            }
            other => {
                warn!(route = %output.name, output_type = %other, "Unknown SIEM output type");
                continue;
            }
        };

        let route = RouteConfig {
            name: output.name.clone(),
            sender,
            min_severity: output.min_severity,
            rule_ids: output.rule_ids.clone(),
            enabled: output.enabled,
        };

        router.add_route(route).await;
    }

    info!(
        "SIEM router configured with {} outputs",
        router.status().await.len()
    );
    router
}

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

    let siem_router = setup_siem(&daemon_cfg).await;

    // Management server (metrics + REST API).
    if daemon_cfg.metrics.enabled || daemon_cfg.siem.enabled {
        let addr: SocketAddr = ([0, 0, 0, 0], daemon_cfg.metrics.port).into();
        let state = crate::api::ApiState {
            router: siem_router.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        tokio::spawn(async move {
            let api = crate::api::api_routes();

            let app = axum::Router::new()
                .route("/health", axum::routing::get(|| async { "OK" }))
                .route(
                    "/metrics",
                    axum::routing::get(|| async { crate::metrics::encode_metrics() }),
                )
                .nest("/api", api)
                .with_state(state);

            match tokio::net::TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!("Management server listening on {}", addr);
                    if let Err(e) = axum::serve(listener, app).await {
                        warn!(error = %e, "Management server exited");
                    }
                }
                Err(e) => {
                    warn!(error = %e, "Failed to bind management server");
                }
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
    let mut threat_intel_cfg = daemon_cfg.threat_intel.clone();
    if let Ok(path) = std::env::var("WINNCORE_THREATINTEL_DB") {
        threat_intel_cfg.db_path = PathBuf::from(path);
    }
    let behavioral_cfg = BehavioralConfig {
        response: daemon_cfg.response.clone(),
        external_rules_dir,
        alert_log_path,
        threat_intel: threat_intel_cfg,
    };
    let behavioral_runtime = start_behavioral_pipeline(behavioral_cfg).await?;
    let mut alert_rx = behavioral_runtime.alert_rx;

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
            let unified = behavioral_alert_to_unified(&alert);
            let _ = siem_router.route(&unified).await;
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
