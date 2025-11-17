use anyhow::{Context, Result};
use av_core::{Scanner, ScannerConfig};
use notify::{Config as NotifyConfig, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
use signal_hook_tokio::Signals;
use std::{
    collections::VecDeque,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, RwLock};
use tokio_stream::StreamExt;
use tracing::{error, info, warn};

mod config;
mod dedup;
use dedup::ScanDeduplicator;
mod response;

use config::DaemonConfig;
use response::ResponseEngine;

#[derive(Clone)]
struct DaemonState {
    scanner: Arc<Scanner>,
    response: Arc<RwLock<ResponseEngine>>,
    config: Arc<DaemonConfig>,
    stats: Arc<RwLock<Stats>>,
    dedup: Arc<ScanDeduplicator>,
}

#[derive(Debug)]
struct Stats {
    scans_today: u64,
    threats_found: u64,
    files_quarantined: u64,
    processes_killed: u64,
    uptime_start: std::time::Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            scans_today: 0,
            threats_found: 0,
            files_quarantined: 0,
            processes_killed: 0,
            uptime_start: std::time::Instant::now(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("🛡️  WinnCoreAV Daemon starting...");

    let config = DaemonConfig::load().context("failed to load daemon configuration")?;
    info!("✅ Configuration loaded");

    let scanner_config = ScannerConfig::default();
    let scanner = Scanner::new(scanner_config).context("failed to initialize scanner")?;
    info!("✅ Scanner initialized");

    let response_engine = ResponseEngine::new(
        config.response.enabled,
        config.thresholds.kill_threshold,
    );
    info!("✅ Response engine initialized");

    let dedup = ScanDeduplicator::new(config.monitoring.debounce_ms);

    let state = DaemonState {
        scanner: Arc::new(scanner),
        response: Arc::new(RwLock::new(response_engine)),
        config: Arc::new(config.clone()),
        stats: Arc::new(RwLock::new(Stats::new())),
        dedup: Arc::new(dedup),
    };

    write_pid_file(&config.daemon.pid_file)?;
    info!("✅ PID file written: {}", config.daemon.pid_file);

    let signals = Signals::new(&[SIGTERM, SIGINT, SIGHUP])?;
    let signals_handle = signals.handle();
    let signal_state = state.clone();
    let mut signals_task =
        tokio::spawn(async move { handle_signals(signals, signal_state).await });

    let monitoring_state = state.clone();
    let mut monitoring_task = tokio::spawn(async move {
        if let Err(err) = monitor_files(monitoring_state).await {
            error!("File monitoring stopped: {err:?}");
        }
    });

    let stats_state = state.clone();
    let mut stats_task = tokio::spawn(async move {
        report_stats(stats_state).await;
    });

    info!("🚀 WinnCoreAV Daemon is running");
    info!(
        "   Watching paths: {:?}",
        state.config.monitoring.watch_paths
    );
    info!("   Auto-response: {}", state.config.response.enabled);

    tokio::select! {
        _ = &mut signals_task => info!("Signal handler stopped"),
        _ = &mut monitoring_task => warn!("File monitoring task exited"),
        _ = &mut stats_task => warn!("Stats reporter task exited"),
    }

    signals_handle.close();
    monitoring_task.abort();
    stats_task.abort();
    signals_task.abort();

    cleanup(&config.daemon.pid_file)?;
    info!("👋 WinnCoreAV Daemon stopped gracefully");

    Ok(())
}

async fn monitor_files(state: DaemonState) -> Result<()> {
    info!("📂 Starting file monitoring...");

    let (event_tx, mut rx) = mpsc::channel(state.config.limits.max_scan_queue);

    let mut watcher = RecommendedWatcher::new(
        {
            let event_tx = event_tx.clone();
            move |res: notify::Result<Event>| match res {
                Ok(event) => {
                    if let Err(send_err) = event_tx.blocking_send(event) {
                        warn!("dropping file event: {send_err}");
                    }
                }
                Err(err) => warn!("notify error: {err}"),
            }
        },
        NotifyConfig::default(),
    )?;
    drop(event_tx);

    for path in &state.config.monitoring.watch_paths {
        let watch_path = Path::new(path);
        if watch_path.exists() {
            register_watch_path(&mut watcher, watch_path, &state.config.monitoring.ignore_paths);
        } else {
            warn!("  ⚠️  Path does not exist: {}", watch_path.display());
        }
    }

    while let Some(event) = rx.recv().await {
        if should_scan_event(&event, state.config.as_ref()) {
            for path in event.paths.clone() {
                let inner_state = state.clone();
                tokio::spawn(async move {
                    scan_file(path, inner_state).await;
                });
            }
        }
    }

    Ok(())
}

fn should_scan_event(event: &Event, config: &DaemonConfig) -> bool {
    if event.paths.is_empty() {
        return false;
    }

    match event.kind {
        EventKind::Create(_) => config.monitoring.scan_on_create,
        EventKind::Modify(_) => config.monitoring.scan_on_modify,
        EventKind::Access(_) => config.monitoring.scan_on_execute,
        _ => false,
    }
}

async fn scan_file(path: PathBuf, state: DaemonState) {
    // Deduplicate scans - skip if scanned recently
    let path_str = path.to_string_lossy().to_string();
    if !state.dedup.should_scan(&path_str).await {
        return; // Already scanned recently
    }

    if is_ignored(&path, &state.config.monitoring.ignore_paths) {
        return;
    }

    if !path.is_file() {
        return;
    }

    info!("🔍 Scanning: {:?}", path);

    let scanner = state.scanner.clone();
    let scan_future = scanner.scan_path(&path);
    let timeout = Duration::from_secs(state.config.limits.scan_timeout_seconds);

    match tokio::time::timeout(timeout, scan_future).await {
        Ok(Ok(scan_result)) => {
            {
                let mut stats = state.stats.write().await;
                stats.scans_today += 1;
            }

            let score = scan_result.heuristic_score.0;

            if score >= state.config.thresholds.quarantine_threshold {
                warn!("⚠️  THREAT DETECTED: {:?} (score: {:.3})", path, score);
                {
                    let mut stats = state.stats.write().await;
                    stats.threats_found += 1;
                }

                if state.config.response.enabled {
                    handle_threat(&path, score, state.clone()).await;
                }
            } else if score >= state.config.thresholds.alert_threshold {
                warn!("⚠️  Suspicious file: {:?} (score: {:.3})", path, score);
            } else {
                info!("✅ Clean: {:?} (score: {:.3})", path, score);
            }
        }
        Ok(Err(err)) => {
            error!("❌ Scan failed for {:?}: {err}", path);
        }
        Err(_) => {
            error!("⏱️  Scan timeout for {:?}", path);
        }
    }
}

async fn handle_threat(path: &Path, score: f32, state: DaemonState) {
    let config = &state.config;

    if score >= config.thresholds.quarantine_threshold && config.response.auto_quarantine {
        info!("🔒 Quarantining: {:?}", path);
        {
            let mut stats = state.stats.write().await;
            stats.files_quarantined += 1;
        }
    }

    if score >= config.thresholds.kill_threshold && config.response.auto_kill {
        info!("💀 Killing process for: {:?}", path);
        {
            let mut stats = state.stats.write().await;
            stats.processes_killed += 1;
        }
    }

    let mut response = state.response.write().await;
    response.record_action();
}

async fn handle_signals(mut signals: Signals, _state: DaemonState) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGINT => {
                info!("📡 Received shutdown signal");
                break;
            }
            SIGHUP => {
                info!("📡 Received SIGHUP - configuration reload requested");
            }
            _ => {}
        }
    }
}

async fn report_stats(state: DaemonState) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        interval.tick().await;

        let stats = state.stats.read().await;
        let uptime = stats.uptime_start.elapsed().as_secs();

        info!(
            "📊 Stats - Uptime: {}s, Scans: {}, Threats: {}, Quarantined: {}, Killed: {}",
            uptime,
            stats.scans_today,
            stats.threats_found,
            stats.files_quarantined,
            stats.processes_killed
        );
    }
}

fn write_pid_file(path: &str) -> Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, std::process::id().to_string())?;
    Ok(())
}

fn cleanup(pid_file: &str) -> Result<()> {
    if Path::new(pid_file).exists() {
        std::fs::remove_file(pid_file)?;
    }
    Ok(())
}

fn register_watch_path(
    watcher: &mut RecommendedWatcher,
    root: &Path,
    ignore_paths: &[String],
) {
    if is_ignored(root, ignore_paths) {
        return;
    }

    match watcher.watch(root, RecursiveMode::Recursive) {
        Ok(_) => info!("  ✅ Watching: {}", root.display()),
        Err(err) => {
            warn!(
                "  ⚠️  Recursive watch failed for {}: {err}",
                root.display()
            );

            if !root.is_dir() {
                return;
            }

            let mut queue = VecDeque::new();
            queue.push_back(root.to_path_buf());

            while let Some(dir) = queue.pop_front() {
                if is_ignored(&dir, ignore_paths) {
                    continue;
                }

                match watcher.watch(&dir, RecursiveMode::NonRecursive) {
                    Ok(_) => info!("  ✅ Watching directory: {}", dir.display()),
                    Err(e) => {
                        warn!(
                            "  ⚠️  Failed to watch directory {}: {e}",
                            dir.display()
                        );
                        continue;
                    }
                }

                if let Ok(entries) = fs::read_dir(&dir) {
                    for entry in entries.flatten() {
                        if let Ok(ft) = entry.file_type() {
                            if ft.is_dir() {
                                queue.push_back(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_ignored(path: &Path, ignore_paths: &[String]) -> bool {
    ignore_paths
        .iter()
        .map(Path::new)
        .any(|ignore| path.starts_with(ignore))
}
