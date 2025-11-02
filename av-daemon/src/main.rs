mod metrics;
mod monitor;

use anyhow::Result;
<<<<<<< HEAD
use metrics::Metrics;
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_level(true)
=======
use metrics::*;
use std::panic;
use tracing::{error, info};

fn init_logging() {
    tracing_subscriber::fmt()
        .with_target(false)
>>>>>>> claude/prometheus-metrics-011CUgPhmcQJyzPKUycQrphV
        .init();

    info!("🛡️  WinnCoreAV v0.1.0");

<<<<<<< HEAD
    info!("🔧 Initializing metrics...");
    let metrics = Arc::new(Metrics::new()?);
    info!("✅ Metrics initialized");

    info!("🔧 Starting metrics HTTP server on 127.0.0.1:9090...");
    metrics.start_server("127.0.0.1:9090".to_string());

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    info!("✅ Scanner initialized (8 workers)");
    info!("🔔 Notifications: ENABLED");
    info!("🔒 Auto-quarantine: ENABLED");
    info!("🚀 Starting monitoring...");
=======
    // Start metrics server
    if let Err(e) = metrics::start_metrics_server(9090) {
        error!("Failed to start metrics server: {}", e);
    } else {
        info!("📊 Metrics available at http://localhost:9090/metrics");
    }

    // Initialize worker count gauge
    WORKER_THREADS.set(num_cpus::get() as f64);
>>>>>>> claude/prometheus-metrics-011CUgPhmcQJyzPKUycQrphV

    let home = dirs::home_dir().expect("No HOME");
    let file_monitor = monitor::FileMonitor::new(
        vec![
            home.join("Downloads"),
            home.join("Desktop"),
            home.join("Documents"),
        ],
        vec![
            "**/node_modules/**".into(),
            "**/target/**".into(),
            "**/.git/**".into(),
            "**/.cache/**".into(),
            "**/__pycache__/**".into(),
            "**/*.swp".into(),
            "**/*.tmp".into(),
        ],
        true,
        Arc::clone(&metrics),
    )?;

    file_monitor.start()?;

    Ok(())
}
