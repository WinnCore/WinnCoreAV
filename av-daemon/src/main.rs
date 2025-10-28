mod monitor;

use anyhow::Result;
use std::path::PathBuf;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    println!("🛡️  WinnCoreAV Daemon - ARM64 Real-time Protection");

    // Watch Downloads and Desktop by default
    let watch_paths = vec![
        PathBuf::from("/tmp"), // For testing
    ];

    let monitor = monitor::FileMonitor::new(watch_paths);
    monitor.start()?;

    Ok(())
}
