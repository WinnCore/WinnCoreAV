mod monitor;

use anyhow::Result;
use std::panic;
use tracing::{error, info};

fn init_logging() {
    tracing_subscriber::fmt().with_target(false).json().init();

    panic::set_hook(Box::new(|p| {
        error!("PANIC: {:?}", p);
    }));
}

fn self_test() -> Result<()> {
    info!("🧪 Self-test...");
    let test_dir = std::env::temp_dir().join("winncore-test");
    std::fs::create_dir_all(&test_dir)?;
    let test_file = test_dir.join("test.txt");
    std::fs::write(&test_file, "test")?;
    info!("✅ File ops OK");
    std::fs::remove_dir_all(&test_dir)?;
    info!("✅ Self-test passed");
    Ok(())
}

fn main() -> Result<()> {
    if std::env::args().any(|a| a == "--self-test") {
        return self_test();
    }

    init_logging();
    info!("🛡️  WinnCoreAV v0.1.0");

    let home = dirs::home_dir().expect("No HOME");
    let monitor = monitor::FileMonitor::new(
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
            "**/*.swx".into(),
            "**/*.tmp".into(),
            "**/.DS_Store".into(),
            "**/~$*".into(),
        ],
        true,
    )?;

    monitor.start()?;
    Ok(())
}
