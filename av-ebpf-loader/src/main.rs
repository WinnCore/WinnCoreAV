use anyhow::Result;
use std::fs;
use std::path::Path;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

const BPF_PIN_PATH: &str = "/sys/fs/bpf/winncore";
const FALLBACK_MARKER: &str = "/var/lib/winncore/state/ebpf_fallback";
const FALLBACK_REASON: &str = "/var/lib/winncore/state/ebpf_fallback_reason";

#[derive(Debug)]
enum LoadResult {
    Fallback(String),
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("WinnCoreAV eBPF loader starting");

    if !nix::unistd::geteuid().is_root() {
        error!("Must run as root to load eBPF programs");
        std::process::exit(1);
    }

    match load_and_pin().await {
        LoadResult::Fallback(reason) => {
            warn!("⚠️  eBPF loader falling back: {}", reason);
            create_fallback_marker(&reason)?;
            std::process::exit(0);
        }
    }
}

async fn load_and_pin() -> LoadResult {
    if !Path::new("/sys/fs/bpf").exists() {
        return LoadResult::Fallback("BPF filesystem not mounted at /sys/fs/bpf".into());
    }

    if let Err(e) = fs::create_dir_all(BPF_PIN_PATH) {
        return LoadResult::Fallback(format!("Cannot create pin dir: {}", e));
    }

    // Real eBPF loading to be implemented; currently create fallback marker
    LoadResult::Fallback("eBPF bytecode loading not implemented yet".into())
}

fn create_fallback_marker(reason: &str) -> Result<()> {
    fs::create_dir_all(
        std::path::Path::new(FALLBACK_MARKER)
            .parent()
            .unwrap_or(std::path::Path::new("/var/lib/winncore/state")),
    )?;
    fs::write(FALLBACK_MARKER, "1")?;
    fs::write(FALLBACK_REASON, reason)?;
    Ok(())
}
