use anyhow::Result;
use std::fs;
use std::path::Path;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use av_ebpf_loader::{load_and_attach, resolve_bpf_object_path, EbpfAttachConfig, EbpfLoadConfig};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/winncore";
const FALLBACK_MARKER: &str = "/var/lib/winncore/state/ebpf_fallback";
const FALLBACK_REASON: &str = "/var/lib/winncore/state/ebpf_fallback_reason";

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

    let Some(object_path) = resolve_bpf_object_path() else {
        let reason =
            "eBPF object not found (set WINNCORE_EBPF_OBJECT or build av-ebpf-probes)".to_string();
        warn!("⚠️  eBPF loader falling back: {}", reason);
        create_fallback_marker(&reason)?;
        std::process::exit(0);
    };

    if !Path::new("/sys/fs/bpf").exists() {
        let reason = "BPF filesystem not mounted at /sys/fs/bpf".to_string();
        warn!("⚠️  eBPF loader falling back: {}", reason);
        create_fallback_marker(&reason)?;
        std::process::exit(0);
    }

    // Create the pin dir for compatibility with self-protection checks.
    if let Err(e) = fs::create_dir_all(BPF_PIN_PATH) {
        let reason = format!("Cannot create pin dir: {}", e);
        warn!("⚠️  eBPF loader falling back: {}", reason);
        create_fallback_marker(&reason)?;
        std::process::exit(0);
    }

    let config = EbpfLoadConfig {
        object_path,
        attach: EbpfAttachConfig::default(),
    };

    let bpf = match load_and_attach(&config) {
        Ok(bpf) => bpf,
        Err(e) => {
            let reason = format!("eBPF load/attach failed: {}", e);
            warn!("⚠️  eBPF loader falling back: {}", reason);
            create_fallback_marker(&reason)?;
            std::process::exit(0);
        }
    };

    info!("eBPF programs loaded and attached; waiting for shutdown signal");

    // Keep programs attached for the lifetime of this process.
    let _bpf = bpf;
    tokio::signal::ctrl_c().await.ok();
    info!("eBPF loader exiting");
    Ok(())
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
