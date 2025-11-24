//! Startup integrity checks and guardrails.

use av_core::selfprotect::SelfProtection;
use tracing::{error, info, warn};

const FALLBACK_MARKER: &str = "/var/lib/winncore/state/ebpf_fallback";
const FALLBACK_REASON: &str = "/var/lib/winncore/state/ebpf_fallback_reason";

pub async fn run_startup_checks() -> Result<(), Vec<String>> {
    let mut failures = Vec::new();

    info!("Running startup integrity checks");

    let protection = SelfProtection::new(|alert| {
        warn!(?alert, "Self-protection alert during startup");
    });

    if let Err(f) = protection.verify_binary_integrity().await {
        failures.extend(f);
    }

    match verify_config_permissions() {
        Ok(()) => info!("Config permissions OK"),
        Err(e) => warn!("Config permission warning: {}", e),
    }

    match protection.verify_bpf_maps().await {
        Ok(()) => info!("eBPF maps present"),
        Err(e) => warn!("eBPF check: {}", e),
    }

    if let Some(reason) = read_fallback_reason() {
        warn!(
            "eBPF fallback marker detected; running with reduced visibility: {}",
            reason
        );
    }

    if failures.is_empty() {
        Ok(())
    } else {
        error!("Startup checks failed: {:?}", failures);
        Err(failures)
    }
}

fn verify_config_permissions() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let path = "/etc/winncore/config.toml";
    let meta = std::fs::metadata(path).map_err(|e| format!("Cannot stat config: {}", e))?;
    if meta.uid() != 0 {
        return Err("Config not owned by root".to_string());
    }
    let mode = meta.mode() & 0o777;
    if mode != 0o640 {
        return Err(format!("Config mode is {:o}, expected 640", mode));
    }
    Ok(())
}

fn read_fallback_reason() -> Option<String> {
    if std::path::Path::new(FALLBACK_MARKER).exists() {
        std::fs::read_to_string(FALLBACK_REASON).ok()
    } else {
        None
    }
}
