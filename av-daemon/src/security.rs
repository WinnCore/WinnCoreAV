use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use av_containers::ContainerDetector;
use av_response::ResponseExecutor;
use av_rootkit::{check_common_hiding_spots, scan_hidden_processes, scan_kernel_modules};
use tracing::{info, warn};

/// Kick off supplemental security tasks (container context + rootkit sweeps).
pub async fn start_security_tasks() -> Arc<ResponseExecutor> {
    // Inspect container context once on startup.
    let detector = ContainerDetector::new();
    if detector.in_container() {
        let ctx = detector.context();
        info!(
            runtime = ?ctx.runtime,
            privileged = ctx.is_privileged,
            host_pid = ctx.has_host_pid,
            host_net = ctx.has_host_network,
            socket = ctx.mounted_docker_socket,
            "Running inside container"
        );
        if ctx.is_high_risk() {
            warn!("Container configuration is high risk; watch for escapes");
        }
    } else {
        info!("Not running inside a container");
    }

    // Response executor for future automated actions.
    let responder = Arc::new(ResponseExecutor::new(PathBuf::from(
        "/var/lib/winncore/quarantine",
    )));

    // Periodic rootkit sweep (best effort, low frequency).
    let responder_clone = responder.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(600));
        loop {
            ticker.tick().await;
            let hidden = scan_hidden_processes();
            if !hidden.hidden_pids.is_empty() {
                warn!(
                    count = hidden.hidden_pids.len(),
                    "Possible hidden processes detected"
                );
            }
            let mods = scan_kernel_modules();
            if !mods.suspicious_modules.is_empty() {
                warn!(mods = ?mods.suspicious_modules, "Suspicious kernel modules detected");
            }
            let hiding_spots = check_common_hiding_spots();
            if !hiding_spots.is_empty() {
                warn!(files = ?hiding_spots, "Suspicious hidden executables found");
            }
            // Future: auto-response via responder_clone based on severity.
            let _ = responder_clone.as_ref() as *const _; // keep responder in scope
        }
    });

    responder
}
