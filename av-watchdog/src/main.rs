use anyhow::Result;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use sysinfo::System;
use tokio::time;
use tracing::{error, info, warn};

const DAEMON_PID_FILE: &str = "/run/winncore/av-daemon.pid";
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(10);
const MAX_RESTART_ATTEMPTS: u32 = 5;
const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(5);

struct WatchdogState {
    daemon_restart_count: u32,
    last_daemon_restart: std::time::Instant,
    system: System,
}

impl WatchdogState {
    fn new() -> Self {
        Self {
            daemon_restart_count: 0,
            last_daemon_restart: std::time::Instant::now(),
            system: System::new_all(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("av_watchdog=info")
        .json()
        .init();

    info!("WinnCoreAV Watchdog starting");

    let mut state = WatchdogState::new();

    loop {
        state.system.refresh_all();

        match check_daemon_health(&mut state).await {
            Ok(true) => {
                if state.last_daemon_restart.elapsed() > Duration::from_secs(300) {
                    state.daemon_restart_count = 0;
                }
            }
            Ok(false) => {
                warn!("Daemon unhealthy, attempting restart");
                if let Err(e) = restart_daemon(&mut state).await {
                    error!("Failed to restart daemon: {}", e);
                }
            }
            Err(e) => error!("Health check failed: {}", e),
        }

        if let Err(e) = check_ebpf_health().await {
            warn!("eBPF health check failed: {}", e);
        }

        check_resource_usage(&state);

        time::sleep(HEALTH_CHECK_INTERVAL).await;
    }
}

async fn check_daemon_health(state: &mut WatchdogState) -> Result<bool> {
    let pid_path = Path::new(DAEMON_PID_FILE);
    if !pid_path.exists() {
        return Ok(false);
    }

    let pid_str = fs::read_to_string(pid_path)?;
    let pid: i32 = pid_str.trim().parse()?;

    if state
        .system
        .process(sysinfo::Pid::from(pid as usize))
        .is_none()
    {
        return Ok(false);
    }

    match reqwest::get("http://127.0.0.1:9090/health").await {
        Ok(resp) if resp.status().is_success() => Ok(true),
        Ok(resp) => {
            warn!("Health endpoint returned {}", resp.status());
            Ok(false)
        }
        Err(e) => {
            warn!("Health endpoint unreachable: {}", e);
            Ok(false)
        }
    }
}

async fn restart_daemon(state: &mut WatchdogState) -> Result<()> {
    if state.daemon_restart_count >= MAX_RESTART_ATTEMPTS {
        error!(
            "Exceeded max restart attempts ({}), manual intervention required",
            MAX_RESTART_ATTEMPTS
        );
        return Err(anyhow::anyhow!("Max restart attempts exceeded"));
    }

    let backoff = RESTART_BACKOFF_BASE * 2u32.pow(state.daemon_restart_count);
    info!("Waiting {:?} before restart attempt", backoff);
    time::sleep(backoff).await;

    if let Ok(pid_str) = fs::read_to_string(DAEMON_PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            let _ = signal::kill(Pid::from_raw(pid), Signal::SIGTERM);
            time::sleep(Duration::from_secs(5)).await;
        }
    }

    let status = Command::new("systemctl")
        .args(["restart", "winncore-daemon"])
        .status()?;

    if status.success() {
        info!("Daemon restart initiated");
        state.daemon_restart_count += 1;
        state.last_daemon_restart = std::time::Instant::now();
        Ok(())
    } else {
        Err(anyhow::anyhow!("systemctl restart failed"))
    }
}

async fn check_ebpf_health() -> Result<()> {
    let bpf_path = Path::new("/sys/fs/bpf/winncore");

    if !bpf_path.exists() {
        return Err(anyhow::anyhow!("BPF maps not pinned"));
    }

    for map_name in &["events", "config", "stats"] {
        let map_path = bpf_path.join(map_name);
        if !map_path.exists() {
            return Err(anyhow::anyhow!("BPF map {} missing", map_name));
        }
    }

    Ok(())
}

fn check_resource_usage(state: &WatchdogState) {
    for (pid, process) in state.system.processes() {
        if process.name() == "av-daemon" {
            let cpu = process.cpu_usage();
            let mem = process.memory();

            if cpu > 80.0 {
                warn!(
                    pid = pid.as_u32(),
                    cpu = %cpu,
                    "Daemon CPU usage high"
                );
            }

            if mem > 500 * 1024 * 1024 {
                warn!(
                    pid = pid.as_u32(),
                    memory_mb = mem / 1024 / 1024,
                    "Daemon memory usage high"
                );
            }
        }
    }
}
