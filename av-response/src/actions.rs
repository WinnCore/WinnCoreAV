use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub action: ResponseAction,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub message: String,
    pub reversal_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponseAction {
    KillProcess {
        pid: u32,
        signal: String,
        reason: String,
    },
    QuarantineFile {
        path: String,
        reason: String,
    },
    BlockIP {
        ip: String,
        direction: BlockDirection,
        reason: String,
    },
    CustomCommand {
        command: String,
        args: Vec<String>,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockDirection {
    Inbound,
    Outbound,
    Both,
}

pub struct ResponseExecutor {
    quarantine_dir: PathBuf,
    rate_limit: u32,
    actions_this_minute: AtomicU32,
    minute_start: Instant,
    dry_run: bool,
    protected_pids: HashSet<u32>,
}

impl ResponseExecutor {
    pub fn new(quarantine_dir: PathBuf) -> Self {
        let mut protected = HashSet::new();
        protected.insert(1);
        Self {
            quarantine_dir,
            rate_limit: 50,
            actions_this_minute: AtomicU32::new(0),
            minute_start: Instant::now(),
            dry_run: false,
            protected_pids: protected,
        }
    }

    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    pub async fn execute(&self, action: ResponseAction) -> ActionResult {
        if !self.check_rate_limit() {
            return ActionResult {
                action,
                success: false,
                timestamp: Utc::now(),
                message: "Rate limit exceeded".to_string(),
                reversal_token: None,
            };
        }
        if self.dry_run {
            return ActionResult {
                action,
                success: true,
                timestamp: Utc::now(),
                message: "Dry run - no action taken".to_string(),
                reversal_token: None,
            };
        }
        match &action {
            ResponseAction::KillProcess {
                pid,
                signal,
                reason,
            } => self.kill_process(*pid, signal, reason).await,
            ResponseAction::QuarantineFile { path, reason } => {
                self.quarantine_file(path, reason).await
            }
            ResponseAction::BlockIP {
                ip,
                direction,
                reason,
            } => self.block_ip(ip, *direction, reason).await,
            ResponseAction::CustomCommand {
                command,
                args,
                reason,
            } => self.custom_command(command, args, reason).await,
        }
    }

    fn check_rate_limit(&self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.minute_start) > Duration::from_secs(60) {
            self.actions_this_minute.store(0, Ordering::SeqCst);
        }
        let count = self.actions_this_minute.fetch_add(1, Ordering::SeqCst);
        count < self.rate_limit
    }

    async fn kill_process(&self, pid: u32, signal_name: &str, reason: &str) -> ActionResult {
        let action = ResponseAction::KillProcess {
            pid,
            signal: signal_name.to_string(),
            reason: reason.to_string(),
        };
        if self.protected_pids.contains(&pid) {
            return ActionResult {
                action,
                success: false,
                timestamp: Utc::now(),
                message: "Protected PID".to_string(),
                reversal_token: None,
            };
        }
        let sig = match signal_name.to_uppercase().as_str() {
            "KILL" | "SIGKILL" => Signal::SIGKILL,
            "STOP" | "SIGSTOP" => Signal::SIGSTOP,
            _ => Signal::SIGTERM,
        };
        let res = signal::kill(Pid::from_raw(pid as i32), sig);
        let success = res.is_ok();
        if success {
            info!("Killed pid {} with {} ({})", pid, signal_name, reason);
        } else if let Err(e) = res {
            warn!("Failed to kill pid {}: {}", pid, e);
        }
        ActionResult {
            action,
            success,
            timestamp: Utc::now(),
            message: if success {
                "Process terminated".into()
            } else {
                "Kill failed".into()
            },
            reversal_token: None,
        }
    }

    async fn quarantine_file(&self, path: &str, reason: &str) -> ActionResult {
        let action = ResponseAction::QuarantineFile {
            path: path.to_string(),
            reason: reason.to_string(),
        };
        let target = self.quarantine_dir.join(format!(
            "{}_{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S"),
            PathBuf::from(path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));
        let res = fs::create_dir_all(&self.quarantine_dir).await;
        let success = if res.is_ok() {
            fs::rename(path, &target).await.is_ok()
        } else {
            false
        };
        if success {
            info!("Quarantined {} -> {} ({})", path, target.display(), reason);
        } else if let Err(e) = res {
            warn!("Failed to quarantine {}: {}", path, e);
        }
        ActionResult {
            action,
            success,
            timestamp: Utc::now(),
            message: if success {
                format!("Moved to {}", target.display())
            } else {
                "Quarantine failed".into()
            },
            reversal_token: if success {
                Some(target.to_string_lossy().into_owned())
            } else {
                None
            },
        }
    }

    async fn block_ip(&self, ip: &str, direction: BlockDirection, reason: &str) -> ActionResult {
        let action = ResponseAction::BlockIP {
            ip: ip.to_string(),
            direction,
            reason: reason.to_string(),
        };
        // Best-effort iptables; ignore failures in constrained envs.
        let chain = match direction {
            BlockDirection::Inbound => "INPUT",
            BlockDirection::Outbound => "OUTPUT",
            BlockDirection::Both => "INPUT",
        };
        let res = Command::new("iptables")
            .args(["-A", chain, "-s", ip, "-j", "DROP"])
            .output();
        let success = res.as_ref().map(|o| o.status.success()).unwrap_or(false);
        ActionResult {
            action,
            success,
            timestamp: Utc::now(),
            message: if success {
                format!("Blocked {}", ip)
            } else {
                "iptables failed".into()
            },
            reversal_token: None,
        }
    }

    async fn custom_command(&self, command: &str, args: &[String], reason: &str) -> ActionResult {
        let action = ResponseAction::CustomCommand {
            command: command.to_string(),
            args: args.to_vec(),
            reason: reason.to_string(),
        };
        let res = Command::new(command).args(args).output();
        let success = res.as_ref().map(|o| o.status.success()).unwrap_or(false);
        ActionResult {
            action,
            success,
            timestamp: Utc::now(),
            message: if success {
                "Command executed".into()
            } else {
                "Command failed".into()
            },
            reversal_token: None,
        }
    }
}
