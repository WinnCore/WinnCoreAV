//! Monitor canary files for access.

use std::collections::HashMap;
use std::path::PathBuf;

use inotify::{Event, EventMask, Inotify, WatchMask};
use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::canary::Canary;

/// Alert generated when a canary is accessed.
#[derive(Debug, Clone)]
pub struct CanaryAlert {
    pub canary: Canary,
    pub event_type: CanaryEventType,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum CanaryEventType {
    Opened,
    Read,
    Modified,
    Deleted,
    AttributeChanged,
}

/// Canary file monitor.
pub struct CanaryMonitor {
    inotify: Inotify,
    canaries: HashMap<i32, Canary>, // Watch descriptor -> Canary
    alert_tx: mpsc::Sender<CanaryAlert>,
}

impl CanaryMonitor {
    /// Create a new canary monitor.
    pub fn new(
        canaries: Vec<Canary>,
    ) -> Result<(Self, mpsc::Receiver<CanaryAlert>), std::io::Error> {
        let inotify = Inotify::init()?;
        let (alert_tx, alert_rx) = mpsc::channel(100);

        let mut monitor = Self {
            inotify,
            canaries: HashMap::new(),
            alert_tx,
        };

        // Add watches for all canaries
        for canary in canaries {
            if let Err(e) = monitor.add_canary(canary.clone()) {
                error!("Failed to watch canary {:?}: {}", canary.path, e);
            }
        }

        Ok((monitor, alert_rx))
    }

    fn add_canary(&mut self, canary: Canary) -> Result<(), std::io::Error> {
        // Watch for: open, access, modify, delete, attrib changes
        let mask = WatchMask::OPEN
            | WatchMask::ACCESS
            | WatchMask::MODIFY
            | WatchMask::DELETE_SELF
            | WatchMask::ATTRIB;

        let wd = self.inotify.watches().add(&canary.path, mask)?;
        self.canaries.insert(wd.get_watch_descriptor_id(), canary);

        Ok(())
    }

    /// Run the monitor loop (blocking).
    pub async fn run(&mut self) {
        let mut buffer = [0u8; 4096];

        loop {
            match self.inotify.read_events(&mut buffer) {
                Ok(events) => {
                    for event in events {
                        self.handle_event(event).await;
                    }
                }
                Err(e) => {
                    error!("inotify read error: {}", e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn handle_event(&self, event: Event<&std::ffi::OsStr>) {
        let wd_id = event.wd.get_watch_descriptor_id();

        let canary = match self.canaries.get(&wd_id) {
            Some(c) => c,
            None => return,
        };

        let event_type = if event.mask.contains(EventMask::OPEN) {
            CanaryEventType::Opened
        } else if event.mask.contains(EventMask::ACCESS) {
            CanaryEventType::Read
        } else if event.mask.contains(EventMask::MODIFY) {
            CanaryEventType::Modified
        } else if event.mask.contains(EventMask::DELETE_SELF) {
            CanaryEventType::Deleted
        } else if event.mask.contains(EventMask::ATTRIB) {
            CanaryEventType::AttributeChanged
        } else {
            return;
        };

        warn!(
            "CANARY TRIGGERED: {:?} event on {:?} (severity: {:?})",
            event_type, canary.path, canary.severity
        );

        // Try to identify the accessing process
        let (pid, comm) = get_accessing_process(&canary.path);

        let alert = CanaryAlert {
            canary: canary.clone(),
            event_type,
            pid,
            comm,
            timestamp: current_time_ns(),
        };

        if let Err(e) = self.alert_tx.send(alert).await {
            error!("Failed to send canary alert: {}", e);
        }
    }
}

fn get_accessing_process(path: &PathBuf) -> (Option<u32>, Option<String>) {
    // Try to find process with this file open via /proc/*/fd
    // This is racy but sometimes works
    for entry in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let name = entry.file_name();
        if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
            let fd_dir = format!("/proc/{}/fd", pid);
            for fd_entry in std::fs::read_dir(&fd_dir).into_iter().flatten().flatten() {
                if let Ok(target) = std::fs::read_link(fd_entry.path()) {
                    if target == *path {
                        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                            .ok()
                            .map(|s| s.trim().to_string());
                        return (Some(pid), comm);
                    }
                }
            }
        }
    }

    (None, None)
}

fn current_time_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
