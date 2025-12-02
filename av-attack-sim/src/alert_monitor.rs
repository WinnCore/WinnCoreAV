//! Monitor EDR alerts during simulations.

use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::Mutex;

const ALERT_LOG_PATH: &str = "/var/log/winncore/alerts.json";

pub struct AlertMonitor {
    alerts: Arc<Mutex<Vec<String>>>,
    last_position: Arc<Mutex<u64>>,
}

impl AlertMonitor {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            alerts: Arc::new(Mutex::new(Vec::new())),
            last_position: Arc::new(Mutex::new(0)),
        })
    }

    pub async fn clear(&self) {
        let mut alerts = self.alerts.lock().await;
        alerts.clear();

        if let Ok(metadata) = fs::metadata(ALERT_LOG_PATH).await {
            let mut pos = self.last_position.lock().await;
            *pos = metadata.len();
        }
    }

    pub async fn wait_for_alert(&self, pattern: &str, max_wait: Duration) -> Option<String> {
        let pattern = pattern.to_lowercase();
        let start = std::time::Instant::now();

        while start.elapsed() < max_wait {
            if let Ok(content) = fs::read_to_string(ALERT_LOG_PATH).await {
                let pos = *self.last_position.lock().await as usize;
                let new_content = if pos < content.len() {
                    &content[pos..]
                } else {
                    ""
                };

                for line in new_content.lines() {
                    let lower = line.to_lowercase();
                    if lower.contains(&pattern)
                        || lower.contains("detected")
                        || lower.contains("alert")
                        || lower.contains("threat")
                    {
                        return Some(line.to_string());
                    }
                }
            }

            if let Ok(output) = tokio::process::Command::new("dmesg")
                .args(["--since", "10 seconds ago"])
                .output()
                .await
            {
                let dmesg = String::from_utf8_lossy(&output.stdout).to_lowercase();
                if dmesg.contains("winncore")
                    && (dmesg.contains(&pattern) || dmesg.contains("alert"))
                {
                    return Some(format!("Kernel alert: {}", pattern));
                }
            }

            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        None
    }
}
