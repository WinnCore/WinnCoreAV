use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct ScanDeduplicator {
    recent_scans: Arc<RwLock<HashMap<String, Instant>>>,
    debounce_duration: Duration,
    cleanup_duration: Duration,
}

impl ScanDeduplicator {
    pub fn new(debounce_ms: u64) -> Self {
        let debounce_ms = debounce_ms.max(1);
        let cleanup_ms = debounce_ms.saturating_mul(2).max(1);

        Self {
            recent_scans: Arc::new(RwLock::new(HashMap::new())),
            debounce_duration: Duration::from_millis(debounce_ms),
            cleanup_duration: Duration::from_millis(cleanup_ms),
        }
    }

    pub async fn should_scan(&self, path: &str) -> bool {
        let mut scans = self.recent_scans.write().await;

        // Check if we scanned this file in the configured debounce duration
        if let Some(&last_scan) = scans.get(path) {
            if last_scan.elapsed() < self.debounce_duration {
                return false; // Skip - scanned recently
            }
        }

        // Record this scan
        scans.insert(path.to_string(), Instant::now());

        // Cleanup old entries (older than cleanup duration)
        scans.retain(|_, &mut time| time.elapsed() < self.cleanup_duration);

        true
    }
}
