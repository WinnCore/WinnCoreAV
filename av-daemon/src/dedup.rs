use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Scan deduplicator to prevent scanning the same file multiple times
/// within a short time window (e.g., when inotify triggers multiple events)
pub struct ScanDeduplicator {
    /// Map of file path -> last scan time
    scans: RwLock<HashMap<String, Instant>>,
    /// Time window for deduplication (default: 5 seconds)
    window: Duration,
}

impl ScanDeduplicator {
    /// Create a new scan deduplicator with default 5-second window
    pub fn new() -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
            window: Duration::from_secs(5),
        }
    }

    /// Create a new scan deduplicator with custom time window
    pub fn with_window(window: Duration) -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
            window,
        }
    }

    /// Check if a file should be scanned (returns true if not scanned recently)
    ///
    /// This method:
    /// 1. Checks if the file was scanned within the time window
    /// 2. If yes, returns false (skip scan - already scanned recently)
    /// 3. If no, records the current time and returns true (proceed with scan)
    pub async fn should_scan(&self, path: &str) -> bool {
        let now = Instant::now();
        let mut scans = self.scans.write().await;

        // Check if file was scanned recently
        if let Some(last_scan) = scans.get(path) {
            if now.duration_since(*last_scan) < self.window {
                // Scanned recently - skip
                tracing::debug!("Skipping duplicate scan: {} (scanned {} seconds ago)",
                    path,
                    now.duration_since(*last_scan).as_secs_f32()
                );
                return false;
            }
        }

        // Not scanned recently - update timestamp and allow scan
        scans.insert(path.to_string(), now);

        // Clean up old entries (> 2x window) to prevent unbounded memory growth
        scans.retain(|_, &mut last_scan| {
            now.duration_since(last_scan) < self.window * 2
        });

        true
    }

    /// Get number of tracked files
    pub async fn tracked_count(&self) -> usize {
        self.scans.read().await.len()
    }

    /// Clear all tracked scans
    pub async fn clear(&self) {
        self.scans.write().await.clear();
    }
}

impl Default for ScanDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_deduplication() {
        let dedup = ScanDeduplicator::with_window(Duration::from_millis(100));

        // First scan should be allowed
        assert!(dedup.should_scan("/test/file.txt").await);

        // Immediate second scan should be blocked
        assert!(!dedup.should_scan("/test/file.txt").await);

        // After window expires, scan should be allowed again
        sleep(Duration::from_millis(150)).await;
        assert!(dedup.should_scan("/test/file.txt").await);
    }

    #[tokio::test]
    async fn test_different_files() {
        let dedup = ScanDeduplicator::new();

        // Different files should not interfere
        assert!(dedup.should_scan("/test/file1.txt").await);
        assert!(dedup.should_scan("/test/file2.txt").await);
        assert!(dedup.should_scan("/test/file3.txt").await);

        // But duplicates should be blocked
        assert!(!dedup.should_scan("/test/file1.txt").await);
        assert!(!dedup.should_scan("/test/file2.txt").await);
    }

    #[tokio::test]
    async fn test_cleanup() {
        let dedup = ScanDeduplicator::with_window(Duration::from_millis(50));

        // Scan multiple files
        for i in 0..10 {
            assert!(dedup.should_scan(&format!("/test/file{}.txt", i)).await);
        }

        assert_eq!(dedup.tracked_count().await, 10);

        // Wait for cleanup window (2x)
        sleep(Duration::from_millis(120)).await;

        // Trigger cleanup by scanning a new file
        assert!(dedup.should_scan("/test/new.txt").await);

        // Old entries should be cleaned up
        assert!(dedup.tracked_count().await < 10);
    }
}
