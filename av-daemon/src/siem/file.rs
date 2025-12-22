//! File sender (JSON Lines)
//!
//! Appends formatted alerts to a local file for log aggregation and forensics.

use super::{AlertFormatter, AlertSender, SiemError};
use crate::alert::Alert;
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::debug;

pub struct FileAlertSender {
    name: String,
    path: PathBuf,
    formatter: Box<dyn AlertFormatter>,
    rotate_size_bytes: Option<u64>,
    rotate_keep: usize,
    write_lock: Mutex<()>,
}

impl FileAlertSender {
    pub fn new(path: PathBuf, formatter: Box<dyn AlertFormatter>) -> Self {
        Self {
            name: "file".to_string(),
            path,
            formatter,
            rotate_size_bytes: None,
            rotate_keep: 0,
            write_lock: Mutex::new(()),
        }
    }

    pub fn with_rotation(mut self, rotate_size_bytes: Option<u64>, rotate_keep: usize) -> Self {
        self.rotate_size_bytes = rotate_size_bytes.filter(|s| *s > 0);
        self.rotate_keep = rotate_keep;
        self
    }

    fn rotated_path(path: &Path, idx: usize) -> PathBuf {
        PathBuf::from(format!("{}.{}", path.display(), idx))
    }

    async fn rotate_if_needed(&self, next_write_len: u64) -> Result<(), SiemError> {
        let Some(limit) = self.rotate_size_bytes else {
            return Ok(());
        };

        let current_len = match tokio::fs::metadata(&self.path).await {
            Ok(meta) => meta.len(),
            Err(_) => 0,
        };

        if current_len.saturating_add(next_write_len) < limit {
            return Ok(());
        }

        if self.rotate_keep == 0 {
            // Best-effort truncate when rotation is disabled.
            let _ = tokio::fs::write(&self.path, b"").await;
            return Ok(());
        }

        // Remove oldest.
        let oldest = Self::rotated_path(&self.path, self.rotate_keep);
        let _ = tokio::fs::remove_file(&oldest).await;

        // Shift existing.
        for idx in (1..self.rotate_keep).rev() {
            let src = Self::rotated_path(&self.path, idx);
            let dst = Self::rotated_path(&self.path, idx + 1);
            if tokio::fs::metadata(&src).await.is_ok() {
                let _ = tokio::fs::rename(&src, &dst).await;
            }
        }

        // Rotate current.
        if tokio::fs::metadata(&self.path).await.is_ok() {
            let dst = Self::rotated_path(&self.path, 1);
            let _ = tokio::fs::rename(&self.path, dst).await;
        }

        Ok(())
    }
}

#[async_trait]
impl AlertSender for FileAlertSender {
    async fn send(&self, alert: &Alert) -> Result<(), SiemError> {
        let mut line = self.formatter.format(alert);
        if !line.ends_with('\n') {
            line.push('\n');
        }

        // Serialize writes + rotation.
        let _guard = self.write_lock.lock().await;

        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        self.rotate_if_needed(line.len() as u64).await?;

        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;

        file.write_all(line.as_bytes()).await?;
        debug!(file = %self.path.display(), "Alert appended");
        Ok(())
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{DetectionSource, Severity};
    use crate::siem::JsonFormatter;

    #[tokio::test]
    async fn writes_jsonl_line() {
        let tmp = std::env::temp_dir().join(format!("winncore-alerts-{}.jsonl", uuid::Uuid::new_v4()));
        let sender = FileAlertSender::new(tmp.clone(), Box::new(JsonFormatter::default()));

        let alert = Alert::new(
            "TEST-001",
            "Test Alert",
            "hello",
            Severity::Info,
            DetectionSource::Heuristic,
        );

        sender.send(&alert).await.unwrap();
        let contents = tokio::fs::read_to_string(&tmp).await.unwrap();
        assert!(contents.ends_with('\n'));

        let _ = tokio::fs::remove_file(&tmp).await;
    }
}

