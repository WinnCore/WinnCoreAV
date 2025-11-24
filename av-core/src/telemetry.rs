//! Telemetry - JSONL-only sink for SIEM ingestion.
//!
//! Honest scope:
//! - Single format (JSONL) for v1.
//! - No OTLP/CEF/Syslog here; add later if needed.
//! - Detection only: if sink fails, events are best-effort.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    #[serde(rename = "@timestamp")]
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub event_type: String,
    pub severity: String,
    pub host: HostInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<DetectionInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre: Option<MitreInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub agent_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionInfo {
    pub file_path: String,
    pub file_hash: String,
    pub detection_name: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cmdline: String,
    pub exe_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreInfo {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
}

#[async_trait]
pub trait TelemetrySink: Send + Sync {
    async fn send(&self, event: &TelemetryEvent) -> anyhow::Result<()>;
    async fn flush(&self) -> anyhow::Result<()>;
}

/// JSONL file sink.
pub struct JsonlFileSink {
    path: PathBuf,
    writer: tokio::sync::Mutex<std::io::BufWriter<std::fs::File>>,
    events_written: std::sync::atomic::AtomicU64,
}

impl JsonlFileSink {
    pub fn new(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        Ok(Self {
            path,
            writer: tokio::sync::Mutex::new(std::io::BufWriter::new(file)),
            events_written: std::sync::atomic::AtomicU64::new(0),
        })
    }

    pub fn events_written(&self) -> u64 {
        self.events_written
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

#[async_trait]
impl TelemetrySink for JsonlFileSink {
    async fn send(&self, event: &TelemetryEvent) -> anyhow::Result<()> {
        let line = serde_json::to_string(event)?;
        let mut writer = self.writer.lock().await;
        writeln!(writer, "{}", line)?;
        self.events_written
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> anyhow::Result<()> {
        let mut writer = self.writer.lock().await;
        writer.flush()?;
        Ok(())
    }
}

/// Host metadata cached per manager.
pub fn get_host_info() -> HostInfo {
    HostInfo {
        hostname: hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        ip: default_net::get_default_interface()
            .ok()
            .and_then(|iface| iface.ipv4.into_iter().next())
            .map(|ip| ip.addr.to_string()),
    }
}

/// Telemetry manager for a single sink.
pub struct TelemetryManager {
    sink: Arc<dyn TelemetrySink>,
    host_info: HostInfo,
}

impl TelemetryManager {
    pub fn new(sink: Arc<dyn TelemetrySink>) -> Self {
        Self {
            sink,
            host_info: get_host_info(),
        }
    }

    pub async fn send(&self, mut event: TelemetryEvent) -> anyhow::Result<()> {
        event.host = self.host_info.clone();
        self.sink.send(&event).await
    }

    pub async fn flush(&self) -> anyhow::Result<()> {
        self.sink.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn jsonl_sink_writes_and_parses() {
        let temp = NamedTempFile::new().unwrap();
        let sink = JsonlFileSink::new(temp.path()).unwrap();
        let event = TelemetryEvent {
            timestamp: chrono::Utc::now(),
            event_type: "test".into(),
            severity: "info".into(),
            host: get_host_info(),
            detection: None,
            process: None,
            mitre: None,
        };
        sink.send(&event).await.unwrap();
        sink.flush().await.unwrap();
        assert_eq!(sink.events_written(), 1);
        let content = std::fs::read_to_string(temp.path()).unwrap();
        let parsed: TelemetryEvent = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed.event_type, "test");
    }
}
