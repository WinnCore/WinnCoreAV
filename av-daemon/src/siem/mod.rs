//! SIEM integration module
//!
//! Provides multiple output formats and transport mechanisms
//! for enterprise security integration.

pub mod cef;
pub mod file;
pub mod json;
pub mod leef;
pub mod router;
pub mod syslog;
pub mod webhook;

pub use cef::CefFormatter;
pub use file::FileAlertSender;
pub use json::JsonFormatter;
pub use leef::LeefFormatter;
pub use router::{AlertRouter, RouteConfig};
pub use syslog::{SyslogSender, SyslogTransport};
pub use webhook::{BatchingWebhookSender, WebhookAuth, WebhookSender};

use crate::alert::Alert;
use async_trait::async_trait;
use serde::Deserialize;
use std::path::PathBuf;

use crate::alert::Severity;

#[derive(Debug, Clone, Deserialize)]
pub struct SiemConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub local_log: bool,
    /// Optional path used for last-resort buffering (JSON lines).
    #[serde(default)]
    pub buffer_path: Option<PathBuf>,
    #[serde(default)]
    pub outputs: Vec<SiemOutputConfig>,
}

fn default_true() -> bool {
    true
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local_log: true,
            buffer_path: None,
            outputs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SiemOutputConfig {
    #[serde(rename = "type")]
    pub output_type: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,

    // Common
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default = "default_min_severity")]
    pub min_severity: Severity,
    #[serde(default)]
    pub rule_ids: Option<Vec<String>>,

    // Syslog
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,

    // Webhook
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub auth_type: Option<String>,
    #[serde(default)]
    pub auth_token: Option<String>,
    #[serde(default)]
    pub auth_username: Option<String>,
    #[serde(default)]
    pub auth_password: Option<String>,
    #[serde(default)]
    pub header_name: Option<String>,
    #[serde(default)]
    pub header_value: Option<String>,
    #[serde(default)]
    pub batch_size: Option<usize>,
    #[serde(default)]
    pub batch_timeout_secs: Option<u64>,

    // File
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub rotate_size_mb: Option<u64>,
    #[serde(default)]
    pub rotate_keep: Option<usize>,
}

fn default_min_severity() -> Severity {
    Severity::Low
}

impl SiemConfig {
    pub fn resolve_env(&mut self) {
        for output in &mut self.outputs {
            output.auth_token = output.auth_token.as_ref().map(|s| expand_env(s));
            output.auth_password = output.auth_password.as_ref().map(|s| expand_env(s));
            output.header_value = output.header_value.as_ref().map(|s| expand_env(s));
            output.url = output.url.as_ref().map(|s| expand_env(s));
            output.address = output.address.as_ref().map(|s| expand_env(s));
        }
    }
}

fn expand_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            out.push_str(&rest[start..]);
            return out;
        };

        let var = &after[..end];
        out.push_str(&std::env::var(var).unwrap_or_default());
        rest = &after[end + 1..];
    }

    out.push_str(rest);
    out
}

/// Output format for alerts
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub enum OutputFormat {
    Json,
    JsonPretty,
    Cef,
    Leef,
    SyslogRfc5424,
}

/// Trait for formatting alerts
pub trait AlertFormatter: Send + Sync {
    fn format(&self, alert: &Alert) -> String;
}

/// Trait for sending alerts
#[async_trait]
pub trait AlertSender: Send + Sync {
    async fn send(&self, alert: &Alert) -> Result<(), SiemError>;
    fn name(&self) -> &str;
}

#[derive(Debug, thiserror::Error)]
pub enum SiemError {
    #[error("Network error: {0}")]
    Network(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Format error: {0}")]
    Format(String),
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Timeout")]
    #[allow(dead_code)]
    Timeout,
}

impl From<std::io::Error> for SiemError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}
