//! SIEM output integration.
//!
//! Provides optional output formats for detections:
//! - Syslog (RFC 5424-ish)
//! - CEF (Common Event Format)
//! - JSON (newline-delimited)

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::UdpSocket;

#[derive(Debug, Clone, Deserialize)]
pub struct SiemConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub output_format: OutputFormat,
    /// Optional syslog receiver (host:port).
    #[serde(default)]
    pub syslog_server: Option<String>,
    #[serde(default = "default_facility")]
    pub syslog_facility: u8,
    #[serde(default = "default_severity")]
    pub syslog_severity: u8,
}

fn default_facility() -> u8 {
    1 // USER
}

fn default_severity() -> u8 {
    4 // WARNING
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            output_format: OutputFormat::Json,
            syslog_server: None,
            syslog_facility: default_facility(),
            syslog_severity: default_severity(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Syslog,
    Cef,
    #[default]
    Json,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiemEvent {
    pub timestamp: DateTime<Utc>,
    pub event_id: String,
    pub severity: String,
    pub severity_num: u8,
    pub rule_id: String,
    pub rule_name: String,
    pub mitre_technique: String,
    pub mitre_tactic: String,
    pub description: String,
    pub hostname: String,
    pub process_pid: Option<u32>,
    pub process_cmdline: Option<String>,
}

pub struct SiemOutput {
    config: SiemConfig,
    socket: Option<UdpSocket>,
    hostname: String,
}

impl SiemOutput {
    pub fn new(config: SiemConfig) -> Self {
        let socket = if config.enabled && config.syslog_server.is_some() {
            UdpSocket::bind("0.0.0.0:0").ok()
        } else {
            None
        };

        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

        Self {
            config,
            socket,
            hostname,
        }
    }

    pub fn send_behavioral_alert(
        &self,
        alert: &crate::behavioral_pipeline::BehavioralAlert,
    ) -> Result<(), SiemError> {
        if !self.config.enabled {
            return Ok(());
        }

        let event = alert_to_siem_event(alert, &self.hostname);
        let message = match self.config.output_format {
            OutputFormat::Syslog => self.format_syslog(&event),
            OutputFormat::Cef => self.format_cef(&event),
            OutputFormat::Json => self.format_json(&event)?,
        };

        if let (Some(socket), Some(server)) = (&self.socket, &self.config.syslog_server) {
            socket
                .send_to(message.as_bytes(), server)
                .map_err(|e| SiemError::SendError(e.to_string()))?;
        }

        tracing::info!(target: "siem", "{}", message);
        Ok(())
    }

    fn format_syslog(&self, event: &SiemEvent) -> String {
        let pri = (self.config.syslog_facility * 8) + self.config.syslog_severity;
        let ts = event
            .timestamp
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        format!(
            "<{}>1 {} {} WinnCoreAV - - - {}",
            pri, ts, event.hostname, event.description
        )
    }

    fn format_cef(&self, event: &SiemEvent) -> String {
        let msg = event.description.replace('|', "\\|");
        let cmd = event
            .process_cmdline
            .as_deref()
            .unwrap_or("-")
            .replace('|', "\\|");
        format!(
            "CEF:0|WinnCore|WinnCoreAV|1.0|{}|{}|{}|rt={} cat={} cs1Label=MITRE_Technique cs1={} cs2Label=MITRE_Tactic cs2={} msg={} cs3Label=cmdline cs3={} spid={}",
            event.rule_id,
            event.rule_name,
            event.severity_num,
            event.timestamp.timestamp_millis(),
            event.mitre_tactic,
            event.mitre_technique,
            event.mitre_tactic,
            msg,
            cmd,
            event.process_pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string()),
        )
    }

    fn format_json(&self, event: &SiemEvent) -> Result<String, SiemError> {
        serde_json::to_string(event).map_err(|e| SiemError::SerializationError(e.to_string()))
    }
}

#[derive(Debug)]
pub enum SiemError {
    SendError(String),
    SerializationError(String),
}

impl std::fmt::Display for SiemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(e) => write!(f, "SIEM send error: {}", e),
            Self::SerializationError(e) => write!(f, "SIEM serialization error: {}", e),
        }
    }
}

impl std::error::Error for SiemError {}

fn severity_to_num(severity: &str) -> u8 {
    match severity.to_lowercase().as_str() {
        "critical" => 2,
        "high" => 3,
        "medium" => 4,
        "low" => 5,
        _ => 6,
    }
}

pub fn alert_to_siem_event(
    alert: &crate::behavioral_pipeline::BehavioralAlert,
    hostname: &str,
) -> SiemEvent {
    SiemEvent {
        timestamp: alert.timestamp,
        event_id: format!("{}-{}", alert.timestamp.timestamp_millis(), alert.pid),
        severity: alert.severity.clone(),
        severity_num: severity_to_num(&alert.severity),
        rule_id: alert.rule_id.clone(),
        rule_name: alert.name.clone(),
        mitre_technique: alert.technique.clone(),
        mitre_tactic: alert.tactic.clone(),
        description: alert.description.clone(),
        hostname: hostname.to_string(),
        process_pid: Some(alert.pid),
        process_cmdline: Some(alert.cmdline.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cef_format() {
        let config = SiemConfig {
            enabled: true,
            output_format: OutputFormat::Cef,
            ..Default::default()
        };

        let output = SiemOutput::new(config);
        let event = SiemEvent {
            timestamp: Utc::now(),
            event_id: "test-123".to_string(),
            severity: "high".to_string(),
            severity_num: 3,
            rule_id: "OBFUSC-001".to_string(),
            rule_name: "Base64 Encoded Command".to_string(),
            mitre_technique: "T1027".to_string(),
            mitre_tactic: "Defense Evasion".to_string(),
            description: "Detected base64 encoded command execution".to_string(),
            hostname: "testhost".to_string(),
            process_pid: Some(1234),
            process_cmdline: Some("echo aWQ= | base64 -d | bash".to_string()),
        };

        let cef = output.format_cef(&event);
        assert!(cef.starts_with("CEF:0|WinnCore|WinnCoreAV|1.0|"));
        assert!(cef.contains("OBFUSC-001"));
        assert!(cef.contains("T1027"));
    }

    #[test]
    fn test_json_format() {
        let config = SiemConfig {
            enabled: true,
            output_format: OutputFormat::Json,
            ..Default::default()
        };

        let output = SiemOutput::new(config);
        let event = SiemEvent {
            timestamp: Utc::now(),
            event_id: "test-456".to_string(),
            severity: "critical".to_string(),
            severity_num: 2,
            rule_id: "MINER-001".to_string(),
            rule_name: "Cryptocurrency Miner".to_string(),
            mitre_technique: "T1496".to_string(),
            mitre_tactic: "Impact".to_string(),
            description: "xmrig miner detected".to_string(),
            hostname: "testhost".to_string(),
            process_pid: Some(5678),
            process_cmdline: None,
        };

        let json = output.format_json(&event).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["rule_id"], "MINER-001");
        assert_eq!(parsed["mitre_technique"], "T1496");
    }
}
