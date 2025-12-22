//! Unified alert schema for WinnCoreAV
//!
//! Designed for SIEM compatibility with MITRE ATT&CK mapping,
//! CEF/LEEF/JSON output formats, and ECS compliance.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// Alert severity levels (aligned with CEF/syslog)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    /// CEF severity (0-10 scale)
    pub fn to_cef(self) -> u8 {
        match self {
            Severity::Info => 1,
            Severity::Low => 3,
            Severity::Medium => 5,
            Severity::High => 7,
            Severity::Critical => 10,
        }
    }

    /// Syslog severity (0-7, inverted)
    pub fn to_syslog(self) -> u8 {
        match self {
            Severity::Critical => 2, // Critical
            Severity::High => 3,     // Error
            Severity::Medium => 4,   // Warning
            Severity::Low => 5,      // Notice
            Severity::Info => 6,     // Info
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid severity: {0}")]
pub struct ParseSeverityError(String);

impl FromStr for Severity {
    type Err = ParseSeverityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "low" => Ok(Severity::Low),
            "medium" => Ok(Severity::Medium),
            "high" => Ok(Severity::High),
            "critical" => Ok(Severity::Critical),
            other => Err(ParseSeverityError(other.to_string())),
        }
    }
}

/// Detection source identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSource {
    Behavioral,
    MlClassifier,
    YaraSignature,
    Ebpf,
    Heuristic,
    ThreatIntel,
}

fn normalize_mitre_technique_id(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }

    let mut chars = raw.chars().peekable();
    let t = chars.next()?;
    if t != 'T' && t != 't' {
        return None;
    }

    let mut digits = String::with_capacity(4);
    for _ in 0..4 {
        let c = chars.next()?;
        if !c.is_ascii_digit() {
            return None;
        }
        digits.push(c);
    }

    if chars.peek().is_none() {
        return Some(format!("T{digits}"));
    }

    if chars.next()? != '.' {
        return None;
    }

    let mut sub = String::new();
    for c in chars {
        if !c.is_ascii_digit() {
            return None;
        }
        if sub.len() >= 3 {
            return None;
        }
        sub.push(c);
    }

    if sub.is_empty() {
        return None;
    }

    Some(format!("T{digits}.{:0>3}", sub))
}

/// MITRE ATT&CK mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String, // e.g., "T1059.004"
    pub technique_name: String,
    pub tactic: String,
    pub subtechnique: Option<String>,
}

impl MitreMapping {
    pub fn try_new(technique_id: &str) -> Option<Self> {
        let technique_id = normalize_mitre_technique_id(technique_id)?;

        // Lookup table for common techniques
        let (name, tactic) = match technique_id.as_str() {
            "T1059" => ("Command and Scripting Interpreter", "Execution"),
            "T1059.004" => ("Unix Shell", "Execution"),
            "T1055" => ("Process Injection", "Defense Evasion"),
            "T1055.008" => ("Ptrace System Calls", "Defense Evasion"),
            "T1071" => ("Application Layer Protocol", "Command and Control"),
            "T1071.001" => ("Web Protocols", "Command and Control"),
            "T1105" => ("Ingress Tool Transfer", "Command and Control"),
            "T1140" => ("Deobfuscate/Decode Files", "Defense Evasion"),
            "T1190" => ("Exploit Public-Facing Application", "Initial Access"),
            "T1543.002" => ("Systemd Service", "Persistence"),
            "T1547.006" => ("Kernel Modules and Extensions", "Persistence"),
            "T1552.001" => ("Credentials In Files", "Credential Access"),
            "T1571" => ("Non-Standard Port", "Command and Control"),
            "T1620" => ("Reflective Code Loading", "Defense Evasion"),
            _ => ("Unknown Technique", "Unknown"),
        };

        let subtechnique = technique_id
            .split('.')
            .nth(1)
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

        Some(Self {
            technique_id,
            technique_name: name.to_string(),
            tactic: tactic.to_string(),
            subtechnique,
        })
    }
}

/// Process context for the alert
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe_path: Option<String>,
    pub cmdline: Option<String>,
    pub username: Option<String>,
    pub uid: Option<u32>,
    pub cwd: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
}

/// File context for file-based alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    pub path: String,
    pub hash_sha256: Option<String>,
    pub hash_md5: Option<String>,
    pub size_bytes: Option<u64>,
    pub file_type: Option<String>,
    pub permissions: Option<String>,
}

/// Network context for network-based alerts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkContext {
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_ip: Option<IpAddr>,
    pub dst_port: Option<u16>,
    pub protocol: Option<String>,
    pub bytes_sent: Option<u64>,
    pub bytes_recv: Option<u64>,
}

/// Host context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostContext {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub arch: String,
    pub agent_version: String,
    pub agent_id: String,
}

/// Unified alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    // Core fields
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub confidence: f32, // 0.0 - 1.0

    // Detection info
    pub rule_id: String,
    pub rule_name: String,
    pub description: String,
    pub source: DetectionSource,
    pub mitre: Option<MitreMapping>,

    // Context
    pub host: HostContext,
    pub process: Option<ProcessContext>,
    pub file: Option<FileContext>,
    pub network: Option<NetworkContext>,

    // Response
    pub action_taken: Option<String>,
    pub quarantine_path: Option<String>,

    // Extensible fields
    pub tags: Vec<String>,
    pub custom_fields: HashMap<String, serde_json::Value>,

    // Raw evidence
    pub raw_event: Option<String>,
}

impl Alert {
    pub fn new(
        rule_id: &str,
        rule_name: &str,
        description: &str,
        severity: Severity,
        source: DetectionSource,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            severity,
            confidence: 1.0,
            rule_id: rule_id.to_string(),
            rule_name: rule_name.to_string(),
            description: description.to_string(),
            source,
            mitre: None,
            host: HostContext::current(),
            process: None,
            file: None,
            network: None,
            action_taken: None,
            quarantine_path: None,
            tags: Vec::new(),
            custom_fields: HashMap::new(),
            raw_event: None,
        }
    }

    pub fn with_mitre(mut self, technique_id: &str) -> Self {
        self.mitre = MitreMapping::try_new(technique_id);
        self
    }

    pub fn with_process(mut self, ctx: ProcessContext) -> Self {
        self.process = Some(ctx);
        self
    }

    #[allow(dead_code)]
    pub fn with_file(mut self, ctx: FileContext) -> Self {
        self.file = Some(ctx);
        self
    }

    #[allow(dead_code)]
    pub fn with_network(mut self, ctx: NetworkContext) -> Self {
        self.network = Some(ctx);
        self
    }
}

impl HostContext {
    pub fn current() -> Self {
        Self {
            hostname: hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            os_name: "Linux".to_string(),
            os_version: std::fs::read_to_string("/proc/version")
                .unwrap_or_default()
                .lines()
                .next()
                .unwrap_or("unknown")
                .to_string(),
            arch: std::env::consts::ARCH.to_string(),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            agent_id: machine_uid::get().unwrap_or_else(|_| "unknown".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mitre_ids() {
        assert_eq!(
            MitreMapping::try_new("T1059").unwrap().technique_id,
            "T1059"
        );
        assert_eq!(
            MitreMapping::try_new("t1059.4").unwrap().technique_id,
            "T1059.004"
        );
        assert!(MitreMapping::try_new("1059").is_none());
        assert!(MitreMapping::try_new("T105").is_none());
        assert!(MitreMapping::try_new("T1059.0004").is_none());
        assert!(MitreMapping::try_new("T1059.").is_none());
    }

    #[test]
    fn parses_severity() {
        assert_eq!("high".parse::<Severity>().unwrap(), Severity::High);
        assert!("urgent".parse::<Severity>().is_err());
    }
}
