//! High-fidelity detection rules based on MITRE ATT&CK.
//!
//! Detection quality hierarchy (lowest to highest):
//! None → Telemetry → General → Tactic → Technique
//!
//! All rules in this module aim for technique-level detection.

pub mod command_and_control;
pub mod credential_access;
pub mod defense_evasion;
pub mod exfiltration;
pub mod fileless;
pub mod lateral_movement;
pub mod persistence;
pub mod privilege_escalation;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// MITRE ATT&CK technique mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitreMapping {
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub sub_technique: Option<String>,
    pub platforms: Vec<String>,
    pub data_sources: Vec<String>,
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

impl MitreMapping {
    pub fn new(technique_id: &str) -> Self {
        let normalized = normalize_mitre_technique_id(technique_id);
        let key = normalized.as_deref().unwrap_or(technique_id);

        MITRE_LOOKUP.get(key).cloned().unwrap_or_else(|| Self {
            technique_id: normalized.unwrap_or_else(|| technique_id.to_string()),
            technique_name: "Unknown".to_string(),
            tactic: "Unknown".to_string(),
            sub_technique: None,
            platforms: vec!["Linux".to_string()],
            data_sources: vec![],
        })
    }
}

lazy_static::lazy_static! {
    static ref MITRE_LOOKUP: HashMap<&'static str, MitreMapping> = {
        let mut m = HashMap::new();

        // Execution
        m.insert("T1059.004", MitreMapping {
            technique_id: "T1059.004".to_string(),
            technique_name: "Unix Shell".to_string(),
            tactic: "Execution".to_string(),
            sub_technique: Some("004".to_string()),
            platforms: vec!["Linux".to_string(), "macOS".to_string()],
            data_sources: vec!["Command".to_string(), "Process".to_string()],
        });

        // Defense Evasion
        m.insert("T1620", MitreMapping {
            technique_id: "T1620".to_string(),
            technique_name: "Reflective Code Loading".to_string(),
            tactic: "Defense Evasion".to_string(),
            sub_technique: None,
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["Module".to_string(), "Process".to_string()],
        });

        m.insert("T1055.008", MitreMapping {
            technique_id: "T1055.008".to_string(),
            technique_name: "Ptrace System Calls".to_string(),
            tactic: "Defense Evasion".to_string(),
            sub_technique: Some("008".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["Process".to_string()],
        });

        m.insert("T1574.006", MitreMapping {
            technique_id: "T1574.006".to_string(),
            technique_name: "Dynamic Linker Hijacking".to_string(),
            tactic: "Defense Evasion".to_string(),
            sub_technique: Some("006".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["File".to_string(), "Process".to_string()],
        });

        // Persistence
        m.insert("T1053.003", MitreMapping {
            technique_id: "T1053.003".to_string(),
            technique_name: "Cron".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("003".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["File".to_string(), "Command".to_string()],
        });

        m.insert("T1543.002", MitreMapping {
            technique_id: "T1543.002".to_string(),
            technique_name: "Systemd Service".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("002".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["File".to_string(), "Service".to_string()],
        });

        m.insert("T1547.006", MitreMapping {
            technique_id: "T1547.006".to_string(),
            technique_name: "Kernel Modules and Extensions".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("006".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["Module".to_string(), "Process".to_string()],
        });

        m.insert("T1098.004", MitreMapping {
            technique_id: "T1098.004".to_string(),
            technique_name: "SSH Authorized Keys".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("004".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["File".to_string()],
        });

        m.insert("T1546.004", MitreMapping {
            technique_id: "T1546.004".to_string(),
            technique_name: "Unix Shell Configuration Modification".to_string(),
            tactic: "Persistence".to_string(),
            sub_technique: Some("004".to_string()),
            platforms: vec!["Linux".to_string(), "macOS".to_string()],
            data_sources: vec!["File".to_string()],
        });

        // Command and Control
        m.insert("T1571", MitreMapping {
            technique_id: "T1571".to_string(),
            technique_name: "Non-Standard Port".to_string(),
            tactic: "Command and Control".to_string(),
            sub_technique: None,
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["Network Traffic".to_string()],
        });

        m.insert("T1090.003", MitreMapping {
            technique_id: "T1090.003".to_string(),
            technique_name: "Multi-hop Proxy: Tor".to_string(),
            tactic: "Command and Control".to_string(),
            sub_technique: Some("003".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["Network Traffic".to_string()],
        });

        // Credential Access
        m.insert("T1552.001", MitreMapping {
            technique_id: "T1552.001".to_string(),
            technique_name: "Credentials In Files".to_string(),
            tactic: "Credential Access".to_string(),
            sub_technique: Some("001".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["File".to_string(), "Command".to_string()],
        });

        // Privilege Escalation
        m.insert("T1548.001", MitreMapping {
            technique_id: "T1548.001".to_string(),
            technique_name: "Setuid and Setgid".to_string(),
            tactic: "Privilege Escalation".to_string(),
            sub_technique: Some("001".to_string()),
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["File".to_string(), "Process".to_string()],
        });

        // Impact / Resource Hijacking
        m.insert("T1496", MitreMapping {
            technique_id: "T1496".to_string(),
            technique_name: "Resource Hijacking".to_string(),
            tactic: "Impact".to_string(),
            sub_technique: None,
            platforms: vec!["Linux".to_string()],
            data_sources: vec!["Network Traffic".to_string(), "Process".to_string()],
        });

        m
    };
}

/// Detection confidence level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Confidence {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Severity levels aligned with a simple CVSS-like scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Detection rule definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub mitre: MitreMapping,
    pub false_positive_notes: Vec<String>,
    pub references: Vec<String>,
}
