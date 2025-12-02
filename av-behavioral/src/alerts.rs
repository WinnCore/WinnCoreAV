use std::time::SystemTime;

use serde::Serialize;

use crate::{correlation::AttackChain, rules::RuleMatch};
use av_ebpf_common::EventType;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub id: String,
    pub timestamp: SystemTime,
    pub severity: AlertSeverity,
    pub title: String,
    pub description: String,
    pub pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<EventType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_tactic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitre_technique: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    pub details: serde_json::Value,
}

impl Alert {
    /// Create alert from a single rule match.
    pub fn from_rule_match(rule_match: &RuleMatch) -> Self {
        let rule = &rule_match.rule;

        Self {
            id: format!("{}-{}-{}", rule.id, rule_match.pid, rule_match.timestamp_ns),
            timestamp: SystemTime::now(),
            severity: match rule.severity {
                crate::rules::Severity::Low => AlertSeverity::Low,
                crate::rules::Severity::Medium => AlertSeverity::Medium,
                crate::rules::Severity::High => AlertSeverity::High,
                crate::rules::Severity::Critical => AlertSeverity::Critical,
            },
            title: rule.name.clone(),
            description: rule.description.clone(),
            pid: rule_match.pid,
            rule_id: Some(rule.id.clone()),
            event_type: Some(rule_match.event_type),
            mitre_tactic: rule.mitre.as_ref().map(|m| m.tactic.clone()),
            mitre_technique: rule.mitre.as_ref().map(|m| m.technique.clone()),
            comm: rule_match.comm.clone(),
            cmdline: rule_match.cmdline.clone(),
            details: serde_json::json!({
                "matched_fields": rule_match.matched_fields,
                "tags": rule.tags,
            }),
        }
    }

    /// Create alert from a completed attack chain.
    pub fn from_attack_chain(chain: &AttackChain) -> Self {
        Self {
            id: chain.id.clone(),
            timestamp: SystemTime::now(),
            severity: chain.severity,
            title: format!("Attack Chain Detected: {}", chain.narrative),
            description: format!(
                "Correlated {} events indicating possible attack: {}",
                chain.events.len(),
                chain.narrative
            ),
            pid: chain.primary_pid,
            rule_id: None,
            event_type: None,
            mitre_tactic: chain.tactics.first().cloned(),
            mitre_technique: None,
            comm: None,
            cmdline: None,
            details: serde_json::json!({
                "events": chain.events.iter().map(|e| {
                    serde_json::json!({
                        "rule": e.rule_match.rule.id,
                        "matched": e.rule_match.matched_fields,
                    })
                }).collect::<Vec<_>>(),
            }),
        }
    }
}
