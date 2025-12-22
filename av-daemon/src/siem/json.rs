//! JSON output format (ECS-compatible)
//!
//! Outputs alerts in Elastic Common Schema format for
//! Splunk, Elastic, Loki, and modern SIEMs.

use super::AlertFormatter;
use crate::alert::Alert;
use serde_json::json;

pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl AlertFormatter for JsonFormatter {
    fn format(&self, alert: &Alert) -> String {
        // ECS-compatible JSON structure
        let ecs = json!({
            "@timestamp": alert.timestamp.to_rfc3339(),
            "event": {
                "id": &alert.id,
                "kind": "alert",
                "category": ["intrusion_detection"],
                "type": ["indicator"],
                "severity": alert.severity.to_cef(),
                "risk_score": (alert.confidence * 100.0) as u32,
                "outcome": "success",
                "action": &alert.action_taken,
                "reason": &alert.description,
            },
            "rule": {
                "id": &alert.rule_id,
                "name": &alert.rule_name,
                "description": &alert.description,
            },
            "threat": alert.mitre.as_ref().map(|m| json!({
                "framework": "MITRE ATT&CK",
                "technique": {
                    "id": &m.technique_id,
                    "name": &m.technique_name,
                },
                "tactic": {
                    "name": &m.tactic,
                },
            })),
            "host": {
                "hostname": &alert.host.hostname,
                "os": {
                    "name": &alert.host.os_name,
                    "version": &alert.host.os_version,
                },
                "architecture": &alert.host.arch,
            },
            "agent": {
                "name": "WinnCoreAV",
                "version": &alert.host.agent_version,
                "id": &alert.host.agent_id,
            },
            "process": alert.process.as_ref().map(|p| json!({
                "pid": p.pid,
                "parent": p.ppid.map(|ppid| json!({ "pid": ppid })),
                "name": &p.name,
                "executable": &p.exe_path,
                "command_line": &p.cmdline,
                "working_directory": &p.cwd,
                "user": {
                    "name": &p.username,
                    "id": p.uid.map(|u| u.to_string()),
                },
            })),
            "file": alert.file.as_ref().map(|f| json!({
                "path": &f.path,
                "hash": {
                    "sha256": &f.hash_sha256,
                    "md5": &f.hash_md5,
                },
                "size": &f.size_bytes,
                "type": &f.file_type,
            })),
            "source": alert.network.as_ref().and_then(|n| n.src_ip.map(|ip| json!({
                "ip": ip.to_string(),
                "port": n.src_port,
            }))),
            "destination": alert.network.as_ref().and_then(|n| n.dst_ip.map(|ip| json!({
                "ip": ip.to_string(),
                "port": n.dst_port,
            }))),
            "network": alert.network.as_ref().map(|n| json!({
                "protocol": &n.protocol,
                "bytes": n.bytes_sent.unwrap_or(0) + n.bytes_recv.unwrap_or(0),
            })),
            "tags": &alert.tags,
            "winncore": {
                "detection_source": format!("{:?}", alert.source),
                "confidence": alert.confidence,
                "quarantine_path": &alert.quarantine_path,
                "raw_event": &alert.raw_event,
                "custom_fields": &alert.custom_fields,
            },
        });

        if self.pretty {
            serde_json::to_string_pretty(&ecs).unwrap_or_default()
        } else {
            serde_json::to_string(&ecs).unwrap_or_default()
        }
    }
}

impl Default for JsonFormatter {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Alert, DetectionSource, Severity};

    #[test]
    fn test_json_format_is_valid() {
        let alert = Alert::new(
            "TEST-001",
            "Test Alert",
            "hello",
            Severity::Info,
            DetectionSource::Heuristic,
        )
        .with_mitre("T1059.004");

        let json = JsonFormatter::default().format(&alert);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["rule"]["id"], "TEST-001");
        assert_eq!(parsed["threat"]["technique"]["id"], "T1059.004");
    }
}

