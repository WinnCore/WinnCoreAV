//! LEEF (Log Event Extended Format) output for QRadar native integration.
//!
//! Format: LEEF:2.0|Vendor|Product|Version|EventID|key=value\tkey=value...

use super::AlertFormatter;
use crate::alert::Alert;

pub struct LeefFormatter {
    vendor: String,
    product: String,
    version: String,
}

impl LeefFormatter {
    pub fn new() -> Self {
        Self {
            vendor: "WinnCore".to_string(),
            product: "WinnCoreAV".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    fn escape_value(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\t', "\\t")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }
}

impl AlertFormatter for LeefFormatter {
    fn format(&self, alert: &Alert) -> String {
        let mut fields = Vec::new();

        fields.push(format!("devTime={}", alert.timestamp.timestamp_millis()));
        fields.push(format!("sev={}", alert.severity.to_cef()));
        fields.push(format!("cat={:?}", alert.source));
        fields.push(format!("msg={}", Self::escape_value(&alert.description)));

        fields.push(format!(
            "hostName={}",
            Self::escape_value(&alert.host.hostname)
        ));
        fields.push(format!(
            "agentId={}",
            Self::escape_value(&alert.host.agent_id)
        ));

        if let Some(ref mitre) = alert.mitre {
            fields.push(format!(
                "mitreTechnique={}",
                Self::escape_value(&mitre.technique_id)
            ));
            fields.push(format!("mitreTactic={}", Self::escape_value(&mitre.tactic)));
        }

        if let Some(ref proc_ctx) = alert.process {
            fields.push(format!("pid={}", proc_ctx.pid));
            fields.push(format!(
                "processName={}",
                Self::escape_value(&proc_ctx.name)
            ));
            if let Some(ref cmdline) = proc_ctx.cmdline {
                fields.push(format!("commandLine={}", Self::escape_value(cmdline)));
            }
        }

        if let Some(ref file) = alert.file {
            fields.push(format!("filePath={}", Self::escape_value(&file.path)));
            if let Some(ref sha) = file.hash_sha256 {
                fields.push(format!("sha256={}", Self::escape_value(sha)));
            }
        }

        if let Some(ref net) = alert.network {
            if let Some(src) = net.src_ip {
                fields.push(format!("src={}", src));
            }
            if let Some(spt) = net.src_port {
                fields.push(format!("srcPort={}", spt));
            }
            if let Some(dst) = net.dst_ip {
                fields.push(format!("dst={}", dst));
            }
            if let Some(dpt) = net.dst_port {
                fields.push(format!("dstPort={}", dpt));
            }
            if let Some(ref proto) = net.protocol {
                fields.push(format!("proto={}", Self::escape_value(proto)));
            }
        }

        format!(
            "LEEF:2.0|{}|{}|{}|{}|\t{}",
            Self::escape_value(&self.vendor),
            Self::escape_value(&self.product),
            Self::escape_value(&self.version),
            Self::escape_value(&alert.rule_id),
            fields.join("\t")
        )
    }
}

impl Default for LeefFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Alert, DetectionSource, Severity};

    #[test]
    fn test_leef_format() {
        let alert = Alert::new(
            "TEST-LEEF",
            "Leef Alert",
            "hello",
            Severity::Low,
            DetectionSource::Behavioral,
        );

        let msg = LeefFormatter::new().format(&alert);
        assert!(msg.starts_with("LEEF:2.0|WinnCore|WinnCoreAV|"));
        assert!(msg.contains("|TEST-LEEF|"));
        assert!(msg.contains("msg=hello"));
    }
}
