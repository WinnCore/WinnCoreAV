//! CEF (Common Event Format) output for ArcSight, QRadar, etc.
//!
//! Format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension

use super::AlertFormatter;
use crate::alert::Alert;

pub struct CefFormatter {
    vendor: String,
    product: String,
    version: String,
}

impl CefFormatter {
    pub fn new() -> Self {
        Self {
            vendor: "WinnCore".to_string(),
            product: "WinnCoreAV".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Escape CEF special characters
    fn escape_cef(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('|', "\\|")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }

    /// Escape extension field values
    fn escape_extension(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('=', "\\=")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
    }
}

impl AlertFormatter for CefFormatter {
    fn format(&self, alert: &Alert) -> String {
        let mut extensions = Vec::new();

        // Standard CEF fields
        extensions.push(format!("rt={}", alert.timestamp.timestamp_millis()));
        extensions.push(format!("cat={:?}", alert.source));
        extensions.push("outcome=success".to_string());
        extensions.push(format!(
            "reason={}",
            Self::escape_extension(&alert.description)
        ));

        // Host info
        extensions.push(format!(
            "dhost={}",
            Self::escape_extension(&alert.host.hostname)
        ));
        extensions.push(format!(
            "deviceExternalId={}",
            Self::escape_extension(&alert.host.agent_id)
        ));

        // Process info
        if let Some(ref proc_ctx) = alert.process {
            extensions.push(format!(
                "dproc={}",
                Self::escape_extension(&proc_ctx.name)
            ));
            extensions.push(format!("dpid={}", proc_ctx.pid));
            if let Some(ref exe) = proc_ctx.exe_path {
                extensions.push(format!("filePath={}", Self::escape_extension(exe)));
            }
            if let Some(ref cmdline) = proc_ctx.cmdline {
                extensions.push(format!("cs1={}", Self::escape_extension(cmdline)));
                extensions.push("cs1Label=CommandLine".to_string());
            }
            if let Some(ref user) = proc_ctx.username {
                extensions.push(format!("duser={}", Self::escape_extension(user)));
            }
        }

        // File info
        if let Some(ref file) = alert.file {
            extensions.push(format!("fname={}", Self::escape_extension(&file.path)));
            if let Some(ref hash) = file.hash_sha256 {
                extensions.push(format!("fileHash={}", hash));
            }
            if let Some(size) = file.size_bytes {
                extensions.push(format!("fsize={}", size));
            }
        }

        // Network info
        if let Some(ref net) = alert.network {
            if let Some(src) = net.src_ip {
                extensions.push(format!("src={}", src));
            }
            if let Some(port) = net.src_port {
                extensions.push(format!("spt={}", port));
            }
            if let Some(dst) = net.dst_ip {
                extensions.push(format!("dst={}", dst));
            }
            if let Some(port) = net.dst_port {
                extensions.push(format!("dpt={}", port));
            }
            if let Some(ref proto) = net.protocol {
                extensions.push(format!("proto={}", proto));
            }
        }

        // MITRE ATT&CK mapping
        if let Some(ref mitre) = alert.mitre {
            extensions.push(format!("cs2={}", mitre.technique_id));
            extensions.push("cs2Label=MitreTechniqueId".to_string());
            extensions.push(format!(
                "cs3={}",
                Self::escape_extension(&mitre.technique_name)
            ));
            extensions.push("cs3Label=MitreTechniqueName".to_string());
            extensions.push(format!("cs4={}", Self::escape_extension(&mitre.tactic)));
            extensions.push("cs4Label=MitreTactic".to_string());
        }

        // Action taken
        if let Some(ref action) = alert.action_taken {
            extensions.push(format!("act={}", Self::escape_extension(action)));
        }

        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            Self::escape_cef(&self.vendor),
            Self::escape_cef(&self.product),
            Self::escape_cef(&self.version),
            Self::escape_cef(&alert.rule_id),
            Self::escape_cef(&alert.rule_name),
            alert.severity.to_cef(),
            extensions.join(" ")
        )
    }
}

impl Default for CefFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Alert, DetectionSource, Severity};

    #[test]
    fn test_cef_format() {
        let alert = Alert::new(
            "OBFUSC-001",
            "Base64 Encoded Command",
            "Detected base64 encoded command execution",
            Severity::High,
            DetectionSource::Behavioral,
        )
        .with_mitre("T1027");

        let cef = CefFormatter::new().format(&alert);
        assert!(cef.starts_with("CEF:0|WinnCore|WinnCoreAV|"));
        assert!(cef.contains("|OBFUSC-001|"));
        assert!(cef.contains("cs2=T1027"));
    }
}

