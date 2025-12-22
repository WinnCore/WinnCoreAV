//! Syslog sender (RFC 5424 compliant)
//!
//! Supports UDP and TCP transports.

use super::{AlertFormatter, AlertSender, SiemError};
use crate::alert::Alert;
use async_trait::async_trait;
use chrono::SecondsFormat;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

pub struct SyslogSender {
    addr: SocketAddr,
    transport: SyslogTransport,
    formatter: Box<dyn AlertFormatter>,
    facility: u8,
    app_name: String,
}

#[derive(Clone)]
pub enum SyslogTransport {
    Udp,
    Tcp,
    TcpTls {
        #[allow(dead_code)]
        ca_cert: Option<String>,
    },
}

impl SyslogSender {
    pub fn new(
        addr: SocketAddr,
        transport: SyslogTransport,
        formatter: Box<dyn AlertFormatter>,
    ) -> Self {
        Self {
            addr,
            transport,
            formatter,
            facility: 1, // user-level messages
            app_name: "WinnCoreAV".to_string(),
        }
    }

    fn escape_sd_param_value(value: &str) -> String {
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(']', "\\]")
    }

    fn build_syslog_message(&self, alert: &Alert) -> String {
        // RFC 5424 format
        // <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG

        let pri = (self.facility * 8) + alert.severity.to_syslog();
        let timestamp = alert.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true);
        let hostname = &alert.host.hostname;
        let procid = std::process::id();
        let msgid = &alert.rule_id;

        // Structured data with MITRE info
        let sd = if let Some(ref mitre) = alert.mitre {
            format!(
                "[mitre@winncore technique=\"{}\" tactic=\"{}\" name=\"{}\"]",
                Self::escape_sd_param_value(&mitre.technique_id),
                Self::escape_sd_param_value(&mitre.tactic),
                Self::escape_sd_param_value(&mitre.technique_name),
            )
        } else {
            "-".to_string()
        };

        let msg = self.formatter.format(alert);

        format!(
            "<{}>{} {} {} {} {} {} {} {}",
            pri,
            1, // syslog version
            timestamp,
            hostname,
            self.app_name,
            procid,
            msgid,
            sd,
            msg
        )
    }
}

#[async_trait]
impl AlertSender for SyslogSender {
    async fn send(&self, alert: &Alert) -> Result<(), SiemError> {
        let message = self.build_syslog_message(alert);
        let bytes = message.as_bytes();

        match &self.transport {
            SyslogTransport::Udp => {
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|e| SiemError::Network(e.to_string()))?;
                socket
                    .send_to(bytes, self.addr)
                    .await
                    .map_err(|e| SiemError::Network(e.to_string()))?;
            }
            SyslogTransport::Tcp => {
                let mut stream = TcpStream::connect(self.addr)
                    .await
                    .map_err(|e| SiemError::Network(e.to_string()))?;

                // Syslog over TCP uses octet counting framing (RFC 6587).
                let framed = format!("{} {}", bytes.len(), message);
                stream
                    .write_all(framed.as_bytes())
                    .await
                    .map_err(|e| SiemError::Network(e.to_string()))?;
            }
            SyslogTransport::TcpTls { .. } => {
                // TLS implementation using tokio-rustls
                return Err(SiemError::Config("TLS not yet implemented".to_string()));
            }
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "syslog"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{Alert, DetectionSource, Severity};

    #[test]
    fn builds_rfc5424_message() {
        let sender = SyslogSender::new(
            "127.0.0.1:514".parse().unwrap(),
            SyslogTransport::Udp,
            Box::new(crate::siem::CefFormatter::new()),
        );

        let alert = Alert::new(
            "TEST-001",
            "Test Alert",
            "hello",
            Severity::Medium,
            DetectionSource::Heuristic,
        )
        .with_mitre("T1059.004");

        let msg = sender.build_syslog_message(&alert);
        assert!(msg.starts_with('<'));
        assert!(msg.contains("mitre@winncore"));
        assert!(msg.contains("CEF:0|"));
    }
}
