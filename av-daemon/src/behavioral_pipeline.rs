use crate::heuristics::HeuristicAnalyzer;
use crate::response::ResponseEngine;
use av_behavioral::detection::{
    command_and_control as det_c2, fileless as det_fileless, persistence as det_persistence,
};
use av_behavioral::rules::{
    check_cmdline_injection, check_container_escape_cmd, check_webshell_spawn, detect_cryptominer,
    detect_log_tampering, detect_obfuscation, detect_rootkit_command, AntiForensicsSeverity,
    CryptoMinerSeverity, ObfuscationType, RootkitSeverity, Rule, RuleEngine, RuleMatch, Severity,
    WebShellSeverity,
};
use av_behavioral::Allowlist;
use av_ebpf_common::{
    FileAccessEvent, FileAccessType, KernelModuleEvent, NetworkConnectEvent, ProcessExecEvent,
    PtraceEvent,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

const DEFAULT_ALERT_LOG: &str = "/var/log/winncore/alerts.json";

#[derive(Debug, Clone, Serialize)]
pub struct BehavioralAlert {
    pub rule_id: String,
    pub name: String,
    pub severity: String,
    pub technique: String,
    pub tactic: String,
    pub pid: u32,
    pub ppid: u32,
    pub cmdline: String,
    pub description: String,
    pub timestamp: DateTime<Utc>,
    pub matched: Vec<String>,
    pub source: String,
}

#[derive(Debug)]
pub enum BehavioralEvent {
    ProcessExec(ProcessExecEvent),
    /// Process execution observed via eBPF (kernel trace).
    #[allow(dead_code)]
    ProcessExecEbpf(ProcessExecEvent),
    #[allow(dead_code)]
    NetworkConnect(NetworkConnectEvent),
    #[allow(dead_code)]
    FileAccess(FileAccessEvent),
    #[allow(dead_code)]
    Ptrace(PtraceEvent),
    #[allow(dead_code)]
    KernelModule(KernelModuleEvent),
    /// Periodic eBPF program integrity/rootkit signal (from av-ebpf-detect).
    EbpfProgramThreat {
        severity: String,
        description: String,
    },
}

pub struct BehavioralRuntime {
    pub event_tx: mpsc::Sender<BehavioralEvent>,
    pub alert_rx: mpsc::Receiver<BehavioralAlert>,
}

#[derive(Debug, Clone)]
pub struct BehavioralConfig {
    pub response: crate::config::ResponseConfig,
    pub external_rules_dir: Option<PathBuf>,
    pub alert_log_path: PathBuf,
}

impl Default for BehavioralConfig {
    fn default() -> Self {
        Self {
            response: crate::config::ResponseConfig::default(),
            external_rules_dir: Some(PathBuf::from("/etc/winncore/rules")),
            alert_log_path: PathBuf::from(DEFAULT_ALERT_LOG),
        }
    }
}

pub struct BehavioralPipeline {
    engine: RuleEngine,
    heuristics: HeuristicAnalyzer,
    response: ResponseEngine,
    config: BehavioralConfig,
    allowlist: Allowlist,
    system_ld_so_preload_alerted: bool,
}

struct SyntheticAlertTemplate<'a> {
    rule_id: &'a str,
    name: &'a str,
    severity: &'a str,
    technique: &'a str,
    tactic: &'a str,
    description: &'a str,
    source: &'a str,
}

struct EbpfAlertTemplate<'a> {
    rule_id: &'a str,
    name: &'a str,
    severity: &'a str,
    technique: &'a str,
    tactic: &'a str,
}

struct EbpfAlertData {
    pid: u32,
    ppid: u32,
    cmdline: String,
    description: String,
}

struct DetectionAlertData {
    pid: u32,
    ppid: u32,
    cmdline: String,
    matched: Vec<String>,
    source: &'static str,
}

impl BehavioralPipeline {
    pub async fn new(config: BehavioralConfig) -> anyhow::Result<Self> {
        let mut engine = RuleEngine::new();
        let rules = load_rules(&config).await?;
        engine.load_rules(rules);

        Ok(BehavioralPipeline {
            engine,
            heuristics: HeuristicAnalyzer::new(),
            response: ResponseEngine::new(config.response.clone()),
            config,
            allowlist: Allowlist::new(),
            system_ld_so_preload_alerted: false,
        })
    }

    pub async fn handle_event(
        &mut self,
        event: BehavioralEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        match event {
            BehavioralEvent::ProcessExec(proc_evt) => {
                self.handle_process_exec(proc_evt, alert_tx).await;
            }
            BehavioralEvent::ProcessExecEbpf(proc_evt) => {
                self.handle_process_exec(proc_evt, alert_tx).await;
                self.handle_ebpf_exec_detections(proc_evt, alert_tx).await;
            }
            BehavioralEvent::NetworkConnect(net_evt) => {
                self.handle_network_connect(net_evt, alert_tx).await;
            }
            BehavioralEvent::FileAccess(file_evt) => {
                self.handle_file_access(file_evt, alert_tx).await;
            }
            BehavioralEvent::Ptrace(ptrace_evt) => {
                self.handle_ptrace(ptrace_evt, alert_tx).await;
            }
            BehavioralEvent::KernelModule(km_evt) => {
                self.handle_kernel_module(km_evt, alert_tx).await;
            }
            BehavioralEvent::EbpfProgramThreat {
                severity,
                description,
            } => {
                self.emit_ebpf_alert(
                    EbpfAlertTemplate {
                        rule_id: "EBPF-900",
                        name: "Suspicious eBPF Program Activity",
                        severity: &severity,
                        technique: "T1014",
                        tactic: "Defense Evasion",
                    },
                    EbpfAlertData {
                        pid: 0,
                        ppid: 0,
                        cmdline: String::new(),
                        description,
                    },
                    alert_tx,
                )
                .await;
            }
        }
    }

    async fn handle_process_exec(
        &mut self,
        event: ProcessExecEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let cmdline = event.args_str().to_string();
        let parent_comm = read_proc_comm(event.ppid).await;

        let exe = Path::new(event.filename_str());
        let exe_opt = (!event.filename_str().is_empty()).then_some(exe);

        if self.allowlist.should_suppress(
            exe_opt,
            parent_comm.as_deref(),
            event.comm_str(),
            &cmdline,
        ) {
            return;
        }

        let heur = self.heuristics.analyze(event.ppid, &cmdline);
        if heur.is_suspicious() {
            let severity = if heur.is_critical() { "high" } else { "medium" };
            let alert = BehavioralAlert {
                rule_id: "heuristics".to_string(),
                name: "Heuristic anomaly".to_string(),
                severity: severity.to_string(),
                technique: "T1027".to_string(),
                tactic: "Defense Evasion".to_string(),
                pid: event.pid,
                ppid: event.ppid,
                cmdline: cmdline.clone(),
                description: format!(
                    "Heuristic indicators: entropy={}, rapid_spawn={}, patterns={:?}",
                    heur.high_entropy, heur.rapid_spawn, heur.suspicious_patterns
                ),
                timestamp: Utc::now(),
                matched: Vec::new(),
                source: "heuristic".to_string(),
            };
            if let Err(e) = alert_tx.send(alert).await {
                warn!(error = %e, "Failed to send heuristic alert");
            }
        }

        let matches = self.engine.evaluate_process(&event);
        let mut matched_rule_ids: HashSet<String> = HashSet::with_capacity(matches.len());
        for m in matches {
            matched_rule_ids.insert(m.rule.id.clone());
            self.emit_rule_alert(&event, &cmdline, m, alert_tx).await;
        }

        self.emit_detector_alerts(
            &event,
            &cmdline,
            parent_comm.as_deref(),
            &matched_rule_ids,
            alert_tx,
        )
        .await;
    }

    async fn emit_rule_alert(
        &self,
        event: &ProcessExecEvent,
        cmdline: &str,
        rule_match: RuleMatch,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let rule = rule_match.rule;
        let severity_str = severity_to_str(&rule.severity).to_string();
        let alert = BehavioralAlert {
            rule_id: rule.id.clone(),
            name: rule.name.clone(),
            severity: severity_str.clone(),
            technique: rule.technique.clone(),
            tactic: rule.tactic.clone(),
            pid: event.pid,
            ppid: event.ppid,
            cmdline: cmdline.to_string(),
            description: rule.description.clone(),
            timestamp: Utc::now(),
            matched: [rule_match.matched_any, rule_match.matched_all].concat(),
            source: "rule".to_string(),
        };

        if let Err(e) = alert_tx.send(alert.clone()).await {
            warn!(error = %e, "Failed to enqueue alert");
        }

        if let Err(e) = persist_alert_line(&self.config.alert_log_path, &alert).await {
            error!(error = %e, "Failed to persist alert log");
        }

        self.response
            .respond(severity_to_str(&rule.severity), event.pid, None);
    }

    async fn emit_detector_alerts(
        &mut self,
        event: &ProcessExecEvent,
        cmdline: &str,
        parent_comm: Option<&str>,
        matched_rule_ids: &HashSet<String>,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        if let Some(obf) = detect_obfuscation(cmdline) {
            let (rule_id, name, severity, technique, tactic, description) =
                obfuscation_metadata(&obf);
            if !matched_rule_ids.contains(rule_id) {
                self.emit_synthetic_alert(
                    event,
                    cmdline,
                    SyntheticAlertTemplate {
                        rule_id,
                        name,
                        severity,
                        technique,
                        tactic,
                        description,
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }

        if check_cmdline_injection(cmdline).is_some()
            && !matched_rule_ids.contains("heur_proc_injection")
        {
            self.emit_synthetic_alert(
                event,
                cmdline,
                SyntheticAlertTemplate {
                    rule_id: "heur_proc_injection",
                    name: "Process Injection Indicators (detector)",
                    severity: "critical",
                    technique: "T1055",
                    tactic: "Defense Evasion",
                    description:
                        "Detected injection indicators (e.g., LD_PRELOAD/ptrace/gdb attach)",
                    source: "detector",
                },
                alert_tx,
            )
            .await;
        }

        if check_container_escape_cmd(cmdline).is_some()
            && !matched_rule_ids.contains("privesc_container_escape")
        {
            self.emit_synthetic_alert(
                event,
                cmdline,
                SyntheticAlertTemplate {
                    rule_id: "privesc_container_escape",
                    name: "Container Escape Attempt (detector)",
                    severity: "critical",
                    technique: "T1611",
                    tactic: "Privilege Escalation",
                    description:
                        "Detected container escape indicators (nsenter/docker privileged/capability abuse)",
                    source: "detector",
                },
                alert_tx,
            )
            .await;
        }

        if let Some(parent) = parent_comm {
            if let Some(indicator) = check_webshell_spawn(parent, event.comm_str(), cmdline) {
                if !matched_rule_ids.contains("heur_webshell_spawn") {
                    self.emit_synthetic_alert(
                        event,
                        cmdline,
                        SyntheticAlertTemplate {
                            rule_id: "heur_webshell_spawn",
                            name: "Web Server Shell Spawn (detector)",
                            severity: webshell_severity_to_str(indicator.severity),
                            technique: "T1505.003",
                            tactic: "Persistence",
                            description:
                                "Web server or app server spawned a shell/interpreter - possible webshell/RCE",
                            source: "detector",
                        },
                        alert_tx,
                    )
                    .await;
                }
            }
        }

        if let Some(indicator) = detect_cryptominer(event.comm_str(), cmdline) {
            if !matched_rule_ids.contains("heur_crypto_miner") {
                self.emit_synthetic_alert(
                    event,
                    cmdline,
                    SyntheticAlertTemplate {
                        rule_id: "heur_crypto_miner",
                        name: "Cryptocurrency Miner (detector)",
                        severity: cryptominer_severity_to_str(indicator.severity),
                        technique: "T1496",
                        tactic: "Impact",
                        description: "Cryptocurrency mining indicators detected",
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }

        if let Some(indicator) = detect_log_tampering(cmdline) {
            if !matched_rule_ids.contains("heur_log_tampering") {
                self.emit_synthetic_alert(
                    event,
                    cmdline,
                    SyntheticAlertTemplate {
                        rule_id: "heur_log_tampering",
                        name: "Log Tampering (detector)",
                        severity: antiforensics_severity_to_str(indicator.severity),
                        technique: "T1070.002",
                        tactic: "Defense Evasion",
                        description: "Potential log/history tampering detected",
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }

        if let Some(indicator) = detect_rootkit_command(cmdline) {
            if !matched_rule_ids.contains("heur_rootkit_indicators") {
                self.emit_synthetic_alert(
                    event,
                    cmdline,
                    SyntheticAlertTemplate {
                        rule_id: "heur_rootkit_indicators",
                        name: "Rootkit Indicators (detector)",
                        severity: rootkit_severity_to_str(indicator.severity),
                        technique: "T1014",
                        tactic: "Defense Evasion",
                        description: "Rootkit installation indicators detected",
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }

        // High-fidelity technique-level detectors (MITRE-aligned).
        if let Some(hit) = det_c2::detect_reverse_shell_cmdline(cmdline) {
            let det_c2::ReverseShellAlert {
                pattern_matched,
                rule,
                ..
            } = hit;

            if !matched_rule_ids.contains(&rule.id) {
                self.emit_detection_rule_alert(
                    rule,
                    DetectionAlertData {
                        pid: event.pid,
                        ppid: event.ppid,
                        cmdline: cmdline.to_string(),
                        matched: vec![pattern_matched],
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }

        if let Some(hit) = det_fileless::detect_memfd_execution(event.pid) {
            let det_fileless::FilelessAlert { exe_path, rule, .. } = hit;

            if !matched_rule_ids.contains(&rule.id) {
                self.emit_detection_rule_alert(
                    rule,
                    DetectionAlertData {
                        pid: event.pid,
                        ppid: event.ppid,
                        cmdline: cmdline.to_string(),
                        matched: vec![exe_path],
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }

        if let Some(hit) = det_fileless::detect_ld_preload_injection(event.pid) {
            let det_fileless::FilelessAlert {
                pid,
                exe_path,
                rule,
                ..
            } = hit;

            if pid == 0 && self.system_ld_so_preload_alerted {
                return;
            }

            if pid == 0 {
                self.system_ld_so_preload_alerted = true;
            }

            if !matched_rule_ids.contains(&rule.id) {
                self.emit_detection_rule_alert(
                    rule,
                    DetectionAlertData {
                        pid,
                        ppid: if pid == 0 { 0 } else { event.ppid },
                        cmdline: if pid == 0 {
                            String::new()
                        } else {
                            cmdline.to_string()
                        },
                        matched: vec![exe_path],
                        source: "detector",
                    },
                    alert_tx,
                )
                .await;
            }
        }
    }

    async fn emit_synthetic_alert(
        &self,
        event: &ProcessExecEvent,
        cmdline: &str,
        template: SyntheticAlertTemplate<'_>,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let alert = BehavioralAlert {
            rule_id: template.rule_id.to_string(),
            name: template.name.to_string(),
            severity: template.severity.to_string(),
            technique: template.technique.to_string(),
            tactic: template.tactic.to_string(),
            pid: event.pid,
            ppid: event.ppid,
            cmdline: cmdline.to_string(),
            description: template.description.to_string(),
            timestamp: Utc::now(),
            matched: Vec::new(),
            source: template.source.to_string(),
        };

        if let Err(e) = alert_tx.send(alert.clone()).await {
            warn!(error = %e, "Failed to enqueue synthetic alert");
        }

        if let Err(e) = persist_alert_line(&self.config.alert_log_path, &alert).await {
            error!(error = %e, "Failed to persist synthetic alert");
        }
    }

    async fn emit_detection_rule_alert(
        &self,
        rule: av_behavioral::detection::DetectionRule,
        data: DetectionAlertData,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let severity = detection_severity_to_str(rule.severity).to_string();
        let alert = BehavioralAlert {
            rule_id: rule.id,
            name: rule.name,
            severity: severity.clone(),
            technique: rule.mitre.technique_id,
            tactic: rule.mitre.tactic,
            pid: data.pid,
            ppid: data.ppid,
            cmdline: data.cmdline,
            description: rule.description,
            timestamp: Utc::now(),
            matched: data.matched,
            source: data.source.to_string(),
        };

        if let Err(e) = alert_tx.send(alert.clone()).await {
            warn!(error = %e, "Failed to enqueue detection alert");
        }

        if let Err(e) = persist_alert_line(&self.config.alert_log_path, &alert).await {
            error!(error = %e, "Failed to persist detection alert");
        }

        if data.pid > 1 {
            self.response.respond(&severity, data.pid, None);
        }
    }

    async fn handle_ebpf_exec_detections(
        &self,
        event: ProcessExecEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let exe = event.filename_str();
        if exe.is_empty() {
            return;
        }

        // Execution from world-writable staging locations.
        if exe.starts_with("/tmp/") || exe.starts_with("/dev/shm/") || exe.starts_with("/var/tmp/")
        {
            self.emit_ebpf_alert(
                EbpfAlertTemplate {
                    rule_id: "EBPF-002",
                    name: "Execution from World-Writable Directory",
                    severity: "high",
                    technique: "T1059",
                    tactic: "Execution",
                },
                EbpfAlertData {
                    pid: event.pid,
                    ppid: event.ppid,
                    cmdline: event.args_str().to_string(),
                    description: format!("Execution from suspicious path: {}", exe),
                },
                alert_tx,
            )
            .await;
        }
    }

    async fn handle_network_connect(
        &self,
        event: NetworkConnectEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let dst_ip = match event.family {
            2 => IpAddr::V4(Ipv4Addr::from(event.dest_addr_v4.to_be_bytes())),
            10 => IpAddr::V6(Ipv6Addr::from(event.dest_addr_v6)),
            _ => return,
        };

        let comm = comm_from_bytes(&event.comm);
        let Some(hit) =
            det_c2::detect_suspicious_connection(event.pid, dst_ip, event.dest_port, &comm)
        else {
            return;
        };

        let det_c2::C2Alert {
            alert_type, rule, ..
        } = hit;

        let (ppid, cmdline) = read_proc_ppid_cmdline(event.pid).await;
        self.emit_detection_rule_alert(
            rule,
            DetectionAlertData {
                pid: event.pid,
                ppid,
                cmdline,
                matched: vec![
                    format!("dst={}:{}", dst_ip, event.dest_port),
                    format!("type={:?}", alert_type),
                ],
                source: "ebpf",
            },
            alert_tx,
        )
        .await;
    }

    async fn handle_file_access(
        &self,
        event: FileAccessEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        if event.access_type == FileAccessType::Normal {
            return;
        }

        let path = std::str::from_utf8(&event.filename)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let (severity, technique) = match event.access_type {
            FileAccessType::Credential => ("high", "T1003"),
            FileAccessType::SshKey => ("medium", "T1552.004"),
            FileAccessType::BrowserCreds => ("medium", "T1555.003"),
            FileAccessType::SensitiveConfig => ("medium", "T1552.001"),
            FileAccessType::Normal => ("low", "T1552.001"),
        };

        let (ppid, cmdline) = read_proc_ppid_cmdline(event.pid).await;

        self.emit_ebpf_alert(
            EbpfAlertTemplate {
                rule_id: "EBPF-020",
                name: "Credential File Access",
                severity,
                technique,
                tactic: "Credential Access",
            },
            EbpfAlertData {
                pid: event.pid,
                ppid,
                cmdline,
                description: format!("Sensitive file access detected: {}", path),
            },
            alert_tx,
        )
        .await;
    }

    async fn handle_ptrace(&self, event: PtraceEvent, alert_tx: &mpsc::Sender<BehavioralAlert>) {
        let Some(hit) =
            det_fileless::detect_ptrace_injection(event.pid, event.target_pid, event.request)
        else {
            return;
        };

        let det_fileless::FilelessAlert { rule, .. } = hit;
        let (ppid, cmdline) = read_proc_ppid_cmdline(event.pid).await;
        self.emit_detection_rule_alert(
            rule,
            DetectionAlertData {
                pid: event.pid,
                ppid,
                cmdline,
                matched: vec![
                    format!("target_pid={}", event.target_pid),
                    format!("request={}", event.request),
                ],
                source: "ebpf",
            },
            alert_tx,
        )
        .await;
    }

    async fn handle_kernel_module(
        &self,
        event: KernelModuleEvent,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let module = std::str::from_utf8(&event.module_name)
            .unwrap_or("")
            .trim_end_matches('\0');

        let comm = read_proc_comm(event.pid)
            .await
            .unwrap_or_else(|| "unknown".to_string());
        let Some(hit) = det_persistence::detect_kernel_module_load(module, event.pid, &comm) else {
            return;
        };

        let det_persistence::PersistenceAlert { rule, .. } = hit;
        let (ppid, cmdline) = read_proc_ppid_cmdline(event.pid).await;
        self.emit_detection_rule_alert(
            rule,
            DetectionAlertData {
                pid: event.pid,
                ppid,
                cmdline,
                matched: vec![format!("module={}", module)],
                source: "ebpf",
            },
            alert_tx,
        )
        .await;
    }

    async fn emit_ebpf_alert(
        &self,
        template: EbpfAlertTemplate<'_>,
        data: EbpfAlertData,
        alert_tx: &mpsc::Sender<BehavioralAlert>,
    ) {
        let alert = BehavioralAlert {
            rule_id: template.rule_id.to_string(),
            name: template.name.to_string(),
            severity: template.severity.to_string(),
            technique: template.technique.to_string(),
            tactic: template.tactic.to_string(),
            pid: data.pid,
            ppid: data.ppid,
            cmdline: data.cmdline,
            description: data.description,
            timestamp: Utc::now(),
            matched: Vec::new(),
            source: "ebpf".to_string(),
        };

        if let Err(e) = alert_tx.send(alert.clone()).await {
            warn!(error = %e, "Failed to enqueue eBPF alert");
        }

        if let Err(e) = persist_alert_line(&self.config.alert_log_path, &alert).await {
            error!(error = %e, "Failed to persist eBPF alert");
        }

        self.response.respond(template.severity, data.pid, None);
    }
}

fn obfuscation_metadata(
    obf: &ObfuscationType,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match obf {
        ObfuscationType::Base64 => (
            "exec_base64_decode",
            "Base64 Encoded Command Execution (detector)",
            "high",
            "T1059.004",
            "Execution",
            "Detected base64 decoding chained to execution",
        ),
        ObfuscationType::DoubleBase64 => (
            "obf_double_base64",
            "Double Base64 Encoding (detector)",
            "high",
            "T1027.001",
            "Defense Evasion",
            "Detected double base64 encoding used to evade detection",
        ),
        ObfuscationType::Hex => (
            "obf_hex_encoding",
            "Hex Encoded Command (detector)",
            "high",
            "T1027",
            "Defense Evasion",
            "Detected hex-escaped content indicative of obfuscated execution",
        ),
        ObfuscationType::Octal => (
            "obf_octal_encoding",
            "Octal Encoded Command (detector)",
            "high",
            "T1027",
            "Defense Evasion",
            "Detected octal-escaped content indicative of obfuscated execution",
        ),
        ObfuscationType::StringConcat => (
            "obf_string_concat",
            "String Concatenation Evasion (detector)",
            "medium",
            "T1027",
            "Defense Evasion",
            "Detected string concatenation patterns used to evade static matching",
        ),
        ObfuscationType::EnvSlice => (
            "obf_env_slice",
            "Env Variable Slicing (detector)",
            "high",
            "T1027",
            "Defense Evasion",
            "Detected environment variable slicing used to build commands",
        ),
        ObfuscationType::Rot13 => (
            "obf_rot13",
            "ROT13 Encoding (detector)",
            "medium",
            "T1027",
            "Defense Evasion",
            "Detected ROT13 encoding pipeline",
        ),
        ObfuscationType::BraceExpansion => (
            "obf_brace_expansion",
            "Brace Expansion Evasion (detector)",
            "medium",
            "T1027",
            "Defense Evasion",
            "Detected brace expansion used to construct commands",
        ),
        ObfuscationType::IfsManipulation => (
            "obf_ifs_manipulation",
            "IFS Manipulation (detector)",
            "high",
            "T1027",
            "Defense Evasion",
            "Detected IFS manipulation used to evade parsing and static matching",
        ),
        ObfuscationType::BacktickEncoded => (
            "obf_backtick_sub",
            "Backtick Substitution with Encoded Content (detector)",
            "high",
            "T1027",
            "Defense Evasion",
            "Detected backtick substitution involving decoding utilities",
        ),
    }
}

pub async fn start_behavioral_pipeline(
    config: BehavioralConfig,
) -> anyhow::Result<BehavioralRuntime> {
    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let (alert_tx, alert_rx) = mpsc::channel(1024);

    let mut pipeline = BehavioralPipeline::new(config).await?;

    tokio::spawn(async move {
        while let Some(event) = event_rx.recv().await {
            pipeline.handle_event(event, &alert_tx).await;
        }
    });

    Ok(BehavioralRuntime { event_tx, alert_rx })
}

async fn load_rules(config: &BehavioralConfig) -> anyhow::Result<Vec<Rule>> {
    let mut map: HashMap<String, Rule> = HashMap::new();

    // Embedded rules
    let embedded_json = include_str!("../../av-behavioral/rules/linux_behavioral.json");
    match serde_json::from_str::<serde_json::Value>(embedded_json) {
        Ok(parsed) => {
            if let Some(arr) = parsed.get("rules").and_then(|v| v.as_array()) {
                for val in arr {
                    match serde_json::from_value::<Rule>(val.clone()) {
                        Ok(rule) => {
                            map.insert(rule.id.clone(), rule);
                        }
                        Err(e) => warn!(error = %e, "Failed to parse embedded rule"),
                    }
                }
            }
        }
        Err(e) => warn!(error = %e, "Failed to parse embedded rules blob"),
    }

    // External overrides
    if let Some(dir) = &config.external_rules_dir {
        if dir.exists() {
            match fs::read_dir(dir).await {
                Ok(mut entries) => {
                    while let Ok(Some(entry)) = entries.next_entry().await {
                        let path = entry.path();
                        if path.extension().and_then(|e| e.to_str()) != Some("json") {
                            continue;
                        }
                        match load_rules_from_file(&path).await {
                            Ok(file_rules) => {
                                for rule in file_rules {
                                    map.insert(rule.id.clone(), rule);
                                }
                            }
                            Err(e) => {
                                warn!(file = %path.display(), error = %e, "Skipping malformed rule file")
                            }
                        }
                    }
                }
                Err(e) => warn!(dir = %dir.display(), error = %e, "Cannot read external rules dir"),
            }
        }
    }

    Ok(map.into_values().collect())
}

async fn load_rules_from_file(path: &Path) -> anyhow::Result<Vec<Rule>> {
    let content = fs::read_to_string(path).await?;
    let parsed: serde_json::Value = serde_json::from_str(&content)?;
    let mut rules = Vec::new();

    if let Some(arr) = parsed.get("rules").and_then(|v| v.as_array()) {
        for val in arr {
            if let Ok(rule) = serde_json::from_value::<Rule>(val.clone()) {
                rules.push(rule);
            } else {
                warn!(file = %path.display(), "Skipping malformed rule entry");
            }
        }
    }

    Ok(rules)
}

fn severity_to_str(sev: &Severity) -> &'static str {
    match sev {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn detection_severity_to_str(sev: av_behavioral::detection::Severity) -> &'static str {
    match sev {
        av_behavioral::detection::Severity::Info => "info",
        av_behavioral::detection::Severity::Low => "low",
        av_behavioral::detection::Severity::Medium => "medium",
        av_behavioral::detection::Severity::High => "high",
        av_behavioral::detection::Severity::Critical => "critical",
    }
}

fn comm_from_bytes(bytes: &[u8]) -> String {
    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..len]).trim().to_string()
}

async fn read_proc_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/comm", pid);
    fs::read_to_string(&path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn read_proc_ppid_cmdline(pid: u32) -> (u32, String) {
    let ppid = fs::read_to_string(format!("/proc/{}/stat", pid))
        .await
        .ok()
        .and_then(|stat| {
            let close_paren = stat.rfind(')')?;
            let after_comm = &stat[close_paren + 2..];
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            fields.get(1).and_then(|s| s.parse().ok())
        })
        .unwrap_or(0);

    let cmdline_bytes = fs::read(format!("/proc/{}/cmdline", pid))
        .await
        .unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&cmdline_bytes)
        .replace('\0', " ")
        .trim()
        .to_string();

    (ppid, cmdline)
}

fn webshell_severity_to_str(sev: WebShellSeverity) -> &'static str {
    match sev {
        WebShellSeverity::Critical => "critical",
        WebShellSeverity::High => "high",
        WebShellSeverity::Medium => "medium",
    }
}

fn cryptominer_severity_to_str(sev: CryptoMinerSeverity) -> &'static str {
    match sev {
        CryptoMinerSeverity::Critical => "critical",
        CryptoMinerSeverity::High => "high",
        CryptoMinerSeverity::Medium => "medium",
    }
}

fn antiforensics_severity_to_str(sev: AntiForensicsSeverity) -> &'static str {
    match sev {
        AntiForensicsSeverity::Critical => "critical",
        AntiForensicsSeverity::High => "high",
    }
}

fn rootkit_severity_to_str(sev: RootkitSeverity) -> &'static str {
    match sev {
        RootkitSeverity::Critical => "critical",
        RootkitSeverity::High => "high",
        RootkitSeverity::Medium => "medium",
    }
}

async fn persist_alert_line(path: &Path, alert: &BehavioralAlert) -> Result<(), std::io::Error> {
    let json_line = match serde_json::to_string(alert) {
        Ok(line) => line,
        Err(_) => return Ok(()), // drop if serialization fails; never panic
    };

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }

    let existing = fs::read(path).await.unwrap_or_default();
    let mut buffer = existing;
    buffer.extend_from_slice(json_line.as_bytes());
    buffer.push(b'\n');

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, buffer).await?;
    fs::rename(&tmp_path, path).await?;

    info!(file = %path.display(), "Alert log updated atomically");
    Ok(())
}

pub fn log_alert(alert: &BehavioralAlert) {
    match serde_json::to_string(alert) {
        Ok(json) => info!("ALERT: {}", json),
        Err(e) => warn!(error = %e, "Failed to serialize alert for logging"),
    }
}
