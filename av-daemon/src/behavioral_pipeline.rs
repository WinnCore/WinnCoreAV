use crate::heuristics::HeuristicAnalyzer;
use crate::response::ResponseEngine;
use av_behavioral::rules::{
    check_cmdline_injection, check_container_escape_cmd, check_webshell_spawn, detect_cryptominer,
    detect_log_tampering, detect_obfuscation, detect_rootkit_command, AntiForensicsSeverity,
    CryptoMinerSeverity, ObfuscationType, RootkitSeverity, Rule, RuleEngine, RuleMatch, Severity,
    WebShellSeverity,
};
use av_behavioral::Allowlist;
use av_ebpf_common::ProcessExecEvent;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
        &self,
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

async fn read_proc_comm(pid: u32) -> Option<String> {
    let path = format!("/proc/{}/comm", pid);
    fs::read_to_string(&path)
        .await
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
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
