use crate::events::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Rule that matches behavioral events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<MitreTechnique>,
    pub enabled: bool,
    pub condition: RuleCondition,
    pub exceptions: Vec<RuleException>,
}

/// Conditions that trigger a rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleCondition {
    ProcessNameMatch { pattern: String, is_regex: bool },
    ProcessPathMatch { pattern: String, is_regex: bool },
    FilePathMatch { pattern: String, is_regex: bool },
    SensitiveFileAccess,
    ExecutableWrite { to_autostart: bool },
    ExternalConnection,
    KnownBadDestination,
    RwxMemoryAllocation,
    RareSyscall { syscalls: Vec<String> },
    And(Vec<RuleCondition>),
    Or(Vec<RuleCondition>),
    Not(Box<RuleCondition>),
}

/// Exceptions to prevent false positives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleException {
    pub process_paths: Vec<String>,
    pub process_names: Vec<String>,
    pub users: Vec<String>,
    pub file_paths: Vec<String>,
}

/// Result of a rule match.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMatch {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub mitre_techniques: Vec<MitreTechnique>,
    pub event: BehavioralEvent,
}

/// Built-in detection rules for common attack patterns.
pub fn get_default_rules() -> Vec<BehavioralRule> {
    vec![
        BehavioralRule {
            id: "WINNCORE-001".into(),
            name: "Process Injection Attempt".into(),
            description: "Detect ptrace or cross-process memory access".into(),
            severity: Severity::High,
            mitre_techniques: vec![MitreTechnique {
                id: "T1055".into(),
                name: "Process Injection".into(),
                tactic: "Defense Evasion".into(),
            }],
            enabled: true,
            condition: RuleCondition::RareSyscall {
                syscalls: vec!["ptrace".into(), "process_vm_writev".into()],
            },
            exceptions: vec![RuleException {
                process_paths: vec!["/usr/bin/gdb".into(), "/usr/bin/strace".into()],
                process_names: vec![],
                users: vec![],
                file_paths: vec![],
            }],
        },
        BehavioralRule {
            id: "WINNCORE-002".into(),
            name: "Credential File Access".into(),
            description: "Sensitive file access such as /etc/shadow".into(),
            severity: Severity::Critical,
            mitre_techniques: vec![MitreTechnique {
                id: "T1003".into(),
                name: "OS Credential Dumping".into(),
                tactic: "Credential Access".into(),
            }],
            enabled: true,
            condition: RuleCondition::FilePathMatch {
                pattern: "^/etc/(shadow|passwd)".into(),
                is_regex: true,
            },
            exceptions: vec![RuleException {
                process_paths: vec!["/usr/sbin/useradd".into(), "/usr/bin/passwd".into()],
                process_names: vec!["sshd".into()],
                users: vec![],
                file_paths: vec![],
            }],
        },
        BehavioralRule {
            id: "WINNCORE-003".into(),
            name: "Suspicious Outbound Connection".into(),
            description: "Detects external or known-bad destinations".into(),
            severity: Severity::Critical,
            mitre_techniques: vec![MitreTechnique {
                id: "T1071".into(),
                name: "Application Layer Protocol".into(),
                tactic: "Command and Control".into(),
            }],
            enabled: true,
            condition: RuleCondition::ExternalConnection,
            exceptions: vec![],
        },
        BehavioralRule {
            id: "WINNCORE-004".into(),
            name: "RWX Memory Allocation".into(),
            description: "Detects mappings that are simultaneously readable, writable, executable."
                .into(),
            severity: Severity::High,
            mitre_techniques: vec![MitreTechnique {
                id: "T1055.012".into(),
                name: "Shellcode".into(),
                tactic: "Execution".into(),
            }],
            enabled: true,
            condition: RuleCondition::RwxMemoryAllocation,
            exceptions: vec![],
        },
    ]
}

pub struct RuleEngine {
    rules: Vec<BehavioralRule>,
    sensitive_paths: HashSet<String>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            rules: get_default_rules(),
            sensitive_paths: HashSet::new(),
        };
        engine.init_sensitive_paths();
        engine
    }

    fn init_sensitive_paths(&mut self) {
        let paths = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/root/.ssh",
            "/home/*/.ssh",
        ];
        for p in paths {
            self.sensitive_paths.insert(p.to_string());
        }
    }

    pub fn load_rules(&mut self, extra: Vec<BehavioralRule>) {
        self.rules.extend(extra);
    }

    pub fn evaluate(&self, event: &BehavioralEvent) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            if self.check_exceptions(&rule.exceptions, event) {
                continue;
            }

            if self.evaluate_condition(&rule.condition, event) {
                matches.push(RuleMatch {
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: rule.severity,
                    mitre_techniques: rule.mitre_techniques.clone(),
                    event: event.clone(),
                });
            }
        }

        matches
    }

    fn check_exceptions(&self, exceptions: &[RuleException], event: &BehavioralEvent) -> bool {
        for exc in exceptions {
            if exc.process_names.iter().any(|n| n == &event.comm) {
                return true;
            }
            if exc
                .process_paths
                .iter()
                .any(|p| event.exe_path.starts_with(p))
            {
                return true;
            }
            if exc.file_paths.iter().any(|p| event.cmdline.contains(p)) {
                return true;
            }
        }
        false
    }

    fn evaluate_condition(&self, condition: &RuleCondition, event: &BehavioralEvent) -> bool {
        match condition {
            RuleCondition::ProcessNameMatch { pattern, is_regex } => {
                if *is_regex {
                    Regex::new(pattern)
                        .map(|re| re.is_match(&event.comm))
                        .unwrap_or(false)
                } else {
                    event.comm.contains(pattern)
                }
            }
            RuleCondition::ProcessPathMatch { pattern, is_regex } => {
                if *is_regex {
                    Regex::new(pattern)
                        .map(|re| re.is_match(&event.exe_path))
                        .unwrap_or(false)
                } else {
                    event.exe_path.contains(pattern)
                }
            }
            RuleCondition::FilePathMatch { pattern, is_regex } => {
                if let EventType::FileOpen(f) = &event.event_type {
                    if *is_regex {
                        Regex::new(pattern)
                            .map(|re| re.is_match(&f.path))
                            .unwrap_or(false)
                    } else {
                        f.path.contains(pattern)
                    }
                } else {
                    false
                }
            }
            RuleCondition::SensitiveFileAccess => {
                if let EventType::FileOpen(f) = &event.event_type {
                    f.is_sensitive || self.sensitive_paths.iter().any(|p| f.path.starts_with(p))
                } else {
                    false
                }
            }
            RuleCondition::ExecutableWrite { to_autostart } => {
                if let EventType::FileWrite(f) = &event.event_type {
                    f.is_executable_content && (!to_autostart || f.is_autostart_location)
                } else {
                    false
                }
            }
            RuleCondition::ExternalConnection => {
                if let EventType::NetworkConnect(n) = &event.event_type {
                    n.is_external
                } else {
                    false
                }
            }
            RuleCondition::KnownBadDestination => {
                if let EventType::NetworkConnect(n) = &event.event_type {
                    n.is_known_bad
                } else {
                    false
                }
            }
            RuleCondition::RwxMemoryAllocation => {
                if let EventType::MemoryMap(m) = &event.event_type {
                    m.is_rwx
                } else {
                    false
                }
            }
            RuleCondition::RareSyscall { syscalls } => {
                if let EventType::SyscallAnomaly(s) = &event.event_type {
                    syscalls.iter().any(|sc| sc == &s.syscall_name)
                } else {
                    false
                }
            }
            RuleCondition::And(conds) => conds.iter().all(|c| self.evaluate_condition(c, event)),
            RuleCondition::Or(conds) => conds.iter().any(|c| self.evaluate_condition(c, event)),
            RuleCondition::Not(cond) => !self.evaluate_condition(cond, event),
        }
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}
