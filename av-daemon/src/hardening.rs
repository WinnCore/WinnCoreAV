//! Hardening orchestration for the daemon.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, warn};

use av_core::{
    allocator, configure_secure_allocator, disable_core_dumps, init_logging, init_mte,
    is_mte_supported, LogConfig, LogSampler, MteMode,
};

use crate::aslr_verify::verify_aslr;
use crate::integrity::{full_integrity_check, init_integrity, IntegrityStatus};
use crate::landlock::{enforce_landlock, is_landlock_supported, LandlockRuleset};
use crate::memory_audit::MemoryAuditor;
use crate::namespaces::{can_use_namespaces, enter_namespaces, NamespaceConfig};

#[derive(Debug, Clone)]
pub struct HardeningConfig {
    pub enable_mte: bool,
    pub enable_landlock: bool,
    pub enable_namespaces: bool,
    pub verify_aslr: bool,
    pub enable_memory_audit: bool,
    pub memory_audit_interval: Duration,
    pub enable_integrity_check: bool,
    pub integrity_check_interval: Duration,
    pub strict_mode: bool,
    pub log_config: LogConfig,
}

impl Default for HardeningConfig {
    fn default() -> Self {
        let namespaces_enabled = std::env::var("WINNCORE_DISABLE_NAMESPACES").is_err();
        Self {
            enable_mte: true,
            enable_landlock: true,
            enable_namespaces: namespaces_enabled,
            verify_aslr: true,
            enable_memory_audit: true,
            memory_audit_interval: Duration::from_secs(60),
            enable_integrity_check: true,
            integrity_check_interval: Duration::from_secs(60),
            strict_mode: true,
            log_config: LogConfig::default(),
        }
    }
}

impl HardeningConfig {
    pub fn development() -> Self {
        Self {
            enable_landlock: false,
            enable_namespaces: false,
            strict_mode: false,
            ..Self::default()
        }
    }
}

#[derive(Debug)]
pub struct HardeningResult {
    pub mte_enabled: bool,
    pub mte_mode: MteMode,
    pub landlock_enabled: bool,
    pub namespaces_enabled: bool,
    pub aslr_verified: bool,
    pub memory_audit_enabled: bool,
    pub integrity_enabled: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl HardeningResult {
    #[allow(dead_code)]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

pub fn init_all_hardening(config: &HardeningConfig) -> Result<HardeningResult, String> {
    let mut result = HardeningResult {
        mte_enabled: false,
        mte_mode: MteMode::Disabled,
        landlock_enabled: false,
        namespaces_enabled: false,
        aslr_verified: false,
        memory_audit_enabled: config.enable_memory_audit,
        integrity_enabled: config.enable_integrity_check,
        warnings: Vec::new(),
        errors: Vec::new(),
    };

    // Disable core dumps early
    let _ = disable_core_dumps();

    // Logging (needed before other steps)
    let _sampler: Arc<LogSampler> =
        init_logging(&config.log_config).map_err(|e| format!("Failed to init logging: {e}"))?;

    configure_secure_allocator();
    if !allocator::verify_heap_integrity() {
        result.errors.push("Heap integrity failed".into());
    }

    if config.enable_mte {
        if is_mte_supported() {
            match init_mte() {
                Ok(mode) => {
                    result.mte_enabled = mode != MteMode::Disabled;
                    result.mte_mode = mode;
                }
                Err(e) => result.warnings.push(format!("MTE init failed: {}", e)),
            }
        } else {
            result.warnings.push("MTE not supported".into());
        }
    }

    if config.verify_aslr {
        let aslr = verify_aslr();
        result.aslr_verified = aslr.is_sufficient;
        for w in aslr.warnings {
            result.warnings.push(format!("ASLR: {}", w));
        }
        if config.strict_mode && !aslr.is_sufficient {
            result.errors.push("ASLR verification failed".into());
        }
    }

    if config.enable_integrity_check {
        if let Err(e) = init_integrity() {
            result.warnings.push(format!("Integrity init failed: {e}"));
        } else if let IntegrityStatus::Ok = full_integrity_check() {
        } else {
            let msg = "Initial integrity check failed".to_string();
            if config.strict_mode {
                result.errors.push(msg);
            } else {
                result.warnings.push(msg);
            }
        }
    }

    if config.enable_namespaces {
        if can_use_namespaces() {
            let ns_cfg = if config.strict_mode {
                NamespaceConfig::production()
            } else {
                NamespaceConfig::development()
            };
            match enter_namespaces(&ns_cfg) {
                Ok(()) => result.namespaces_enabled = true,
                Err(e) => {
                    let msg = format!("Namespace isolation failed: {}", e);
                    // If user namespaces are denied (common when disabled), fall back to warning.
                    if let crate::namespaces::NamespaceError::SyscallFailed(_, ref err) = e {
                        if err.kind() == std::io::ErrorKind::PermissionDenied {
                            result.warnings.push(format!(
                                "Namespace isolation skipped (permission denied): {}",
                                err
                            ));
                            result.namespaces_enabled = false;
                        } else if config.strict_mode {
                            result.errors.push(msg);
                        } else {
                            result.warnings.push(msg);
                        }
                    } else if config.strict_mode {
                        result.errors.push(msg);
                    } else {
                        result.warnings.push(msg);
                    }
                }
            }
        } else {
            result.warnings.push("Namespaces not available".into());
        }
    }

    if config.enable_landlock {
        if is_landlock_supported() {
            let rules = LandlockRuleset::av_daemon_default();
            match enforce_landlock(&rules) {
                Ok(()) => result.landlock_enabled = true,
                Err(e) => {
                    let msg = format!("Landlock failed: {}", e);
                    if config.strict_mode {
                        result.errors.push(msg);
                    } else {
                        result.warnings.push(msg);
                    }
                }
            }
        } else {
            result.warnings.push("Landlock not available".into());
        }
    }

    info!(
        mte = result.mte_enabled,
        landlock = result.landlock_enabled,
        namespaces = result.namespaces_enabled,
        aslr = result.aslr_verified,
        memory_audit = result.memory_audit_enabled,
        integrity = result.integrity_enabled,
        warnings = result.warnings.len(),
        errors = result.errors.len(),
        "Hardening initialization complete"
    );

    for w in &result.warnings {
        warn!("Hardening warning: {}", w);
    }
    for e in &result.errors {
        error!("Hardening error: {}", e);
    }

    if config.strict_mode && !result.errors.is_empty() {
        return Err(format!("Hardening failed: {}", result.errors.join("; ")));
    }

    Ok(result)
}

pub async fn start_background_hardening(config: &HardeningConfig) -> Arc<MemoryAuditor> {
    let auditor = Arc::new(MemoryAuditor::new());
    if config.enable_memory_audit {
        if let Err(e) = auditor.init_baseline() {
            warn!(error = %e, "Memory audit baseline failed");
        }
        let auditor_clone = auditor.clone();
        let interval_dur = config.memory_audit_interval;
        tokio::spawn(async move {
            let mut ticker = interval(interval_dur);
            loop {
                ticker.tick().await;
                auditor_clone.check_and_log();
            }
        });
    }

    if config.enable_integrity_check {
        let interval_dur = config.integrity_check_interval;
        tokio::spawn(async move {
            let mut ticker = interval(interval_dur);
            loop {
                ticker.tick().await;
                match full_integrity_check() {
                    IntegrityStatus::Ok => {}
                    status => {
                        error!(status = ?status, "Integrity check failed");
                    }
                }
            }
        });
    }

    auditor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dev_config_ok() {
        let cfg = HardeningConfig::development();
        let res = init_all_hardening(&cfg);
        assert!(res.is_ok());
    }
}
