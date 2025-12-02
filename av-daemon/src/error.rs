#![allow(dead_code)]
//! Structured error types with recovery strategies

use std::fmt;
use std::time::Duration;

/// Daemon-specific errors with recovery hints
#[derive(Debug)]
pub enum DaemonError {
    /// ML subsystem failed - can operate in signature-only mode
    MlSubsystemFailure {
        source: Box<dyn std::error::Error + Send + Sync>,
        recovery: RecoveryStrategy,
    },

    /// Signature engine failed - can operate in ML-only mode
    SignatureEngineFailure {
        source: Box<dyn std::error::Error + Send + Sync>,
        recovery: RecoveryStrategy,
    },

    /// eBPF monitoring failed - fall back to fanotify only
    EbpfFailure {
        source: Box<dyn std::error::Error + Send + Sync>,
        recovery: RecoveryStrategy,
    },

    /// File monitoring failed - critical, needs restart
    FileMonitorFailure {
        source: Box<dyn std::error::Error + Send + Sync>,
        recovery: RecoveryStrategy,
    },

    /// Configuration error - needs manual intervention
    ConfigError {
        message: String,
        recovery: RecoveryStrategy,
    },

    /// Resource exhaustion (memory, file descriptors, etc.)
    ResourceExhaustion {
        resource: String,
        recovery: RecoveryStrategy,
    },

    /// Quarantine operation failed
    QuarantineError {
        source: Box<dyn std::error::Error + Send + Sync>,
        file_path: String,
        recovery: RecoveryStrategy,
    },
}

/// How to recover from an error
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryStrategy {
    /// Retry with exponential backoff
    RetryWithBackoff {
        max_attempts: u32,
        initial_delay: Duration,
        max_delay: Duration,
    },

    /// Disable the failing subsystem and continue with degraded functionality
    Degrade {
        subsystem: Subsystem,
        fallback_mode: String,
    },

    /// Restart the entire daemon
    Restart { delay: Duration },

    /// Fatal error - shut down cleanly and alert
    Fatal { exit_code: i32 },

    /// Ignore and continue (for non-critical errors)
    Continue,
}

/// Subsystems that can be degraded
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subsystem {
    MlDetection,
    SignatureMatching,
    EbpfMonitoring,
    FileMonitoring,
    Quarantine,
    Metrics,
    Alerting,
}

impl Subsystem {
    pub fn is_critical(&self) -> bool {
        matches!(self, Subsystem::FileMonitoring)
    }

    pub fn name(&self) -> &'static str {
        match self {
            Subsystem::MlDetection => "ML Detection",
            Subsystem::SignatureMatching => "Signature Matching",
            Subsystem::EbpfMonitoring => "eBPF Monitoring",
            Subsystem::FileMonitoring => "File Monitoring",
            Subsystem::Quarantine => "Quarantine",
            Subsystem::Metrics => "Metrics",
            Subsystem::Alerting => "Alerting",
        }
    }
}

impl std::error::Error for DaemonError {}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::MlSubsystemFailure { source, .. } => {
                write!(f, "ML subsystem failure: {}", source)
            }
            DaemonError::SignatureEngineFailure { source, .. } => {
                write!(f, "Signature engine failure: {}", source)
            }
            DaemonError::EbpfFailure { source, .. } => {
                write!(f, "eBPF monitoring failure: {}", source)
            }
            DaemonError::FileMonitorFailure { source, .. } => {
                write!(f, "File monitor failure: {}", source)
            }
            DaemonError::ConfigError { message, .. } => {
                write!(f, "Configuration error: {}", message)
            }
            DaemonError::ResourceExhaustion { resource, .. } => {
                write!(f, "Resource exhaustion: {}", resource)
            }
            DaemonError::QuarantineError {
                file_path, source, ..
            } => {
                write!(f, "Quarantine failed for {}: {}", file_path, source)
            }
        }
    }
}

impl DaemonError {
    pub fn recovery_strategy(&self) -> &RecoveryStrategy {
        match self {
            DaemonError::MlSubsystemFailure { recovery, .. } => recovery,
            DaemonError::SignatureEngineFailure { recovery, .. } => recovery,
            DaemonError::EbpfFailure { recovery, .. } => recovery,
            DaemonError::FileMonitorFailure { recovery, .. } => recovery,
            DaemonError::ConfigError { recovery, .. } => recovery,
            DaemonError::ResourceExhaustion { recovery, .. } => recovery,
            DaemonError::QuarantineError { recovery, .. } => recovery,
        }
    }
}

/// Result type for daemon operations
pub type DaemonResult<T> = Result<T, DaemonError>;
