//! Metrics and structured logging for WinnCore AV
//!
//! This module provides:
//! - Prometheus metrics for monitoring
//! - Structured JSON logging for detections
//! - Integration with existing telemetry

use serde::{Deserialize, Serialize};
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Prometheus-style metrics for LOTL detections
pub struct LotlMetrics {
    /// Total LOTL detections by type
    detections_total: Arc<Mutex<std::collections::HashMap<String, AtomicU64>>>,
    /// Total automated responses by action
    responses_total: Arc<Mutex<std::collections::HashMap<String, AtomicU64>>>,
    /// Total behavioral scans performed
    scans_total: AtomicU64,
    /// Total threats mitigated
    threats_mitigated: AtomicU64,
}

impl LotlMetrics {
    pub fn new() -> Self {
        Self {
            detections_total: Arc::new(Mutex::new(std::collections::HashMap::new())),
            responses_total: Arc::new(Mutex::new(std::collections::HashMap::new())),
            scans_total: AtomicU64::new(0),
            threats_mitigated: AtomicU64::new(0),
        }
    }

    /// Increment detection counter for a specific type
    pub fn increment_detection(&self, detection_type: &str) {
        let mut detections = self.detections_total.lock().unwrap();
        detections
            .entry(detection_type.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment response counter for a specific action
    pub fn increment_response(&self, action: &str) {
        let mut responses = self.responses_total.lock().unwrap();
        responses
            .entry(action.to_string())
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment scan counter
    pub fn increment_scan(&self) {
        self.scans_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment threats mitigated counter
    pub fn increment_threat_mitigated(&self) {
        self.threats_mitigated.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total scans
    pub fn get_scans_total(&self) -> u64 {
        self.scans_total.load(Ordering::Relaxed)
    }

    /// Get total threats mitigated
    pub fn get_threats_mitigated(&self) -> u64 {
        self.threats_mitigated.load(Ordering::Relaxed)
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self) -> String {
        let mut output = String::new();

        // winncore_lotl_detections_total
        output.push_str("# HELP winncore_lotl_detections_total Total LOTL detections by type\n");
        output.push_str("# TYPE winncore_lotl_detections_total counter\n");

        let detections = self.detections_total.lock().unwrap();
        for (detection_type, counter) in detections.iter() {
            let value = counter.load(Ordering::Relaxed);
            output.push_str(&format!(
                "winncore_lotl_detections_total{{type=\"{}\"}} {}\n",
                detection_type, value
            ));
        }

        // winncore_responses_total
        output.push_str("# HELP winncore_responses_total Total automated responses by action\n");
        output.push_str("# TYPE winncore_responses_total counter\n");

        let responses = self.responses_total.lock().unwrap();
        for (action, counter) in responses.iter() {
            let value = counter.load(Ordering::Relaxed);
            output.push_str(&format!(
                "winncore_responses_total{{action=\"{}\"}} {}\n",
                action, value
            ));
        }

        // winncore_scans_total
        output.push_str("# HELP winncore_scans_total Total behavioral scans performed\n");
        output.push_str("# TYPE winncore_scans_total counter\n");
        output.push_str(&format!(
            "winncore_scans_total {}\n",
            self.get_scans_total()
        ));

        // winncore_threats_mitigated_total
        output.push_str("# HELP winncore_threats_mitigated_total Total threats mitigated\n");
        output.push_str("# TYPE winncore_threats_mitigated_total counter\n");
        output.push_str(&format!(
            "winncore_threats_mitigated_total {}\n",
            self.get_threats_mitigated()
        ));

        output
    }
}

impl Default for LotlMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Structured detection log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionLog {
    pub timestamp: u64,
    pub detection_type: String,
    pub threat_score: f32,
    pub risk_level: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
    pub details: String,
    pub response_action: Option<String>,
    pub response_success: Option<bool>,
}

/// JSON logger for detections
pub struct DetectionLogger {
    log_path: String,
}

impl DetectionLogger {
    pub fn new(log_path: &str) -> Self {
        Self {
            log_path: log_path.to_string(),
        }
    }

    /// Default logger writes to /var/log/winncore/detections.json
    pub fn default_path() -> Self {
        Self::new("/var/log/winncore/detections.json")
    }

    /// Ensure log directory exists
    fn ensure_log_dir(&self) -> std::io::Result<()> {
        if let Some(parent) = std::path::Path::new(&self.log_path).parent() {
            create_dir_all(parent)?;
        }
        Ok(())
    }

    /// Log a detection event
    pub fn log_detection(&self, entry: &DetectionLog) -> std::io::Result<()> {
        self.ensure_log_dir()?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;

        let json = serde_json::to_string(entry)?;
        writeln!(file, "{}", json)?;

        Ok(())
    }

    /// Log behavioral scan results
    pub fn log_behavioral_scan(
        &self,
        behavioral_score: &crate::behavioral_score::BehavioralScore,
        summary: &crate::EventSummary,
        responses: Option<&[crate::response::ResponseResult]>,
    ) -> std::io::Result<()> {
        // Log overall behavioral score
        let overall_log = DetectionLog {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            detection_type: "behavioral_scan".to_string(),
            threat_score: behavioral_score.overall_score,
            risk_level: format!("{:?}", behavioral_score.risk_level),
            pid: None,
            process_name: None,
            details: behavioral_score.assessment.clone(),
            response_action: None,
            response_success: None,
        };
        self.log_detection(&overall_log)?;

        // Log individual LOTL events
        if let Some(event) = &summary.most_recent {
            let event_log = DetectionLog {
                timestamp: event.timestamp,
                detection_type: format!("lotl_{:?}", event.event_type),
                threat_score: event.suspicion_score,
                risk_level: if event.suspicion_score > 0.8 {
                    "High".to_string()
                } else {
                    "Medium".to_string()
                },
                pid: Some(event.pid),
                process_name: Some(event.comm.clone()),
                details: event.details.clone(),
                response_action: None,
                response_success: None,
            };
            self.log_detection(&event_log)?;
        }

        // Log network events
        for net_event in &summary.network_events {
            let net_log = DetectionLog {
                timestamp: net_event.timestamp,
                detection_type: format!("network_{:?}", net_event.event_type),
                threat_score: net_event.suspicion_score,
                risk_level: if net_event.suspicion_score > 0.8 {
                    "High".to_string()
                } else {
                    "Medium".to_string()
                },
                pid: Some(net_event.pid),
                process_name: Some(net_event.comm.clone()),
                details: format!("{}:{}", net_event.remote_ip, net_event.remote_port),
                response_action: None,
                response_success: None,
            };
            self.log_detection(&net_log)?;
        }

        // Log fileless events
        for fileless_event in &summary.fileless_events {
            let fileless_log = DetectionLog {
                timestamp: fileless_event.timestamp,
                detection_type: format!("fileless_{:?}", fileless_event.technique),
                threat_score: fileless_event.suspicion_score,
                risk_level: if fileless_event.suspicion_score > 0.8 {
                    "High".to_string()
                } else {
                    "Medium".to_string()
                },
                pid: Some(fileless_event.pid),
                process_name: Some(fileless_event.comm.clone()),
                details: fileless_event.details.clone(),
                response_action: None,
                response_success: None,
            };
            self.log_detection(&fileless_log)?;
        }

        // Log responses if any
        if let Some(response_list) = responses {
            for response in response_list {
                let response_log = DetectionLog {
                    timestamp: response.timestamp,
                    detection_type: "automated_response".to_string(),
                    threat_score: 0.0,
                    risk_level: "Response".to_string(),
                    pid: None,
                    process_name: None,
                    details: response.details.clone(),
                    response_action: Some(format!("{:?}", response.action)),
                    response_success: Some(response.success),
                };
                self.log_detection(&response_log)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_creation() {
        let metrics = LotlMetrics::new();
        assert_eq!(metrics.get_scans_total(), 0);
        assert_eq!(metrics.get_threats_mitigated(), 0);
    }

    #[test]
    fn test_metrics_increment() {
        let metrics = LotlMetrics::new();
        metrics.increment_scan();
        metrics.increment_scan();
        assert_eq!(metrics.get_scans_total(), 2);

        metrics.increment_threat_mitigated();
        assert_eq!(metrics.get_threats_mitigated(), 1);
    }

    #[test]
    fn test_detection_counter() {
        let metrics = LotlMetrics::new();
        metrics.increment_detection("ReverseShell");
        metrics.increment_detection("ReverseShell");
        metrics.increment_detection("PythonExec");

        let prometheus = metrics.export_prometheus();
        assert!(prometheus.contains("winncore_lotl_detections_total"));
        assert!(prometheus.contains("ReverseShell"));
    }

    #[test]
    fn test_prometheus_export() {
        let metrics = LotlMetrics::new();
        metrics.increment_detection("ReverseShell");
        metrics.increment_response("KillProcess");
        metrics.increment_scan();

        let output = metrics.export_prometheus();
        assert!(output.contains("winncore_lotl_detections_total"));
        assert!(output.contains("winncore_responses_total"));
        assert!(output.contains("winncore_scans_total"));
        assert!(output.contains("winncore_threats_mitigated_total"));
    }
}
