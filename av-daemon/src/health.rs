#![allow(dead_code, unused_imports)]
//! Health check infrastructure for daemon subsystems

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use serde::Serialize;

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerStats, CircuitState};
use crate::error::Subsystem;

/// Overall daemon health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some non-critical subsystems degraded
    Degraded,
    /// Critical subsystem failure
    Unhealthy,
}

/// Health information for a single subsystem
#[derive(Debug, Clone, Serialize)]
pub struct SubsystemHealth {
    pub name: String,
    pub status: HealthStatus,
    pub message: Option<String>,
    pub last_check: chrono::DateTime<chrono::Utc>,
    pub consecutive_failures: u32,
    pub circuit_breaker: Option<CircuitBreakerStats>,
}

/// Complete health report for the daemon
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    pub status: HealthStatus,
    pub uptime_seconds: u64,
    pub subsystems: HashMap<String, SubsystemHealth>,
    pub degraded_subsystems: Vec<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Health check manager
pub struct HealthChecker {
    start_time: Instant,
    subsystems: RwLock<HashMap<Subsystem, SubsystemHealth>>,
    circuit_breakers: RwLock<HashMap<Subsystem, Arc<CircuitBreaker>>>,
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            subsystems: RwLock::new(HashMap::new()),
            circuit_breakers: RwLock::new(HashMap::new()),
        }
    }

    /// Register a subsystem with its circuit breaker
    pub async fn register_subsystem(
        &self,
        subsystem: Subsystem,
        circuit_breaker: Arc<CircuitBreaker>,
    ) {
        let health = SubsystemHealth {
            name: subsystem.name().to_string(),
            status: HealthStatus::Healthy,
            message: None,
            last_check: chrono::Utc::now(),
            consecutive_failures: 0,
            circuit_breaker: Some(circuit_breaker.stats()),
        };

        self.subsystems.write().await.insert(subsystem, health);
        self.circuit_breakers
            .write()
            .await
            .insert(subsystem, circuit_breaker);
    }

    /// Update subsystem health status
    pub async fn update_status(
        &self,
        subsystem: Subsystem,
        status: HealthStatus,
        message: Option<String>,
    ) {
        let mut subsystems = self.subsystems.write().await;
        if let Some(health) = subsystems.get_mut(&subsystem) {
            if status == HealthStatus::Healthy {
                health.consecutive_failures = 0;
            } else {
                health.consecutive_failures += 1;
            }
            health.status = status;
            health.message = message;
            health.last_check = chrono::Utc::now();

            if let Some(cb) = self.circuit_breakers.read().await.get(&subsystem) {
                health.circuit_breaker = Some(cb.stats());
            }
        }
    }

    /// Record a successful operation for a subsystem
    pub async fn record_success(&self, subsystem: Subsystem) {
        self.update_status(subsystem, HealthStatus::Healthy, None)
            .await;
    }

    /// Record a failed operation for a subsystem
    pub async fn record_failure(&self, subsystem: Subsystem, error: &str) {
        let status = if subsystem.is_critical() {
            HealthStatus::Unhealthy
        } else {
            HealthStatus::Degraded
        };
        self.update_status(subsystem, status, Some(error.to_string()))
            .await;
    }

    /// Generate a complete health report
    pub async fn report(&self) -> HealthReport {
        let subsystems_read = self.subsystems.read().await;
        let circuit_breakers = self.circuit_breakers.read().await;

        let mut subsystems_map = HashMap::new();
        let mut degraded = Vec::new();
        let mut overall_status = HealthStatus::Healthy;

        for (key, mut health) in subsystems_read.iter().map(|(k, v)| (*k, v.clone())) {
            if let Some(cb) = circuit_breakers.get(&key) {
                let stats = cb.stats();
                health.circuit_breaker = Some(stats.clone());

                if stats.state == CircuitState::Open {
                    if key.is_critical() {
                        health.status = HealthStatus::Unhealthy;
                    } else {
                        health.status = HealthStatus::Degraded;
                    }
                }
            }

            if health.status == HealthStatus::Degraded {
                degraded.push(health.name.clone());
                if overall_status == HealthStatus::Healthy {
                    overall_status = HealthStatus::Degraded;
                }
            } else if health.status == HealthStatus::Unhealthy {
                overall_status = HealthStatus::Unhealthy;
            }

            subsystems_map.insert(health.name.clone(), health);
        }

        HealthReport {
            status: overall_status,
            uptime_seconds: self.start_time.elapsed().as_secs(),
            subsystems: subsystems_map,
            degraded_subsystems: degraded,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Check if daemon should continue running
    pub async fn is_viable(&self) -> bool {
        let report = self.report().await;
        report.status != HealthStatus::Unhealthy
    }
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}
