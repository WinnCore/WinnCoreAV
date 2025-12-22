//! Alert router - sends alerts to multiple destinations
//!
//! Manages multiple SIEM outputs with filtering and routing rules.

use super::{AlertSender, SiemError};
use crate::alert::{Alert, Severity};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Route configuration for alert filtering
#[derive(Clone)]
pub struct RouteConfig {
    pub name: String,
    pub sender: Arc<dyn AlertSender>,
    pub min_severity: Severity,
    pub rule_ids: Option<Vec<String>>, // None = all rules
    pub enabled: bool,
}

/// Alert router manages multiple output destinations
pub struct AlertRouter {
    routes: RwLock<Vec<RouteConfig>>,
    local_log: bool,
    buffer_sender: Option<Arc<dyn AlertSender>>,
}

impl AlertRouter {
    pub fn new(local_log: bool) -> Self {
        Self {
            routes: RwLock::new(Vec::new()),
            local_log,
            buffer_sender: None,
        }
    }

    pub fn with_buffer_sender(mut self, sender: Arc<dyn AlertSender>) -> Self {
        self.buffer_sender = Some(sender);
        self
    }

    pub async fn add_route(&self, config: RouteConfig) {
        let mut routes = self.routes.write().await;
        info!(
            "Adding SIEM route: {} (min_severity={:?})",
            config.name, config.min_severity
        );
        routes.push(config);
    }

    #[allow(dead_code)]
    pub async fn remove_route(&self, name: &str) {
        let mut routes = self.routes.write().await;
        routes.retain(|r| r.name != name);
        info!("Removed SIEM route: {}", name);
    }

    pub async fn set_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut routes = self.routes.write().await;
        for route in routes.iter_mut() {
            if route.name == name {
                route.enabled = enabled;
                info!("Route {} enabled={}", name, enabled);
                return true;
            }
        }
        false
    }

    /// Route an alert to all matching destinations
    pub async fn route(&self, alert: &Alert) -> Vec<Result<(), SiemError>> {
        let routes = self.routes.read().await;
        let mut results = Vec::new();

        let mut attempted = 0usize;
        let mut succeeded = 0usize;

        for route in routes.iter() {
            if !route.enabled {
                continue;
            }

            if alert.severity < route.min_severity {
                continue;
            }

            if let Some(ref allowed_rules) = route.rule_ids {
                if !allowed_rules.contains(&alert.rule_id) {
                    continue;
                }
            }

            attempted += 1;
            debug!(
                "Routing alert {} to {} ({})",
                alert.id,
                route.name,
                route.sender.name()
            );
            let result = route.sender.send(alert).await;

            if result.is_ok() {
                succeeded += 1;
            } else if let Err(ref e) = result {
                error!(
                    "Failed to send alert to {} ({}): {}",
                    route.name,
                    route.sender.name(),
                    e
                );
            }

            results.push(result);
        }

        if attempted == 0 {
            warn!("No SIEM routes matched alert {}", alert.id);
        }

        // Buffer locally only if nothing was delivered.
        if succeeded == 0 {
            if let Some(ref buffer) = self.buffer_sender {
                if let Err(e) = buffer.send(alert).await {
                    error!("Failed to buffer alert locally: {}", e);
                }
            }
        }

        // Always log locally if enabled.
        if self.local_log {
            info!(
                alert_id = %alert.id,
                rule_id = %alert.rule_id,
                severity = ?alert.severity,
                mitre = ?alert.mitre.as_ref().map(|m| &m.technique_id),
                "Alert generated"
            );
        }

        results
    }

    pub async fn status(&self) -> Vec<(String, bool)> {
        let routes = self.routes.read().await;
        routes
            .iter()
            .map(|r| (r.name.clone(), r.enabled))
            .collect()
    }
}

impl Default for AlertRouter {
    fn default() -> Self {
        Self::new(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{DetectionSource, Severity};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSender {
        name: String,
        count: AtomicUsize,
    }

    impl CountingSender {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl AlertSender for CountingSender {
        async fn send(&self, _alert: &Alert) -> Result<(), SiemError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn name(&self) -> &str {
            self.name.as_str()
        }
    }

    #[tokio::test]
    async fn filters_by_severity() {
        let router = AlertRouter::new(false);
        router
            .add_route(RouteConfig {
                name: "count".to_string(),
                sender: Arc::new(CountingSender::new("count")),
                min_severity: Severity::High,
                rule_ids: None,
                enabled: true,
            })
            .await;

        let low = Alert::new(
            "TEST-001",
            "Test Alert",
            "hello",
            Severity::Low,
            DetectionSource::Heuristic,
        );
        let high = Alert::new(
            "TEST-002",
            "Test Alert",
            "hello",
            Severity::High,
            DetectionSource::Heuristic,
        );

        assert_eq!(router.route(&low).await.len(), 0);
        assert_eq!(router.route(&high).await.len(), 1);
    }
}
