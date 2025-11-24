pub mod bpf_types;
pub mod consumer;
pub mod events;
pub mod rulepack;
pub mod rules;

use consumer::{EbpfEventConsumer, ProcfsEventConsumer};
use events::*;
use rules::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tracing::{info, warn};

/// Main behavioral monitor that bridges eBPF events to the rule engine.
pub struct BehavioralMonitor {
    rule_engine: Arc<RwLock<RuleEngine>>,
    event_tx: broadcast::Sender<BehavioralEvent>,
    alert_tx: broadcast::Sender<RuleMatch>,
    running: Arc<AtomicBool>,
}

impl BehavioralMonitor {
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(10_000);
        let (alert_tx, _) = broadcast::channel(1_000);

        Self {
            rule_engine: Arc::new(RwLock::new(RuleEngine::new())),
            event_tx,
            alert_tx,
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<BehavioralEvent> {
        self.event_tx.subscribe()
    }

    pub fn subscribe_alerts(&self) -> broadcast::Receiver<RuleMatch> {
        self.alert_tx.subscribe()
    }

    /// Start monitoring. Attempts eBPF first, then falls back to procfs polling.
    pub async fn start(&self) -> anyhow::Result<()> {
        if self.running.swap(true, Ordering::SeqCst) {
            anyhow::bail!("monitor already running");
        }

        let (tx, mut rx) = mpsc::channel(2048);

        match EbpfEventConsumer::from_pinned(tx.clone()) {
            Ok(mut consumer) => {
                info!("eBPF consumer active");
                tokio::spawn(async move {
                    let _ = consumer.run().await;
                });
            }
            Err(e) => {
                warn!("eBPF unavailable ({}), falling back to procfs", e);
                let mut consumer = ProcfsEventConsumer::new(tx.clone());
                tokio::spawn(async move {
                    let _ = consumer.run().await;
                });
            }
        }

        let engine = self.rule_engine.clone();
        let alerts = self.alert_tx.clone();
        let events = self.event_tx.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                let _ = events.send(event.clone());

                let engine = engine.read().await;
                for m in engine.evaluate(&event) {
                    let _ = alerts.send(m);
                }

                if !running.load(Ordering::SeqCst) {
                    break;
                }
            }
        });

        // Keep consumer task alive
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Load additional rules (e.g., from hot reload).
    pub async fn load_rules(&self, rules: Vec<BehavioralRule>) {
        let mut engine = self.rule_engine.write().await;
        engine.load_rules(rules);
    }
}

impl Default for BehavioralMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn monitor_starts() {
        let monitor = BehavioralMonitor::new();
        assert!(monitor.start().await.is_ok());
        monitor.stop();
    }

    #[tokio::test]
    async fn rule_engine_matches_sensitive_file() {
        let engine = RuleEngine::new();
        let event = BehavioralEvent {
            timestamp: chrono::Utc::now(),
            event_type: EventType::FileOpen(FileOpenEvent {
                path: "/etc/shadow".into(),
                flags: 0,
                mode: 0,
                is_sensitive: true,
                is_executable: false,
            }),
            pid: 1,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: "test".into(),
            exe_path: "/bin/test".into(),
            cmdline: "/bin/test".into(),
            cwd: "/".into(),
            severity: Severity::Info,
            mitre_techniques: vec![],
            raw_data: std::collections::HashMap::new(),
        };

        let matches = engine.evaluate(&event);
        assert!(!matches.is_empty());
    }
}
