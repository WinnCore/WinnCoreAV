#![allow(dead_code, unused_imports)]
//! Graceful shutdown coordination for the daemon

use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{broadcast, watch, Mutex};
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Shutdown coordinator for managing graceful shutdown
pub struct ShutdownCoordinator {
    /// Signal to initiate shutdown
    shutdown_tx: broadcast::Sender<()>,

    /// Watch channel for shutdown completion status
    completion_tx: watch::Sender<bool>,
    completion_rx: watch::Receiver<bool>,

    /// Registered shutdown handlers
    handlers: Mutex<Vec<ShutdownHandler>>,

    /// Maximum time to wait for graceful shutdown
    timeout: Duration,
}

struct ShutdownHandler {
    name: String,
    handler: Box<
        dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync,
    >,
    priority: u32,
}

impl ShutdownCoordinator {
    pub fn new(timeout: Duration) -> Arc<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (completion_tx, completion_rx) = watch::channel(false);

        Arc::new(Self {
            shutdown_tx,
            completion_tx,
            completion_rx,
            handlers: Mutex::new(Vec::new()),
            timeout,
        })
    }

    /// Subscribe to shutdown signals
    pub fn subscribe(&self) -> broadcast::Receiver<()> {
        self.shutdown_tx.subscribe()
    }

    /// Get a receiver for completion status
    pub fn completion_receiver(&self) -> watch::Receiver<bool> {
        self.completion_rx.clone()
    }

    /// Register a shutdown handler with priority (higher = runs first)
    pub async fn register_handler<F, Fut>(&self, name: impl Into<String>, priority: u32, handler: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        let wrapped = Box::new(move || {
            let fut = handler();
            Box::pin(fut) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        });

        let mut handlers = self.handlers.lock().await;
        handlers.push(ShutdownHandler {
            name,
            handler: wrapped,
            priority,
        });

        handlers.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Initiate graceful shutdown
    pub async fn shutdown(&self) {
        info!("Initiating graceful shutdown...");

        let _ = self.shutdown_tx.send(());

        let handlers = self.handlers.lock().await;

        for handler in handlers.iter() {
            info!(handler = %handler.name, "Running shutdown handler");

            let fut = (handler.handler)();
            match timeout(Duration::from_secs(10), fut).await {
                Ok(()) => {
                    info!(handler = %handler.name, "Shutdown handler completed");
                }
                Err(_) => {
                    warn!(handler = %handler.name, "Shutdown handler timed out");
                }
            }
        }

        info!("Graceful shutdown complete");
        let _ = self.completion_tx.send(true);
    }

    /// Wait for shutdown to complete with timeout
    pub async fn wait_for_completion(&self) -> bool {
        let mut rx = self.completion_rx.clone();

        let wait_future = rx.wait_for(|&completed| completed);
        let result = timeout(self.timeout, wait_future).await;

        match result {
            Ok(Ok(_)) => {
                info!("Shutdown completed successfully");
                true
            }
            Ok(Err(_)) => {
                error!("Shutdown completion channel closed unexpectedly");
                false
            }
            Err(_) => {
                error!("Shutdown timed out after {:?}", self.timeout);
                false
            }
        }
    }
}

/// Install signal handlers for graceful shutdown
pub async fn install_signal_handlers(coordinator: Arc<ShutdownCoordinator>) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(sig) => sig,
        Err(e) => {
            error!(error = %e, "Failed to install SIGTERM handler");
            return;
        }
    };
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(sig) => sig,
        Err(e) => {
            error!(error = %e, "Failed to install SIGINT handler");
            return;
        }
    };
    let mut sigquit = match signal(SignalKind::quit()) {
        Ok(sig) => sig,
        Err(e) => {
            error!(error = %e, "Failed to install SIGQUIT handler");
            return;
        }
    };

    let coordinator_clone = coordinator.clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
            _ = sigquit.recv() => {
                info!("Received SIGQUIT");
            }
        }

        // Flush async stdout/stderr before triggering shutdown to preserve logs.
        if let Err(e) = tokio::io::stdout().flush().await {
            warn!(error = %e, "Failed to flush stdout during shutdown");
        }
        if let Err(e) = tokio::io::stderr().flush().await {
            warn!(error = %e, "Failed to flush stderr during shutdown");
        }

        coordinator_clone.shutdown().await;
    });
}
