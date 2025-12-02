#![allow(dead_code, unused_imports)]
//! Circuit breaker pattern for failing subsystems

use serde::Serialize;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CircuitState {
    /// Normal operation - requests flow through
    Closed,
    /// Too many failures - requests are blocked
    Open,
    /// Testing if service recovered - limited requests allowed
    HalfOpen,
}

/// Configuration for circuit breaker behavior
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit
    pub failure_threshold: u32,
    /// How long to wait before attempting recovery (half-open state)
    pub recovery_timeout: Duration,
    /// Number of successful calls needed to close the circuit from half-open
    pub success_threshold: u32,
    /// Window for counting failures (failures reset after this time)
    pub failure_window: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout: Duration::from_secs(30),
            success_threshold: 3,
            failure_window: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker for protecting against cascading failures
pub struct CircuitBreaker {
    name: String,
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_time: RwLock<Option<Instant>>,
    opened_at: RwLock<Option<Instant>>,
    total_calls: AtomicU64,
    total_failures: AtomicU64,
    total_rejections: AtomicU64,
}

impl CircuitBreaker {
    pub fn new(name: impl Into<String>, config: CircuitBreakerConfig) -> Self {
        Self {
            name: name.into(),
            config,
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_time: RwLock::new(None),
            opened_at: RwLock::new(None),
            total_calls: AtomicU64::new(0),
            total_failures: AtomicU64::new(0),
            total_rejections: AtomicU64::new(0),
        }
    }

    /// Check if a call should be allowed through
    pub fn allow_call(&self) -> bool {
        self.total_calls.fetch_add(1, Ordering::Relaxed);

        let state = *self.state.read().unwrap();

        match state {
            CircuitState::Closed => {
                if let Some(last_failure) = *self.last_failure_time.read().unwrap() {
                    if last_failure.elapsed() > self.config.failure_window {
                        self.failure_count.store(0, Ordering::Relaxed);
                    }
                }
                true
            }
            CircuitState::Open => {
                if let Some(opened_at) = *self.opened_at.read().unwrap() {
                    if opened_at.elapsed() > self.config.recovery_timeout {
                        let mut state = self.state.write().unwrap();
                        if *state == CircuitState::Open {
                            *state = CircuitState::HalfOpen;
                            self.success_count.store(0, Ordering::Relaxed);
                            info!(
                                circuit = %self.name,
                                "Circuit breaker transitioning to half-open"
                            );
                        }
                        true
                    } else {
                        self.total_rejections.fetch_add(1, Ordering::Relaxed);
                        false
                    }
                } else {
                    self.total_rejections.fetch_add(1, Ordering::Relaxed);
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful call
    pub fn record_success(&self) {
        let state = *self.state.read().unwrap();

        match state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.success_threshold {
                    let mut state = self.state.write().unwrap();
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    *self.opened_at.write().unwrap() = None;
                    info!(
                        circuit = %self.name,
                        "Circuit breaker closed - service recovered"
                    );
                }
            }
            CircuitState::Closed => {}
            CircuitState::Open => {}
        }
    }

    /// Record a failed call
    pub fn record_failure(&self) {
        self.total_failures.fetch_add(1, Ordering::Relaxed);
        *self.last_failure_time.write().unwrap() = Some(Instant::now());

        let state = *self.state.read().unwrap();

        match state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.failure_threshold {
                    let mut state = self.state.write().unwrap();
                    *state = CircuitState::Open;
                    *self.opened_at.write().unwrap() = Some(Instant::now());
                    error!(
                        circuit = %self.name,
                        failures = count,
                        "Circuit breaker opened due to failures"
                    );
                }
            }
            CircuitState::HalfOpen => {
                let mut state = self.state.write().unwrap();
                *state = CircuitState::Open;
                *self.opened_at.write().unwrap() = Some(Instant::now());
                self.success_count.store(0, Ordering::Relaxed);
                warn!(
                    circuit = %self.name,
                    "Circuit breaker re-opened from half-open state"
                );
            }
            CircuitState::Open => {}
        }
    }

    /// Get current circuit state
    pub fn state(&self) -> CircuitState {
        *self.state.read().unwrap()
    }

    /// Get statistics
    pub fn stats(&self) -> CircuitBreakerStats {
        CircuitBreakerStats {
            name: self.name.clone(),
            state: self.state(),
            total_calls: self.total_calls.load(Ordering::Relaxed),
            total_failures: self.total_failures.load(Ordering::Relaxed),
            total_rejections: self.total_rejections.load(Ordering::Relaxed),
            current_failure_count: self.failure_count.load(Ordering::Relaxed),
        }
    }

    /// Execute a function with circuit breaker protection
    pub async fn call<F, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: std::future::Future<Output = Result<T, E>>,
    {
        if !self.allow_call() {
            return Err(CircuitBreakerError::Open(self.name.clone()));
        }

        match f.await {
            Ok(result) => {
                self.record_success();
                Ok(result)
            }
            Err(e) => {
                self.record_failure();
                Err(CircuitBreakerError::Inner(e))
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CircuitBreakerStats {
    pub name: String,
    pub state: CircuitState,
    pub total_calls: u64,
    pub total_failures: u64,
    pub total_rejections: u64,
    pub current_failure_count: u32,
}

#[derive(Debug)]
pub enum CircuitBreakerError<E> {
    /// Circuit is open, call was rejected
    Open(String),
    /// Call was allowed but the inner function failed
    Inner(E),
}

impl<E: std::fmt::Display> std::fmt::Display for CircuitBreakerError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitBreakerError::Open(name) => {
                write!(f, "Circuit breaker '{}' is open", name)
            }
            CircuitBreakerError::Inner(e) => {
                write!(f, "{}", e)
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CircuitBreakerError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CircuitBreakerError::Open(_) => None,
            CircuitBreakerError::Inner(e) => Some(e),
        }
    }
}

#[cfg(test)]
mod tests;
