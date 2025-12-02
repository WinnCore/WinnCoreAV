//! Retry logic with exponential backoff and jitter

use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

/// Configuration for retry behavior
#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay: Duration,
    pub max_delay: Duration,
    pub multiplier: f64,
    pub jitter_factor: f64,
    pub attempt_timeout: Option<Duration>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter_factor: 0.1,
            attempt_timeout: None,
        }
    }
}

impl RetryConfig {
    pub fn fast() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(10),
            max_delay: Duration::from_millis(500),
            multiplier: 2.0,
            jitter_factor: 0.1,
            attempt_timeout: Some(Duration::from_millis(100)),
        }
    }

    pub fn aggressive() -> Self {
        Self {
            max_attempts: 10,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(30),
            multiplier: 1.5,
            jitter_factor: 0.2,
            attempt_timeout: Some(Duration::from_secs(5)),
        }
    }

    pub fn conservative() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            multiplier: 3.0,
            jitter_factor: 0.3,
            attempt_timeout: Some(Duration::from_secs(30)),
        }
    }

    /// Calculate delay for a given attempt number (0-indexed)
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let base_delay = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped_delay = base_delay.min(self.max_delay.as_secs_f64());

        let jitter = if self.jitter_factor > 0.0 {
            let mut rng = rand::thread_rng();
            let jitter_range = capped_delay * self.jitter_factor;
            rng.gen_range(-jitter_range..jitter_range)
        } else {
            0.0
        };

        Duration::from_secs_f64((capped_delay + jitter).max(0.0))
    }
}

/// Result of a retry operation
#[derive(Debug)]
pub struct RetryResult<T, E> {
    pub result: Result<T, E>,
    pub attempts: u32,
    pub total_duration: Duration,
    pub exhausted: bool,
}

/// Error classification for retry decisions
pub trait RetryableError {
    fn is_retryable(&self) -> bool;
    fn retry_after(&self) -> Option<Duration> {
        None
    }
}

/// Execute an async operation with retry logic
pub async fn with_retry<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> RetryResult<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display + RetryableError,
{
    let start = std::time::Instant::now();
    let mut last_error: Option<E> = None;

    for attempt in 0..=config.max_attempts {
        let result = if let Some(timeout) = config.attempt_timeout {
            match tokio::time::timeout(timeout, operation()).await {
                Ok(r) => r,
                Err(_) => {
                    warn!(
                        operation = operation_name,
                        attempt = attempt + 1,
                        max_attempts = config.max_attempts + 1,
                        "Attempt timed out"
                    );
                    continue;
                }
            }
        } else {
            operation().await
        };

        match result {
            Ok(value) => {
                if attempt > 0 {
                    debug!(
                        operation = operation_name,
                        attempts = attempt + 1,
                        "Operation succeeded after retries"
                    );
                }
                return RetryResult {
                    result: Ok(value),
                    attempts: attempt + 1,
                    total_duration: start.elapsed(),
                    exhausted: false,
                };
            }
            Err(e) => {
                let is_last_attempt = attempt >= config.max_attempts;

                let retryable = e.is_retryable();
                if !retryable || is_last_attempt {
                    if !retryable {
                        debug!(
                            operation = operation_name,
                            error = %e,
                            "Non-retryable error"
                        );
                    } else {
                        warn!(
                            operation = operation_name,
                            error = %e,
                            attempts = attempt + 1,
                            "Exhausted all retry attempts"
                        );
                    }
                    return RetryResult {
                        result: Err(e),
                        attempts: attempt + 1,
                        total_duration: start.elapsed(),
                        exhausted: is_last_attempt && retryable,
                    };
                }

                let delay = e
                    .retry_after()
                    .unwrap_or_else(|| config.delay_for_attempt(attempt));
                warn!(
                    operation = operation_name,
                    error = %e,
                    attempt = attempt + 1,
                    max_attempts = config.max_attempts + 1,
                    delay_ms = delay.as_millis(),
                    "Retryable error, will retry"
                );

                last_error = Some(e);
                sleep(delay).await;
            }
        }
    }

    RetryResult {
        result: Err(last_error.expect("Should have at least one error")),
        attempts: config.max_attempts + 1,
        total_duration: start.elapsed(),
        exhausted: true,
    }
}

/// Execute operation with retry, using a closure that receives attempt number
pub async fn with_retry_context<F, Fut, T, E>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
) -> RetryResult<T, E>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display + RetryableError,
{
    let start = std::time::Instant::now();

    for attempt in 0..=config.max_attempts {
        let result = if let Some(timeout) = config.attempt_timeout {
            match tokio::time::timeout(timeout, operation(attempt)).await {
                Ok(r) => r,
                Err(_) => continue,
            }
        } else {
            operation(attempt).await
        };

        match result {
            Ok(value) => {
                return RetryResult {
                    result: Ok(value),
                    attempts: attempt + 1,
                    total_duration: start.elapsed(),
                    exhausted: false,
                };
            }
            Err(e) => {
                let is_last_attempt = attempt >= config.max_attempts;

                let retryable = e.is_retryable();
                if !retryable || is_last_attempt {
                    return RetryResult {
                        result: Err(e),
                        attempts: attempt + 1,
                        total_duration: start.elapsed(),
                        exhausted: is_last_attempt && retryable,
                    };
                }

                let delay = e
                    .retry_after()
                    .unwrap_or_else(|| config.delay_for_attempt(attempt));
                sleep(delay).await;
            }
        }
    }

    unreachable!("Loop should have returned")
}

/// Common retryable error wrapper
#[derive(Debug)]
pub struct TransientError<E> {
    pub inner: E,
    pub retryable: bool,
    pub retry_after: Option<Duration>,
}

impl<E> TransientError<E> {
    pub fn retryable(inner: E) -> Self {
        Self {
            inner,
            retryable: true,
            retry_after: None,
        }
    }

    pub fn non_retryable(inner: E) -> Self {
        Self {
            inner,
            retryable: false,
            retry_after: None,
        }
    }

    pub fn with_retry_after(mut self, duration: Duration) -> Self {
        self.retry_after = Some(duration);
        self
    }
}

impl<E: std::fmt::Display> std::fmt::Display for TransientError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl<E: std::error::Error + 'static> std::error::Error for TransientError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.inner)
    }
}

impl<E> RetryableError for TransientError<E> {
    fn is_retryable(&self) -> bool {
        self.retryable
    }

    fn retry_after(&self) -> Option<Duration> {
        self.retry_after
    }
}

impl RetryableError for std::io::Error {
    fn is_retryable(&self) -> bool {
        use std::io::ErrorKind::*;
        matches!(
            self.kind(),
            ConnectionReset
                | ConnectionAborted
                | NotConnected
                | TimedOut
                | Interrupted
                | WouldBlock
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[derive(Debug)]
    struct TestError {
        retryable: bool,
        message: String,
    }

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.message)
        }
    }

    impl RetryableError for TestError {
        fn is_retryable(&self) -> bool {
            self.retryable
        }
    }

    #[tokio::test]
    async fn test_succeeds_first_try() {
        let config = RetryConfig::default();
        let result: RetryResult<i32, TestError> =
            with_retry(&config, "test", || async { Ok(42) }).await;

        assert!(result.result.is_ok());
        assert_eq!(result.attempts, 1);
        assert!(!result.exhausted);
    }

    #[tokio::test]
    async fn test_succeeds_after_retry() {
        let config = RetryConfig {
            max_attempts: 3,
            initial_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result: RetryResult<i32, TestError> = with_retry(&config, "test", || {
            let c = counter_clone.clone();
            async move {
                let count = c.fetch_add(1, Ordering::SeqCst);
                if count < 2 {
                    Err(TestError {
                        retryable: true,
                        message: "transient".to_string(),
                    })
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert!(result.result.is_ok());
        assert_eq!(result.attempts, 3);
    }

    #[tokio::test]
    async fn test_exhausts_retries() {
        let config = RetryConfig {
            max_attempts: 2,
            initial_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let result: RetryResult<i32, TestError> = with_retry(&config, "test", || async {
            Err(TestError {
                retryable: true,
                message: "always fails".to_string(),
            })
        })
        .await;

        assert!(result.result.is_err());
        assert_eq!(result.attempts, 3);
        assert!(result.exhausted);
    }

    #[tokio::test]
    async fn test_non_retryable_fails_immediately() {
        let config = RetryConfig::default();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result: RetryResult<i32, TestError> = with_retry(&config, "test", || {
            let c = counter_clone.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Err(TestError {
                    retryable: false,
                    message: "permanent".to_string(),
                })
            }
        })
        .await;

        assert!(result.result.is_err());
        assert_eq!(result.attempts, 1);
        assert!(!result.exhausted);
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_delay_calculation() {
        let config = RetryConfig {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
            jitter_factor: 0.0,
            ..Default::default()
        };

        assert_eq!(config.delay_for_attempt(0), Duration::from_millis(100));
        assert_eq!(config.delay_for_attempt(1), Duration::from_millis(200));
        assert_eq!(config.delay_for_attempt(2), Duration::from_millis(400));
        assert_eq!(config.delay_for_attempt(10), Duration::from_secs(10));
    }
}
