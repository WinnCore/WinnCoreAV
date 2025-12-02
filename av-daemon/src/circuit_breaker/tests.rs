use super::*;
use std::time::Duration;

#[tokio::test]
async fn test_circuit_breaker_opens_after_failures() {
    let config = CircuitBreakerConfig {
        failure_threshold: 3,
        ..Default::default()
    };
    let cb = CircuitBreaker::new("test", config);

    assert_eq!(cb.state(), CircuitState::Closed);

    for _ in 0..3 {
        cb.record_failure();
    }

    assert_eq!(cb.state(), CircuitState::Open);
}

#[tokio::test]
async fn test_circuit_breaker_half_open_recovery() {
    let config = CircuitBreakerConfig {
        failure_threshold: 1,
        recovery_timeout: Duration::from_millis(10),
        success_threshold: 2,
        ..Default::default()
    };
    let cb = CircuitBreaker::new("test", config);

    cb.record_failure();
    assert_eq!(cb.state(), CircuitState::Open);

    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(cb.allow_call());
    assert_eq!(cb.state(), CircuitState::HalfOpen);

    cb.record_success();
    cb.record_success();

    assert_eq!(cb.state(), CircuitState::Closed);
}
