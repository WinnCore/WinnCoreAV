//! Integration tests for hardening infrastructure

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

use av_core::bounded::{BoundedMap, BoundedQueue, RateLimitedCounter};
use av_core::logging::{LogConfig, LogSampler};
use av_core::retry::{RetryConfig, RetryableError, with_retry};

/// High-throughput stress test that previously failed due to logging overhead
#[tokio::test]
async fn test_high_throughput_scanning_with_sampling() {
    let config = LogConfig {
        level: "warn".to_string(),
        enable_sampling: true,
        ml_inference_sample_rate: 1000,
        file_scan_sample_rate: 100,
        max_logs_per_second: 100,
        ..Default::default()
    };

    let sampler = Arc::new(LogSampler::new(&config));

    let total_ops = 50_000;
    let concurrency = 100;
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let start = Instant::now();
    let mut handles = Vec::new();

    for i in 0..total_ops {
        let sampler = sampler.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            if sampler.should_log_ml_inference() && sampler.check_rate_limit() {
                // sampled log would go here
            }
            tokio::time::sleep(Duration::from_micros(10)).await;
            drop(permit);
            i
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "Stress test took too long: {:?}",
        elapsed
    );

    let stats = sampler.get_stats();
    assert!(
        stats.ml_logged < stats.ml_total / 100,
        "ML logging not sufficiently sampled"
    );
}

/// Test retry logic under load
#[tokio::test]
async fn test_retry_under_load() {
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug)]
    struct TestError(String);

    impl std::fmt::Display for TestError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl RetryableError for TestError {
        fn is_retryable(&self) -> bool {
            true
        }
    }

    let config = RetryConfig {
        max_attempts: 3,
        initial_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(10),
        multiplier: 2.0,
        jitter_factor: 0.0,
        attempt_timeout: Some(Duration::from_millis(100)),
    };

    let success_count = Arc::new(AtomicU32::new(0));
    let total_attempts = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();

    for i in 0..100 {
        let config = config.clone();
        let success = success_count.clone();
        let attempts = total_attempts.clone();

        handles.push(tokio::spawn(async move {
            let fail_until = i % 3;
            let attempt_counter = Arc::new(AtomicU32::new(0));
            let counter = attempt_counter.clone();

            let result = with_retry(&config, "test_op", || {
                let c = counter.clone();
                async move {
                    let attempt = c.fetch_add(1, Ordering::SeqCst);
                    if attempt < fail_until {
                        Err(TestError("transient".to_string()))
                    } else {
                        Ok(i)
                    }
                }
            })
            .await;

            attempts.fetch_add(attempt_counter.load(Ordering::SeqCst), Ordering::SeqCst);
            if result.result.is_ok() {
                success.fetch_add(1, Ordering::SeqCst);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let successes = success_count.load(Ordering::SeqCst);
    let total = total_attempts.load(Ordering::SeqCst);

    assert_eq!(successes, 100, "All operations should eventually succeed");
    assert!(total > 100, "Should have needed retries");
}

/// Test bounded collections under concurrent access
#[tokio::test]
async fn test_bounded_collections_concurrent() {
    let queue: Arc<BoundedQueue<u64>> = Arc::new(BoundedQueue::new(100));
    let map: Arc<BoundedMap<u64, String>> = Arc::new(BoundedMap::new(100));

    let mut handles = Vec::new();

    for i in 0..10 {
        let q = queue.clone();
        let m = map.clone();
        handles.push(tokio::spawn(async move {
            for j in 0..1000 {
                let key = i * 1000 + j;
                q.push(key);
                m.insert(key, format!("value_{}", key));
            }
        }));
    }

    for _ in 0..5 {
        let q = queue.clone();
        handles.push(tokio::spawn(async move {
            let mut consumed = 0;
            while consumed < 1000 {
                if q.pop().is_some() {
                    consumed += 1;
                }
                tokio::task::yield_now().await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let q_stats = queue.stats();
    let m_stats = map.stats();

    assert!(q_stats.total_dropped > 0, "Queue should have dropped items");
    assert!(m_stats.total_evicted > 0, "Map should have evicted items");
    assert!(q_stats.current_size <= 100);
    assert!(m_stats.current_size <= 100);
}

/// Test rate limiter under burst load
#[tokio::test]
async fn test_rate_limiter_burst() {
    let limiter = Arc::new(RateLimitedCounter::new(100, Duration::from_secs(1)));
    let mut handles = Vec::new();
    let allowed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let rejected = Arc::new(std::sync::atomic::AtomicU32::new(0));

    for _ in 0..1000 {
        let l = limiter.clone();
        let a = allowed.clone();
        let r = rejected.clone();
        handles.push(tokio::spawn(async move {
            if l.try_acquire() {
                a.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                r.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let allowed_count = allowed.load(std::sync::atomic::Ordering::Relaxed);
    let rejected_count = rejected.load(std::sync::atomic::Ordering::Relaxed);

    assert!(allowed_count <= 100, "Should not exceed rate limit");
    assert!(rejected_count >= 900, "Should reject excess requests");
}
