use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;

/// Stress test that simulates high-throughput scanning
/// This previously failed due to logging overhead
#[tokio::test]
async fn test_high_throughput_scanning() {
    let config = av_core::logging::LogConfig {
        level: "warn".to_string(),
        enable_sampling: true,
        ml_inference_sample_rate: 1000,
        max_logs_per_second: 100,
        ..Default::default()
    };

    let sampler = Arc::new(av_core::logging::LogSampler::new(&config));

    let total_ops = 50_000;
    let concurrency = 100;
    let semaphore = Arc::new(Semaphore::new(concurrency));

    let start = Instant::now();
    let mut handles = Vec::new();

    for _ in 0..total_ops {
        let sampler = sampler.clone();
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        handles.push(tokio::spawn(async move {
            if sampler.should_log_ml_inference() && sampler.check_rate_limit() {}
            tokio::time::sleep(Duration::from_micros(10)).await;
            drop(permit);
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    let elapsed = start.elapsed();
    let ops_per_second = total_ops as f64 / elapsed.as_secs_f64();

    println!("Completed {} operations in {:?}", total_ops, elapsed);
    println!("Throughput: {:.0} ops/second", ops_per_second);

    assert!(
        elapsed < Duration::from_secs(30),
        "Stress test took too long: {:?}",
        elapsed
    );

    let stats = sampler.get_stats();
    println!("Sampling stats: {:?}", stats);

    assert!(
        stats.ml_logged < stats.ml_total / 100,
        "ML logging not sufficiently sampled"
    );
}
