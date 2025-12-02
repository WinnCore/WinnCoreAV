use super::*;

#[test]
fn test_log_sampler_ml_sampling() {
    let config = LogConfig {
        ml_inference_sample_rate: 10,
        ..Default::default()
    };
    let sampler = LogSampler::new(&config);

    let mut logged = 0;
    for _ in 0..100 {
        if sampler.should_log_ml_inference() {
            logged += 1;
        }
    }

    assert_eq!(logged, 10, "Should log 10 out of 100 with rate=10");
}

#[test]
fn test_rate_limiting() {
    let config = LogConfig {
        max_logs_per_second: 10,
        ..Default::default()
    };
    let sampler = LogSampler::new(&config);

    let mut allowed = 0;
    for _ in 0..100 {
        if sampler.check_rate_limit() {
            allowed += 1;
        }
    }

    assert!(
        allowed <= 10,
        "Rate limiter should cap at 10 logs/second (allowed={allowed})"
    );
}
