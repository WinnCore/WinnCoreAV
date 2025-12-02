#![allow(dead_code, unused_imports)]
//! Prometheus metrics for observability

use lazy_static::lazy_static;
use prometheus::{
    histogram_opts, Encoder, Histogram, HistogramVec, IntCounter, IntCounterVec, IntGauge,
    IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::net::SocketAddr;

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();
    pub static ref FILES_SCANNED: IntCounter = IntCounter::new(
        "winncore_files_scanned_total",
        "Total number of files scanned"
    )
    .unwrap();
    pub static ref FILES_SCANNED_BY_RESULT: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "winncore_files_scanned_by_result_total",
            "Files scanned by detection result"
        ),
        &["result"]
    )
    .unwrap();
    pub static ref SCAN_QUEUE_DEPTH: IntGauge =
        IntGauge::new("winncore_scan_queue_depth", "Current scan queue depth").unwrap();
    pub static ref SCAN_DURATION: Histogram = Histogram::with_opts(histogram_opts!(
        "winncore_scan_duration_seconds",
        "Time taken to scan a file",
        prometheus::exponential_buckets(0.001, 2.0, 15).unwrap()
    ))
    .unwrap();
    pub static ref SCAN_DURATION_BY_DETECTOR: HistogramVec = HistogramVec::new(
        histogram_opts!(
            "winncore_scan_duration_by_detector_seconds",
            "Scan duration by detector type",
            prometheus::exponential_buckets(0.0001, 2.0, 15).unwrap()
        ),
        &["detector"]
    )
    .unwrap();
    pub static ref THREATS_DETECTED: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "winncore_threats_detected_total",
            "Total threats detected by severity and detector"
        ),
        &["severity", "detector"]
    )
    .unwrap();
    pub static ref THREAT_SCORES: Histogram = Histogram::with_opts(histogram_opts!(
        "winncore_threat_score",
        "Distribution of threat scores",
        prometheus::linear_buckets(0.0, 0.1, 11).unwrap()
    ))
    .unwrap();
    pub static ref QUARANTINE_OPERATIONS: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "winncore_quarantine_operations_total",
            "Quarantine operations by result"
        ),
        &["result"]
    )
    .unwrap();
    pub static ref ML_INFERENCES: IntCounter = IntCounter::new(
        "winncore_ml_inferences_total",
        "Total ML inference operations"
    )
    .unwrap();
    pub static ref ML_INFERENCE_DURATION: Histogram = Histogram::with_opts(histogram_opts!(
        "winncore_ml_inference_duration_seconds",
        "ML inference duration",
        prometheus::exponential_buckets(0.0001, 2.0, 12).unwrap()
    ))
    .unwrap();
    pub static ref ML_MODEL_LOADED: IntGauge = IntGauge::new(
        "winncore_ml_model_loaded",
        "Whether the ML model is loaded (1/0)"
    )
    .unwrap();
    pub static ref SIGNATURE_MATCHES: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "winncore_signature_matches_total",
            "Signature matches by rule name"
        ),
        &["rule_name"]
    )
    .unwrap();
    pub static ref SIGNATURE_RULES_LOADED: IntGauge = IntGauge::new(
        "winncore_signature_rules_loaded",
        "Number of signature rules currently loaded"
    )
    .unwrap();
    pub static ref UPTIME_SECONDS: IntGauge =
        IntGauge::new("winncore_uptime_seconds", "Daemon uptime in seconds").unwrap();
    pub static ref SUBSYSTEM_HEALTH: IntGaugeVec = IntGaugeVec::new(
        Opts::new(
            "winncore_subsystem_health",
            "Health status of subsystems (1 healthy, 0 degraded/unhealthy)"
        ),
        &["subsystem"]
    )
    .unwrap();
    pub static ref CIRCUIT_BREAKER_STATE: IntGaugeVec = IntGaugeVec::new(
        Opts::new(
            "winncore_circuit_breaker_state",
            "Circuit breaker state (0=closed,1=open,2=half-open)"
        ),
        &["circuit"]
    )
    .unwrap();
    pub static ref CIRCUIT_BREAKER_FAILURES: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "winncore_circuit_breaker_failures_total",
            "Circuit breaker failure count"
        ),
        &["circuit"]
    )
    .unwrap();
    pub static ref MEMORY_USAGE_BYTES: IntGauge = IntGauge::new(
        "winncore_memory_usage_bytes",
        "Current memory usage in bytes"
    )
    .unwrap();
    pub static ref OPEN_FDS: IntGauge = IntGauge::new(
        "winncore_open_file_descriptors",
        "Number of open file descriptors"
    )
    .unwrap();
    pub static ref ACTIVE_TASKS: IntGauge =
        IntGauge::new("winncore_active_tasks", "Number of active async tasks").unwrap();
    pub static ref FILE_EVENTS_RECEIVED: IntCounterVec = IntCounterVec::new(
        Opts::new(
            "winncore_file_events_received_total",
            "File events received by source"
        ),
        &["source"]
    )
    .unwrap();
    pub static ref EVENTS_DROPPED: IntCounter = IntCounter::new(
        "winncore_events_dropped_total",
        "Events dropped due to backpressure"
    )
    .unwrap();
    pub static ref EVENT_PROCESSING_LATENCY: Histogram = Histogram::with_opts(histogram_opts!(
        "winncore_event_processing_latency_seconds",
        "Time from event receipt to processing completion",
        prometheus::exponential_buckets(0.001, 2.0, 12).unwrap()
    ))
    .unwrap();
    pub static ref ERRORS: IntCounterVec = IntCounterVec::new(
        Opts::new("winncore_errors_total", "Errors by type and component"),
        &["type", "component"]
    )
    .unwrap();
    pub static ref RETRIES: IntCounterVec = IntCounterVec::new(
        Opts::new("winncore_retries_total", "Retry attempts by operation"),
        &["operation", "result"]
    )
    .unwrap();
}

/// Register all metrics with the registry
pub fn register_metrics() -> Result<(), prometheus::Error> {
    REGISTRY.register(Box::new(FILES_SCANNED.clone()))?;
    REGISTRY.register(Box::new(FILES_SCANNED_BY_RESULT.clone()))?;
    REGISTRY.register(Box::new(SCAN_QUEUE_DEPTH.clone()))?;
    REGISTRY.register(Box::new(SCAN_DURATION.clone()))?;
    REGISTRY.register(Box::new(SCAN_DURATION_BY_DETECTOR.clone()))?;
    REGISTRY.register(Box::new(THREATS_DETECTED.clone()))?;
    REGISTRY.register(Box::new(THREAT_SCORES.clone()))?;
    REGISTRY.register(Box::new(QUARANTINE_OPERATIONS.clone()))?;
    REGISTRY.register(Box::new(ML_INFERENCES.clone()))?;
    REGISTRY.register(Box::new(ML_INFERENCE_DURATION.clone()))?;
    REGISTRY.register(Box::new(ML_MODEL_LOADED.clone()))?;
    REGISTRY.register(Box::new(SIGNATURE_MATCHES.clone()))?;
    REGISTRY.register(Box::new(SIGNATURE_RULES_LOADED.clone()))?;
    REGISTRY.register(Box::new(UPTIME_SECONDS.clone()))?;
    REGISTRY.register(Box::new(SUBSYSTEM_HEALTH.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_BREAKER_STATE.clone()))?;
    REGISTRY.register(Box::new(CIRCUIT_BREAKER_FAILURES.clone()))?;
    REGISTRY.register(Box::new(MEMORY_USAGE_BYTES.clone()))?;
    REGISTRY.register(Box::new(OPEN_FDS.clone()))?;
    REGISTRY.register(Box::new(ACTIVE_TASKS.clone()))?;
    REGISTRY.register(Box::new(FILE_EVENTS_RECEIVED.clone()))?;
    REGISTRY.register(Box::new(EVENTS_DROPPED.clone()))?;
    REGISTRY.register(Box::new(EVENT_PROCESSING_LATENCY.clone()))?;
    REGISTRY.register(Box::new(ERRORS.clone()))?;
    REGISTRY.register(Box::new(RETRIES.clone()))?;
    Ok(())
}

/// Encode metrics to Prometheus text format
pub fn encode_metrics() -> String {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

/// Helper to record scan result
pub fn record_scan_result(result: &str, duration_secs: f64) {
    FILES_SCANNED.inc();
    FILES_SCANNED_BY_RESULT.with_label_values(&[result]).inc();
    SCAN_DURATION.observe(duration_secs);
}

/// Helper to record threat detection
pub fn record_threat(severity: &str, detector: &str, score: f64) {
    THREATS_DETECTED
        .with_label_values(&[severity, detector])
        .inc();
    THREAT_SCORES.observe(score);
}

/// Helper to update circuit breaker metrics
pub fn update_circuit_breaker(name: &str, state: u8, failures: u64) {
    CIRCUIT_BREAKER_STATE
        .with_label_values(&[name])
        .set(state as i64);
    CIRCUIT_BREAKER_FAILURES
        .with_label_values(&[name])
        .inc_by(failures);
}

/// Timer guard for measuring durations
pub struct MetricsTimer {
    histogram: Histogram,
    start: std::time::Instant,
}

impl MetricsTimer {
    pub fn new(histogram: &Histogram) -> Self {
        Self {
            histogram: histogram.clone(),
            start: std::time::Instant::now(),
        }
    }

    pub fn observe(self) {
        self.histogram.observe(self.start.elapsed().as_secs_f64());
    }
}

impl Drop for MetricsTimer {
    fn drop(&mut self) {
        self.histogram.observe(self.start.elapsed().as_secs_f64());
    }
}

/// Start HTTP server for metrics endpoint
pub async fn start_metrics_server(addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    use hyper::{
        service::{make_service_fn, service_fn},
        Body, Request, Response, Server,
    };

    async fn serve_metrics(_req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
        let metrics = encode_metrics();
        Ok(Response::new(Body::from(metrics)))
    }

    let make_svc =
        make_service_fn(|_conn| async { Ok::<_, hyper::Error>(service_fn(serve_metrics)) });

    tracing::info!("Metrics server listening on {}", addr);
    Server::bind(&addr).serve(make_svc).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_registration() {
        let registry = Registry::new();
        let counter = IntCounter::new("test_counter", "Test counter").unwrap();
        registry.register(Box::new(counter.clone())).unwrap();
        counter.inc();
        assert_eq!(counter.get(), 1);
    }

    #[test]
    fn test_metrics_timer() {
        let histogram =
            Histogram::with_opts(histogram_opts!("test_histogram", "Test histogram")).unwrap();
        {
            let _timer = MetricsTimer::new(&histogram);
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(histogram.get_sample_count() > 0);
    }
}
