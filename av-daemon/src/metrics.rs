<<<<<<< HEAD
//! Prometheus metrics for WinnCoreAV daemon

use anyhow::Result;
use prometheus::{Counter, Encoder, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder};
use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::thread;
use tracing::{error, info, warn};

pub struct Metrics {
    registry: Arc<Registry>,
    pub files_scanned: Counter,
    pub threats_detected: Counter,
    pub scan_duration_seconds: Histogram,
    pub active_scans: Gauge,
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let files_scanned = Counter::with_opts(Opts::new(
            "winncore_files_scanned_total",
            "Total number of files scanned",
        ))?;
        registry.register(Box::new(files_scanned.clone()))?;

        let threats_detected = Counter::with_opts(Opts::new(
            "winncore_threats_detected_total",
            "Total number of threats detected",
        ))?;
        registry.register(Box::new(threats_detected.clone()))?;

        let scan_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "winncore_scan_duration_seconds",
            "Duration of file scans in seconds",
        ))?;
        registry.register(Box::new(scan_duration_seconds.clone()))?;

        let active_scans = Gauge::with_opts(Opts::new(
            "winncore_active_scans",
            "Number of currently active scans",
        ))?;
        registry.register(Box::new(active_scans.clone()))?;

        Ok(Self {
            registry: Arc::new(registry),
            files_scanned,
            threats_detected,
            scan_duration_seconds,
            active_scans,
        })
    }

    pub fn start_server(&self, bind_addr: String) {
        let registry: Arc<Registry> = Arc::clone(&self.registry);

        info!("🔧 Starting metrics server on {}", bind_addr);

        thread::Builder::new()
            .name("metrics-server".to_string())
            .spawn(move || {
                info!("🔧 Inside metrics thread, attempting bind");

                let listener = match TcpListener::bind(&bind_addr) {
                    Ok(l) => {
                        info!("📊 Metrics server listening on http://{}", bind_addr);
                        l
                    }
                    Err(e) => {
                        error!("❌ Failed to bind to {}: {}", bind_addr, e);
                        return;
                    }
                };

                info!("✅ Bound to port, entering accept loop");

                for stream in listener.incoming() {
                    match stream {
                        Ok(mut stream) => {
                            let metric_families = registry.gather();
                            let mut buffer = Vec::new();
                            let encoder = TextEncoder::new();

                            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                                error!("Failed to encode metrics: {}", e);
                                continue;
                            }

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\n\r\n",
                                buffer.len()
                            );

                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.write_all(&buffer);

                            info!("✅ Served metrics request");
                        }
                        Err(e) => {
                            warn!("Failed to accept connection: {}", e);
                        }
                    }
                }
            })
            .expect("Failed to spawn metrics thread");

        info!("✅ Metrics server thread spawned");
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("Failed to create metrics")
    }
=======
use lazy_static::lazy_static;
use prometheus::{
    register_counter, register_gauge, register_histogram, Counter, Encoder, Gauge, Histogram,
    TextEncoder,
};

lazy_static! {
    // Counters (always increasing)
    pub static ref FILES_SCANNED: Counter = register_counter!(
        "winncore_files_scanned_total",
        "Total number of files scanned"
    )
    .unwrap();

    pub static ref THREATS_DETECTED: Counter = register_counter!(
        "winncore_threats_detected_total",
        "Total number of threats detected"
    )
    .unwrap();

    pub static ref QUARANTINE_OPS: Counter = register_counter!(
        "winncore_quarantine_operations_total",
        "Total number of quarantine operations"
    )
    .unwrap();

    pub static ref SCAN_ERRORS: Counter = register_counter!(
        "winncore_scan_errors_total",
        "Total number of scan errors"
    )
    .unwrap();

    pub static ref QUEUE_DROPS: Counter = register_counter!(
        "winncore_queue_drops_total",
        "Total number of events dropped due to full queue"
    )
    .unwrap();

    // Gauges (can go up or down)
    pub static ref QUEUE_DEPTH: Gauge = register_gauge!(
        "winncore_queue_depth",
        "Current number of items in scan queue"
    )
    .unwrap();

    pub static ref WORKER_THREADS: Gauge = register_gauge!(
        "winncore_worker_threads",
        "Number of active worker threads"
    )
    .unwrap();

    // Histograms (distributions)
    pub static ref SCAN_DURATION: Histogram = register_histogram!(
        "winncore_scan_duration_seconds",
        "Time taken to scan files in seconds",
        vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0]
    )
    .unwrap();
}

pub fn start_metrics_server(port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", port);
    let server = tiny_http::Server::http(&addr)?;

    tracing::info!("📊 Metrics server listening on http://{}/metrics", addr);

    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let path = request.url();

            if path == "/metrics" || path == "/metrics/" {
                let encoder = TextEncoder::new();
                let metric_families = prometheus::gather();
                let mut buffer = Vec::new();

                if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                    tracing::error!("Failed to encode metrics: {}", e);
                    let response = tiny_http::Response::from_string("Error encoding metrics")
                        .with_status_code(500);
                    let _ = request.respond(response);
                    continue;
                }

                let response = tiny_http::Response::from_data(buffer).with_header(
                    tiny_http::Header::from_bytes(
                        &b"Content-Type"[..],
                        &b"text/plain; version=0.0.4"[..],
                    )
                    .unwrap(),
                );

                if let Err(e) = request.respond(response) {
                    tracing::error!("Failed to send metrics response: {}", e);
                }
            } else if path == "/" {
                let html = r#"
                    <!DOCTYPE html>
                    <html>
                    <head><title>WinnCoreAV Metrics</title></head>
                    <body>
                        <h1>🛡️ WinnCoreAV Metrics</h1>
                        <p><a href="/metrics">View Prometheus Metrics</a></p>
                        <p>Use with Prometheus: <code>http://localhost:9090/metrics</code></p>
                    </body>
                    </html>
                "#;
                let response = tiny_http::Response::from_string(html).with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..]).unwrap(),
                );
                let _ = request.respond(response);
            } else {
                let response = tiny_http::Response::from_string("Not Found").with_status_code(404);
                let _ = request.respond(response);
            }
        }
    });

    Ok(())
>>>>>>> claude/prometheus-metrics-011CUgPhmcQJyzPKUycQrphV
}
