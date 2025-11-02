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
}
