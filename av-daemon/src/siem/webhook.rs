//! HTTP webhook sender for Splunk HEC, Elastic, custom endpoints
//!
//! Supports authentication, optional batching, and retry/backoff.

use super::{AlertFormatter, AlertSender, SiemError};
use crate::alert::Alert;
use async_trait::async_trait;
use reqwest::{header, Client};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, sleep};
use tracing::{debug, warn};

pub struct WebhookSender {
    client: Client,
    url: String,
    formatter: Box<dyn AlertFormatter>,
    auth: WebhookAuth,
}

#[derive(Clone)]
pub enum WebhookAuth {
    None,
    Bearer(String),
    Basic {
        username: String,
        password: String,
    },
    SplunkHec(String), // Splunk HEC token
    Custom {
        header_name: String,
        header_value: String,
    },
}

impl WebhookSender {
    pub fn new(url: String, formatter: Box<dyn AlertFormatter>, auth: WebhookAuth) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to build HTTP client");

        Self {
            client,
            url,
            formatter,
            auth,
        }
    }

    fn apply_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            WebhookAuth::None => request,
            WebhookAuth::Bearer(token) => request.bearer_auth(token),
            WebhookAuth::Basic { username, password } => {
                request.basic_auth(username, Some(password))
            }
            WebhookAuth::SplunkHec(token) => {
                request.header("Authorization", format!("Splunk {}", token))
            }
            WebhookAuth::Custom {
                header_name,
                header_value,
            } => request.header(header_name.as_str(), header_value.as_str()),
        }
    }

    async fn post_json(&self, body: String) -> Result<(), SiemError> {
        let request = self
            .client
            .post(&self.url)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body);

        let request = self.apply_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| SiemError::Network(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(SiemError::Network(format!("HTTP {}: {}", status, body)));
        }

        Ok(())
    }
}

#[async_trait]
impl AlertSender for WebhookSender {
    async fn send(&self, alert: &Alert) -> Result<(), SiemError> {
        let body = self.formatter.format(alert);

        // Best-effort Splunk HEC wrapping when configured.
        let body = match &self.auth {
            WebhookAuth::SplunkHec(_) => {
                let event = serde_json::from_str::<serde_json::Value>(&body)
                    .unwrap_or(serde_json::Value::String(body));
                serde_json::to_string(&serde_json::json!({
                    "time": alert.timestamp.timestamp(),
                    "event": event,
                }))
                .map_err(|e| SiemError::Format(e.to_string()))?
            }
            _ => body,
        };

        self.post_json(body).await?;
        debug!("Alert sent to webhook successfully");
        Ok(())
    }

    fn name(&self) -> &str {
        "webhook"
    }
}

/// Batching webhook sender for high-volume environments.
///
/// - `send()` enqueues alerts quickly.
/// - a background task periodically flushes a batch
/// - on failure, batch is retained and retried with backoff.
pub struct BatchingWebhookSender {
    name: String,
    tx: mpsc::Sender<Alert>,
}

impl BatchingWebhookSender {
    pub fn new(
        name: String,
        inner: WebhookSender,
        batch_size: usize,
        batch_timeout: Duration,
    ) -> Self {
        let (tx, mut rx) = mpsc::channel::<Alert>(10000);

        let inner = Arc::new(inner);
        let batch: Arc<Mutex<Vec<Alert>>> = Arc::new(Mutex::new(Vec::with_capacity(batch_size)));
        let batch_clone = batch.clone();

        tokio::spawn(async move {
            let mut ticker = interval(batch_timeout);
            let mut backoff = Duration::from_millis(0);
            let mut next_allowed = Instant::now();

            loop {
                tokio::select! {
                    Some(alert) = rx.recv() => {
                        let mut b = batch_clone.lock().await;
                        b.push(alert);
                        if b.len() >= batch_size {
                            drop(b);
                            flush_with_backoff(&inner, &batch_clone, &mut backoff, &mut next_allowed).await;
                        }
                    }
                    _ = ticker.tick() => {
                        flush_with_backoff(&inner, &batch_clone, &mut backoff, &mut next_allowed).await;
                    }
                }
            }
        });

        Self { name, tx }
    }
}

async fn flush_with_backoff(
    inner: &Arc<WebhookSender>,
    batch: &Arc<Mutex<Vec<Alert>>>,
    backoff: &mut Duration,
    next_allowed: &mut Instant,
) {
    if Instant::now() < *next_allowed {
        return;
    }

    let mut b = batch.lock().await;
    if b.is_empty() {
        return;
    }

    // Build JSON-lines payload for batch.
    let body = b
        .iter()
        .map(|a| inner.formatter.format(a))
        .collect::<Vec<_>>()
        .join("\n");

    match inner.post_json(body).await {
        Ok(()) => {
            debug!("Flushed {} alerts to webhook", b.len());
            b.clear();
            *backoff = Duration::from_millis(0);
            *next_allowed = Instant::now();
        }
        Err(e) => {
            warn!("Failed to flush batch to webhook: {}", e);

            *backoff = if backoff.is_zero() {
                Duration::from_millis(500)
            } else {
                (*backoff * 2).min(Duration::from_secs(60))
            };
            *next_allowed = Instant::now() + *backoff;

            // Avoid tight-looping when remote is down.
            sleep((*backoff).min(Duration::from_secs(1))).await;
        }
    }
}

#[async_trait]
impl AlertSender for BatchingWebhookSender {
    async fn send(&self, alert: &Alert) -> Result<(), SiemError> {
        self.tx
            .send(alert.clone())
            .await
            .map_err(|e| SiemError::Network(e.to_string()))
    }

    fn name(&self) -> &str {
        self.name.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alert::{DetectionSource, Severity};
    use crate::siem::JsonFormatter;

    #[tokio::test]
    async fn batching_sender_enqueues() {
        let inner = WebhookSender::new(
            "http://127.0.0.1:9".to_string(), // discard port - request will fail if flushed
            Box::new(JsonFormatter::default()),
            WebhookAuth::None,
        );

        let sender = BatchingWebhookSender::new(
            "webhook_batch".to_string(),
            inner,
            2,
            Duration::from_millis(50),
        );

        let alert = Alert::new(
            "TEST-001",
            "Test Alert",
            "hello",
            Severity::Info,
            DetectionSource::Heuristic,
        );

        // enqueue should succeed even if endpoint doesn't exist (flush occurs later)
        sender.send(&alert).await.unwrap();
    }
}
