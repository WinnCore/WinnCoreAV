//! REST API for WinnCoreAV management
//!
//! Endpoints for status, configuration, and manual alert submission.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::alert::{Alert, DetectionSource, Severity};
use crate::siem::AlertRouter;

#[derive(Clone)]
pub struct ApiState {
    pub router: Arc<AlertRouter>,
    pub version: String,
}

pub fn api_routes() -> Router<ApiState> {
    Router::<ApiState>::new()
        .route("/health", get(health_check))
        .route("/version", get(version))
        .route("/alerts", post(submit_alert))
        .route("/siem/status", get(siem_status))
        .route("/siem/routes", get(list_routes))
        .route("/siem/routes/:name/enable", post(enable_route))
        .route("/siem/routes/:name/disable", post(disable_route))
        .route("/siem/test", post(test_siem))
}

async fn health_check() -> &'static str {
    "OK"
}

async fn version(State(state): State<ApiState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "WinnCoreAV",
        "version": state.version,
        "arch": std::env::consts::ARCH,
    }))
}

#[derive(Deserialize)]
struct AlertSubmission {
    rule_id: String,
    description: String,
    severity: String,
}

async fn submit_alert(
    State(state): State<ApiState>,
    Json(submission): Json<AlertSubmission>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let severity = submission
        .severity
        .parse::<Severity>()
        .unwrap_or(Severity::Medium);

    let alert = Alert::new(
        &submission.rule_id,
        "Manual Alert",
        &submission.description,
        severity,
        DetectionSource::Heuristic,
    );

    let _ = state.router.route(&alert).await;

    Ok(Json(serde_json::json!({
        "status": "accepted",
        "alert_id": alert.id,
    })))
}

async fn siem_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let routes = state.router.status().await;
    Json(serde_json::json!({
        "enabled": true,
        "routes": routes.iter().map(|(name, enabled)| {
            serde_json::json!({ "name": name, "enabled": enabled })
        }).collect::<Vec<_>>(),
    }))
}

async fn list_routes(State(state): State<ApiState>) -> Json<Vec<serde_json::Value>> {
    let routes = state.router.status().await;
    Json(routes
        .into_iter()
        .map(|(name, enabled)| serde_json::json!({ "name": name, "enabled": enabled }))
        .collect())
}

async fn enable_route(State(state): State<ApiState>, Path(name): Path<String>) -> StatusCode {
    if state.router.set_enabled(&name, true).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn disable_route(State(state): State<ApiState>, Path(name): Path<String>) -> StatusCode {
    if state.router.set_enabled(&name, false).await {
        StatusCode::OK
    } else {
        StatusCode::NOT_FOUND
    }
}

async fn test_siem(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let alert = Alert::new(
        "TEST-001",
        "Test Alert",
        "This is a test alert from WinnCoreAV SIEM integration",
        Severity::Info,
        DetectionSource::Heuristic,
    );

    let results = state.router.route(&alert).await;
    let success_count = results.iter().filter(|r| r.is_ok()).count();

    Json(serde_json::json!({
        "status": "completed",
        "alert_id": alert.id,
        "routes_attempted": results.len(),
        "routes_succeeded": success_count,
    }))
}
