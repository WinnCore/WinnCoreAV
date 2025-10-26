#![allow(dead_code)]
#![allow(unused_variables)]
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryBatch {
    pub points: Vec<MetricPoint>,
}

impl TelemetryBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, point: MetricPoint) {
        self.points.push(point);
    }
}
