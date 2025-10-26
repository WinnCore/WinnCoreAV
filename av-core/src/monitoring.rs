#![allow(dead_code)]
#![allow(unused_variables)]
//! Helper utilities for fanotify/inotify abstraction.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringEvent {
    pub path: String,
    pub event: MonitoringEventType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MonitoringEventType {
    Open,
    Close,
    Modify,
    Execute,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringReport {
    pub events: Vec<MonitoringEvent>,
    pub degraded_mode: bool,
}
