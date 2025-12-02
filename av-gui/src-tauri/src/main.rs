#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Alert {
    pub timestamp: String,
    pub rule_id: String,
    pub technique: String,
    pub severity: String,
    pub message: String,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub cmdline: Option<String>,
}

pub struct AppState {
    alert_path: PathBuf,
}

#[tauri::command]
fn get_alerts(state: State<Mutex<AppState>>) -> Result<Vec<Alert>, String> {
    let state = state.lock().map_err(|e| e.to_string())?;
    let path = &state.alert_path;

    if !path.exists() {
        return Ok(vec![]);
    }

    let file = File::open(path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);

    let alerts: Vec<Alert> = reader
        .lines()
        .filter_map(|line| line.ok())
        .filter_map(|line| serde_json::from_str(&line).ok())
        .collect();

    Ok(alerts)
}

#[tauri::command]
fn get_daemon_status() -> Result<bool, String> {
    use std::process::Command;
    let output = Command::new("pgrep")
        .args(["-x", "av-daemon"])
        .output()
        .map_err(|e| e.to_string())?;
    Ok(output.status.success())
}

#[tauri::command]
fn get_stats(state: State<Mutex<AppState>>) -> Result<serde_json::Value, String> {
    let alerts = get_alerts(state)?;

    let total = alerts.len();
    let critical = alerts.iter().filter(|a| a.severity == "Critical").count();
    let high = alerts.iter().filter(|a| a.severity == "High").count();
    let medium = alerts.iter().filter(|a| a.severity == "Medium").count();
    let low = alerts.iter().filter(|a| a.severity == "Low").count();

    Ok(serde_json::json!({
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low
    }))
}

fn main() {
    let alert_path = std::env::var("WINNCORE_ALERT_LOG")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/log/winncore/alerts.json"));

    let state = Mutex::new(AppState { alert_path });

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            get_alerts,
            get_daemon_status,
            get_stats
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
