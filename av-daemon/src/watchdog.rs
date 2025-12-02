#![allow(dead_code, unused_imports)]
//! Watchdog timer and task supervision

use parking_lot::RwLock;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

pub type TaskId = u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskInfo {
    pub id: TaskId,
    pub name: String,
    pub state: TaskState,
    pub started_at: std::time::SystemTime,
    pub last_heartbeat: std::time::SystemTime,
    pub timeout: Duration,
    pub heartbeat_interval: Duration,
}

#[derive(Debug, Clone)]
pub enum WatchdogEvent {
    TaskStarted {
        id: TaskId,
        name: String,
    },
    TaskCompleted {
        id: TaskId,
    },
    TaskFailed {
        id: TaskId,
        error: String,
    },
    TaskTimedOut {
        id: TaskId,
        name: String,
        elapsed: Duration,
    },
    HeartbeatMissed {
        id: TaskId,
        name: String,
        last_seen: Duration,
    },
}

#[derive(Debug, Clone)]
pub struct WatchdogConfig {
    pub check_interval: Duration,
    pub default_timeout: Duration,
    pub default_heartbeat_interval: Duration,
    pub max_missed_heartbeats: u32,
    pub emit_completion_events: bool,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            check_interval: Duration::from_secs(5),
            default_timeout: Duration::from_secs(300),
            default_heartbeat_interval: Duration::from_secs(30),
            max_missed_heartbeats: 3,
            emit_completion_events: true,
        }
    }
}

pub struct HeartbeatHandle {
    task_id: TaskId,
    last_beat: Arc<AtomicU64>,
    cancelled: Arc<AtomicBool>,
}

impl HeartbeatHandle {
    pub fn beat(&self) {
        let now = Instant::now().elapsed().as_millis() as u64;
        self.last_beat.store(now, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn task_id(&self) -> TaskId {
        self.task_id
    }
}

impl Clone for HeartbeatHandle {
    fn clone(&self) -> Self {
        Self {
            task_id: self.task_id,
            last_beat: self.last_beat.clone(),
            cancelled: self.cancelled.clone(),
        }
    }
}

struct WatchedTask {
    info: TaskInfo,
    last_beat: Arc<AtomicU64>,
    cancelled: Arc<AtomicBool>,
    started: Instant,
}

pub struct Watchdog {
    config: WatchdogConfig,
    tasks: RwLock<HashMap<TaskId, WatchedTask>>,
    next_id: AtomicU64,
    event_tx: mpsc::Sender<WatchdogEvent>,
    running: AtomicBool,
    start_instant: Instant,
}

impl Watchdog {
    pub fn new(config: WatchdogConfig) -> (Arc<Self>, mpsc::Receiver<WatchdogEvent>) {
        let (event_tx, event_rx) = mpsc::channel(1000);
        let watchdog = Arc::new(Self {
            config,
            tasks: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            event_tx,
            running: AtomicBool::new(true),
            start_instant: Instant::now(),
        });
        (watchdog, event_rx)
    }

    pub fn watch_task(
        &self,
        name: impl Into<String>,
        timeout: Option<Duration>,
        heartbeat_interval: Option<Duration>,
    ) -> HeartbeatHandle {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let name = name.into();
        let now = std::time::SystemTime::now();
        let now_instant = self.start_instant.elapsed().as_millis() as u64;

        let last_beat = Arc::new(AtomicU64::new(now_instant));
        let cancelled = Arc::new(AtomicBool::new(false));

        let task = WatchedTask {
            info: TaskInfo {
                id,
                name: name.clone(),
                state: TaskState::Running,
                started_at: now,
                last_heartbeat: now,
                timeout: timeout.unwrap_or(self.config.default_timeout),
                heartbeat_interval: heartbeat_interval
                    .unwrap_or(self.config.default_heartbeat_interval),
            },
            last_beat: last_beat.clone(),
            cancelled: cancelled.clone(),
            started: Instant::now(),
        };

        self.tasks.write().insert(id, task);
        let _ = self
            .event_tx
            .try_send(WatchdogEvent::TaskStarted { id, name });

        HeartbeatHandle {
            task_id: id,
            last_beat,
            cancelled,
        }
    }

    pub fn complete_task(&self, id: TaskId) {
        if let Some(mut task) = self.tasks.write().remove(&id) {
            task.info.state = TaskState::Completed;
            if self.config.emit_completion_events {
                let _ = self.event_tx.try_send(WatchdogEvent::TaskCompleted { id });
            }
        }
    }

    pub fn fail_task(&self, id: TaskId, error: impl Into<String>) {
        if let Some(mut task) = self.tasks.write().remove(&id) {
            task.info.state = TaskState::Failed;
            let _ = self.event_tx.try_send(WatchdogEvent::TaskFailed {
                id,
                error: error.into(),
            });
        }
    }

    pub fn cancel_task(&self, id: TaskId) {
        if let Some(task) = self.tasks.read().get(&id) {
            task.cancelled.store(true, Ordering::Relaxed);
        }
    }

    pub fn running_tasks(&self) -> Vec<TaskInfo> {
        self.tasks
            .read()
            .values()
            .map(|t| {
                let mut info = t.info.clone();
                let beat_ms = t.last_beat.load(Ordering::Relaxed);
                let elapsed = Duration::from_millis(beat_ms);
                info.last_heartbeat =
                    std::time::SystemTime::now() - (self.start_instant.elapsed() - elapsed);
                info
            })
            .collect()
    }

    pub fn check_tasks(&self) -> Vec<WatchdogEvent> {
        let mut events = Vec::new();
        let mut timed_out = Vec::new();
        let now_ms = self.start_instant.elapsed().as_millis() as u64;

        {
            let tasks = self.tasks.read();
            for (id, task) in tasks.iter() {
                let elapsed = task.started.elapsed();
                if elapsed > task.info.timeout {
                    events.push(WatchdogEvent::TaskTimedOut {
                        id: *id,
                        name: task.info.name.clone(),
                        elapsed,
                    });
                    timed_out.push(*id);
                    continue;
                }

                let last_beat_ms = task.last_beat.load(Ordering::Relaxed);
                let since_heartbeat = Duration::from_millis(now_ms.saturating_sub(last_beat_ms));
                let max_silence = task.info.heartbeat_interval * self.config.max_missed_heartbeats;
                if since_heartbeat > max_silence {
                    events.push(WatchdogEvent::HeartbeatMissed {
                        id: *id,
                        name: task.info.name.clone(),
                        last_seen: since_heartbeat,
                    });
                }
            }
        }

        if !timed_out.is_empty() {
            let mut tasks = self.tasks.write();
            for id in timed_out {
                if let Some(mut task) = tasks.remove(&id) {
                    task.info.state = TaskState::TimedOut;
                    task.cancelled.store(true, Ordering::Relaxed);
                }
            }
        }

        events
    }

    pub async fn run(self: Arc<Self>) {
        info!("Watchdog started");
        while self.running.load(Ordering::Relaxed) {
            tokio::time::sleep(self.config.check_interval).await;
            let events = self.check_tasks();
            for event in events {
                match &event {
                    WatchdogEvent::TaskTimedOut { id, name, elapsed } => {
                        error!(
                            task_id = id,
                            task_name = %name,
                            elapsed_secs = elapsed.as_secs(),
                            "Task timed out"
                        );
                    }
                    WatchdogEvent::HeartbeatMissed {
                        id,
                        name,
                        last_seen,
                    } => {
                        warn!(
                            task_id = id,
                            task_name = %name,
                            last_seen_secs = last_seen.as_secs(),
                            "Task missed heartbeat"
                        );
                    }
                    _ => {}
                }
                let _ = self.event_tx.try_send(event);
            }
        }
        info!("Watchdog stopped");
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }

    pub fn stats(&self) -> WatchdogStats {
        let tasks = self.tasks.read();
        WatchdogStats {
            running_tasks: tasks.len(),
            tasks: tasks.values().map(|t| t.info.clone()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WatchdogStats {
    pub running_tasks: usize,
    pub tasks: Vec<TaskInfo>,
}

pub struct TaskGuard {
    watchdog: Arc<Watchdog>,
    handle: HeartbeatHandle,
    completed: bool,
}

impl TaskGuard {
    pub fn new(watchdog: Arc<Watchdog>, name: impl Into<String>) -> Self {
        let handle = watchdog.watch_task(name, None, None);
        Self {
            watchdog,
            handle,
            completed: false,
        }
    }

    pub fn with_timeout(
        watchdog: Arc<Watchdog>,
        name: impl Into<String>,
        timeout: Duration,
    ) -> Self {
        let handle = watchdog.watch_task(name, Some(timeout), None);
        Self {
            watchdog,
            handle,
            completed: false,
        }
    }

    pub fn beat(&self) {
        self.handle.beat();
    }

    pub fn is_cancelled(&self) -> bool {
        self.handle.is_cancelled()
    }

    pub fn complete(mut self) {
        self.completed = true;
        self.watchdog.complete_task(self.handle.task_id());
    }

    pub fn fail(mut self, error: impl Into<String>) {
        self.completed = true;
        self.watchdog.fail_task(self.handle.task_id(), error);
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.watchdog.fail_task(
                self.handle.task_id(),
                "Task dropped without completion (possible panic)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_task_completion() {
        let config = WatchdogConfig::default();
        let (watchdog, _rx) = Watchdog::new(config);
        let handle = watchdog.watch_task("test_task", None, None);
        assert_eq!(watchdog.running_tasks().len(), 1);
        watchdog.complete_task(handle.task_id());
        assert_eq!(watchdog.running_tasks().len(), 0);
    }

    #[tokio::test]
    async fn test_heartbeat() {
        let config = WatchdogConfig {
            default_heartbeat_interval: Duration::from_millis(10),
            max_missed_heartbeats: 2,
            ..Default::default()
        };
        let (watchdog, _rx) = Watchdog::new(config);
        let handle = watchdog.watch_task("heartbeat_task", None, None);
        for _ in 0..5 {
            handle.beat();
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        watchdog.complete_task(handle.task_id());
    }

    #[tokio::test]
    async fn test_timeout_detection() {
        let config = WatchdogConfig {
            default_timeout: Duration::from_millis(50),
            check_interval: Duration::from_millis(10),
            ..Default::default()
        };
        let (watchdog, _rx) = Watchdog::new(config);
        let _handle = watchdog.watch_task("slow_task", None, None);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let events = watchdog.check_tasks();
        assert!(events
            .iter()
            .any(|e| matches!(e, WatchdogEvent::TaskTimedOut { .. })));
    }

    #[tokio::test]
    async fn test_task_guard() {
        let config = WatchdogConfig::default();
        let (watchdog, _rx) = Watchdog::new(config);
        {
            let guard = TaskGuard::new(watchdog.clone(), "guarded_task");
            guard.beat();
            guard.complete();
        }
        assert_eq!(watchdog.running_tasks().len(), 0);
    }

    #[tokio::test]
    async fn test_task_guard_drop_without_complete() {
        let config = WatchdogConfig::default();
        let (watchdog, _rx) = Watchdog::new(config);
        {
            let _guard = TaskGuard::new(watchdog.clone(), "dropped_task");
        }
        assert_eq!(watchdog.running_tasks().len(), 0);
    }
}
