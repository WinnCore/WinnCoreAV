#[derive(Debug)]
pub struct ResponseEngine {
    enabled: bool,
    threshold: f32,
    actions_recorded: u64,
}

impl ResponseEngine {
    pub fn new(enabled: bool, threshold: f32) -> Self {
        Self {
            enabled,
            threshold,
            actions_recorded: 0,
        }
    }

    #[allow(dead_code)]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    #[allow(dead_code)]
    pub fn threshold(&self) -> f32 {
        self.threshold
    }

    pub fn record_action(&mut self) {
        self.actions_recorded = self.actions_recorded.saturating_add(1);
    }
}
