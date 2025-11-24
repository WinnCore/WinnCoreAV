/// Configure quieter logging for long-running stress scenarios.
pub fn configure_quiet_mode() {
    std::env::set_var("WINNCORE_QUIET_STRESS", "1");
}
