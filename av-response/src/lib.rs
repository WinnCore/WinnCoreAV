//! Automated response helpers (process kill, quarantine stubs, network block stubs).

pub mod actions;

pub use actions::{ActionResult, BlockDirection, ResponseAction, ResponseExecutor};
