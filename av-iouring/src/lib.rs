//! io_uring attack detection.
//!
//! io_uring can bypass syscall-level monitoring. This crate provides
//! a userspace detector that ingests events (from eBPF or proc scanning)
//! and scores risk.
#![allow(dead_code)]

pub mod detector;
pub mod events;
pub mod parser;

pub use detector::{IoUringDetector, IoUringRing, IoUringStats, ProcessIoUringContext};
pub use events::{IoUringEvent, IoUringOp, RiskLevel};
