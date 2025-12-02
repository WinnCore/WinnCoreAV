//! Container escape and Kubernetes abuse detection.

pub mod context;
pub mod detection;

pub use context::{ContainerContext, ContainerRuntime};
pub use detection::{ContainerDetector, ContainerThreat};
