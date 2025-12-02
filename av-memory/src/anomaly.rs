use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemoryAnomaly {
    RwxRegion {
        address: u64,
        size: u64,
        pathname: String,
    },
    AnonymousExecutable {
        address: u64,
        size: u64,
    },
    ExecutableStack {
        address: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl MemoryAnomaly {
    pub fn severity(&self) -> AnomalySeverity {
        match self {
            MemoryAnomaly::RwxRegion { .. } => AnomalySeverity::High,
            MemoryAnomaly::AnonymousExecutable { .. } => AnomalySeverity::High,
            MemoryAnomaly::ExecutableStack { .. } => AnomalySeverity::Critical,
        }
    }

    pub fn description(&self) -> String {
        match self {
            MemoryAnomaly::RwxRegion {
                address,
                size,
                pathname,
            } => format!(
                "RWX region at 0x{:x} ({} bytes) {}",
                address, size, pathname
            ),
            MemoryAnomaly::AnonymousExecutable { address, size } => {
                format!(
                    "Anonymous executable memory at 0x{:x} ({} bytes)",
                    address, size
                )
            }
            MemoryAnomaly::ExecutableStack { address } => {
                format!("Executable stack at 0x{:x}", address)
            }
        }
    }
}
