//! Cryptocurrency miner detection.
//!
//! MITRE ATT&CK: T1496 (Resource Hijacking)

use lazy_static::lazy_static;
use regex::Regex;

/// Common miner executable names.
const MINER_PROCESSES: &[&str] = &[
    "xmrig",
    "xmr-stak",
    "minerd",
    "minergate",
    "cgminer",
    "bfgminer",
    "ethminer",
    "claymore",
    "phoenixminer",
    "nbminer",
    "gminer",
    "lolminer",
    "t-rex",
    "teamredminer",
    "nanominer",
    "cpuminer",
    "nicehash",
    "minerstat",
    "awesome-miner",
    "kryptex",
    "cudo",
    "honeyminer",
];

/// CPU mining-related flags (generic).
const CPU_MINING_ARGS: &[&str] = &[
    "--cpu",
    "--threads",
    "--cpu-priority",
    "--randomx",
    "--rx/",
    "--cn/",
    "--astrobwt",
    "--cpu-affinity",
    "--huge-pages",
];

/// GPU mining-related flags (generic).
const GPU_MINING_ARGS: &[&str] = &[
    "--cuda",
    "--opencl",
    "--nvidia",
    "--amd",
    "--devices",
    "--gpu-",
    "--intensity",
    "--kernel",
    "-g",
    "--cl-",
];

lazy_static! {
    /// Mining pool patterns in command lines.
    static ref POOL_PATTERNS: Regex = Regex::new(
        r"(?xi)
        stratum\+(?:tcp|ssl)://|
        stratum2\+tcp://|
        \.nicehash\.com|
        pool\.minexmr|
        pool\.supportxmr|
        xmrpool\.|
        nanopool\.|
        2miners\.|
        ethermine\.|
        flypool\.|
        f2pool\.|
        antpool\.|
        poolin\.|
        viabtc\.|
        slushpool\.|
        luxor\.|
        foundry|
        --donate-level|
        \s-o\s+[^\\s]+|
        --url\\s+[^\\s]+
        "
    )
    .unwrap();

    /// Wallet address patterns (simplified; best-effort).
    static ref WALLET_PATTERNS: Regex = Regex::new(
        r"(?x)
        # Monero-style addresses (95 chars starting with 4)
        \b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b|
        # Bitcoin addresses
        \b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b|
        # Ethereum addresses
        \b0x[a-fA-F0-9]{40}\b
        "
    )
    .unwrap();
}

#[derive(Debug, Clone)]
pub struct CryptoMinerIndicator {
    pub miner_type: MinerType,
    pub evidence: Vec<String>,
    pub severity: Severity,
    pub wallet_detected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MinerType {
    ProcessName,
    PoolConnection,
    WalletAddress,
    MiningArguments,
    Combined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Critical,
    High,
    Medium,
}

pub fn detect_cryptominer(process_name: &str, cmdline: &str) -> Option<CryptoMinerIndicator> {
    let process_lower = process_name.to_lowercase();
    let cmdline_lower = cmdline.to_lowercase();
    let mut evidence = Vec::new();

    let is_known_miner = MINER_PROCESSES.iter().any(|&m| process_lower.contains(m));
    if is_known_miner {
        evidence.push(format!("Known miner process: {}", process_name));
    }

    let has_pool = POOL_PATTERNS.is_match(&cmdline_lower);
    if has_pool {
        evidence.push("Mining pool connection detected".to_string());
    }

    let wallet_detected = WALLET_PATTERNS.is_match(cmdline);
    if wallet_detected {
        evidence.push("Cryptocurrency wallet address present".to_string());
    }

    let has_cpu_mining = CPU_MINING_ARGS.iter().any(|&a| cmdline_lower.contains(a));
    let has_gpu_mining = GPU_MINING_ARGS.iter().any(|&a| cmdline_lower.contains(a));
    if has_cpu_mining {
        evidence.push("CPU mining arguments detected".to_string());
    }
    if has_gpu_mining {
        evidence.push("GPU mining arguments detected".to_string());
    }

    if evidence.is_empty() {
        return None;
    }

    let (miner_type, severity) = if is_known_miner && evidence.len() > 1 {
        (MinerType::Combined, Severity::Critical)
    } else if is_known_miner {
        (MinerType::ProcessName, Severity::Critical)
    } else if has_pool {
        (MinerType::PoolConnection, Severity::Critical)
    } else if wallet_detected {
        (MinerType::WalletAddress, Severity::High)
    } else {
        (MinerType::MiningArguments, Severity::Medium)
    };

    Some(CryptoMinerIndicator {
        miner_type,
        evidence,
        severity,
        wallet_detected,
    })
}

pub fn detect_hidden_miner(
    process_name: &str,
    cpu_usage: f32,
    cmdline: &str,
) -> Option<CryptoMinerIndicator> {
    if cpu_usage < 70.0 {
        return None;
    }

    let cmdline_lower = cmdline.to_lowercase();
    let has_mining_args = CPU_MINING_ARGS.iter().any(|&a| cmdline_lower.contains(a))
        || GPU_MINING_ARGS.iter().any(|&a| cmdline_lower.contains(a))
        || POOL_PATTERNS.is_match(&cmdline_lower);

    if !has_mining_args {
        return None;
    }

    Some(CryptoMinerIndicator {
        miner_type: MinerType::MiningArguments,
        evidence: vec![
            format!("High CPU usage: {:.1}%", cpu_usage),
            format!("Suspicious process name: {}", process_name),
            "Mining indicators detected".to_string(),
        ],
        severity: Severity::High,
        wallet_detected: WALLET_PATTERNS.is_match(cmdline),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xmrig_detection() {
        let result = detect_cryptominer("xmrig", "xmrig -o pool.minexmr.com:4444 -u 4ABC -p x");
        assert!(result.is_some());
        let indicator = result.unwrap();
        assert!(matches!(indicator.severity, Severity::Critical));
        assert!(matches!(indicator.miner_type, MinerType::Combined));
    }

    #[test]
    fn test_pool_connection() {
        let result = detect_cryptominer(
            "worker",
            "./worker --url stratum+tcp://pool.supportxmr.com:3333",
        );
        assert!(result.is_some());
    }

    #[test]
    fn test_wallet_detection() {
        let result = detect_cryptominer(
            "app",
            "app -wallet 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD12",
        );
        assert!(result.is_some());
        assert!(result.unwrap().wallet_detected);
    }

    #[test]
    fn test_legitimate_process() {
        let result = detect_cryptominer("firefox", "firefox https://example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_hidden_miner() {
        let result = detect_hidden_miner("system_update", 95.0, "--randomx --threads 8 -o pool");
        assert!(result.is_some());
    }
}
