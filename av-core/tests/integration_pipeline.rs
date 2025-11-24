use av_core::config::ThreatIntelConfig;
use av_core::{logging::sha256_file, Scanner, ScannerConfig};
use std::fs;
use std::path::PathBuf;
use tokio::runtime::Runtime;

fn write_sample(path: &PathBuf, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

fn sample_elf(prefix: &[u8], body: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(b"\x7FELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    v.extend_from_slice(prefix);
    v.extend_from_slice(body);
    v
}

#[test]
fn integration_pipeline_basic() {
    let rt = Runtime::new().unwrap();

    // Set up temp dirs and samples
    let tmp = tempfile::tempdir().unwrap();
    let yara_dir = tmp.path().join("yara");
    let ioc_path = tmp.path().join("iocs.json");
    fs::create_dir_all(&yara_dir).unwrap();

    // YARA rule
    let yara_rule = r#"
rule test_malware {
    strings:
        $a = "EVIL_STRING"
    condition:
        $a
}
"#;
    fs::write(yara_dir.join("test_rule.yar"), yara_rule).unwrap();

    // Samples
    let benign_path = tmp.path().join("benign.bin");
    let malicious_path = tmp.path().join("malicious.bin");
    let non_elf_path = tmp.path().join("non_elf.txt");

    write_sample(&benign_path, &sample_elf(b"BENIGN", b"SAFE"));
    write_sample(&malicious_path, &sample_elf(b"MAL", b"EVIL_STRING"));
    write_sample(&non_elf_path, b"not an elf");

    // IoC cache with malicious hash
    let mal_hash = sha256_file(&malicious_path).unwrap();
    let ioc_json = serde_json::json!({ "sha256": [mal_hash] });
    fs::write(&ioc_path, serde_json::to_string(&ioc_json).unwrap()).unwrap();

    // Config
    let cfg = ScannerConfig {
        threat_intel: ThreatIntelConfig {
            yara_rules_dir: Some(yara_dir),
            ioc_cache_path: Some(ioc_path.clone()),
            ..ThreatIntelConfig::default()
        },
        allowlist_hashes: vec![sha256_file(&benign_path).unwrap()],
        ..ScannerConfig::default()
    };

    let scanner = Scanner::new(cfg.clone()).unwrap();

    // Benign
    let benign_out = rt.block_on(scanner.scan_path(&benign_path)).unwrap();
    assert!(benign_out.yara_matches.is_empty());
    assert!(benign_out.ioc_hits.is_empty());
    assert_eq!(
        benign_out.recommended_action,
        av_core::RecommendedAction::Allow
    );

    // Malicious: expect YARA + IoC → Quarantine
    let mal_out = rt.block_on(scanner.scan_path(&malicious_path)).unwrap();
    assert!(mal_out
        .yara_matches
        .iter()
        .any(|m| m.contains("test_malware")));
    assert!(mal_out.ioc_hits.iter().any(|h| h == &mal_hash));
    assert_eq!(
        mal_out.recommended_action,
        av_core::RecommendedAction::Quarantine
    );

    // Non-ELF: should allow, no hits
    let non_out = rt.block_on(scanner.scan_path(&non_elf_path)).unwrap();
    assert!(non_out.yara_matches.is_empty());
    assert!(non_out.ioc_hits.is_empty());
    assert_eq!(
        non_out.recommended_action,
        av_core::RecommendedAction::Allow
    );
}
