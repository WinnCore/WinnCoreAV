mod common;

#[test]
fn test_malware_and_benign_samples() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let benign = common::create_benign_file(tmp.path());
    let malware = common::create_test_malware(tmp.path());

    assert!(benign.exists(), "benign file created");
    assert!(malware.exists(), "malware sample created");

    let benign_size = std::fs::metadata(&benign).unwrap().len();
    let malware_size = std::fs::metadata(&malware).unwrap().len();
    assert!(
        malware_size > benign_size,
        "malware sample should be larger"
    );

    let malware_bytes = std::fs::read(&malware).unwrap();
    assert!(
        malware_bytes
            .windows(b"/etc/shadow".len())
            .any(|w| w == b"/etc/shadow"),
        "malware sample should contain suspicious string"
    );
}
