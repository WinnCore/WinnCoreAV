use std::path::Path;

/// Create a benign test file with simple text content.
pub fn create_benign_file(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("benign_file.txt");
    std::fs::write(&path, b"This is a benign file\n").expect("write benign file");
    path
}

/// Create a synthetic "malware-like" sample for testing pipelines.
/// Not real malware: embeds suspicious strings and high-entropy bytes.
pub fn create_test_malware(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("malware_sample.bin");
    let mut content = vec![0u8; 1024];

    // High entropy pattern
    for (i, byte) in content.iter_mut().enumerate().take(256) {
        *byte = (i as u8).wrapping_mul(17).wrapping_add(31);
    }

    // Suspicious strings
    let shadow = b"/etc/shadow";
    content[256..256 + shadow.len()].copy_from_slice(shadow);
    let rm_str = b"rm -rf /";
    content[268..268 + rm_str.len()].copy_from_slice(rm_str);

    std::fs::write(&path, content).expect("write malware sample");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("set perms");
    }

    path
}
