pub struct ShellcodePatterns {
    patterns: Vec<(Vec<u8>, &'static str)>,
}

impl ShellcodePatterns {
    pub fn new() -> Self {
        let mut patterns = Vec::new();
        patterns.push((vec![0x0f, 0x05], "x64_syscall"));
        patterns.push((vec![0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00], "x64_execve"));
        patterns.push((vec![0x01, 0x00, 0x00, 0xd4], "arm64_svc"));
        patterns.push((vec![0x90; 8], "nop_sled"));
        Self { patterns }
    }

    pub fn scan(&self, buf: &[u8]) -> Vec<(usize, &'static str)> {
        let mut hits = Vec::new();
        for (pat, name) in &self.patterns {
            if pat.len() > buf.len() {
                continue;
            }
            for i in 0..=buf.len() - pat.len() {
                if &buf[i..i + pat.len()] == pat.as_slice() {
                    hits.push((i, *name));
                }
            }
        }
        hits
    }
}
