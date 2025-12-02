#![allow(dead_code, unused_imports)]
//! Landlock filesystem sandboxing (Linux only).
//! Restricts filesystem access even if seccomp allows syscalls.

use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Filesystem access rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    pub execute: bool,
    pub write_file: bool,
    pub read_file: bool,
    pub read_dir: bool,
    pub remove_dir: bool,
    pub remove_file: bool,
    pub make_char: bool,
    pub make_dir: bool,
    pub make_reg: bool,
    pub make_sock: bool,
    pub make_fifo: bool,
    pub make_block: bool,
    pub make_sym: bool,
    pub refer: bool,
    pub truncate: bool,
}

impl AccessRights {
    pub fn none() -> Self {
        Self {
            execute: false,
            write_file: false,
            read_file: false,
            read_dir: false,
            remove_dir: false,
            remove_file: false,
            make_char: false,
            make_dir: false,
            make_reg: false,
            make_sock: false,
            make_fifo: false,
            make_block: false,
            make_sym: false,
            refer: false,
            truncate: false,
        }
    }

    pub fn read_only() -> Self {
        Self {
            read_file: true,
            read_dir: true,
            ..Self::none()
        }
    }

    pub fn read_write() -> Self {
        Self {
            read_file: true,
            read_dir: true,
            write_file: true,
            truncate: true,
            make_reg: true,
            make_dir: true,
            remove_file: true,
            remove_dir: true,
            ..Self::none()
        }
    }

    pub fn full() -> Self {
        Self {
            execute: true,
            write_file: true,
            read_file: true,
            read_dir: true,
            remove_dir: true,
            remove_file: true,
            make_char: true,
            make_dir: true,
            make_reg: true,
            make_sock: true,
            make_fifo: true,
            make_block: true,
            make_sym: true,
            refer: true,
            truncate: true,
        }
    }

    fn to_bits(&self) -> u64 {
        const EXEC: u64 = 1 << 0;
        const WRITE_FILE: u64 = 1 << 1;
        const READ_FILE: u64 = 1 << 2;
        const READ_DIR: u64 = 1 << 3;
        const REMOVE_DIR: u64 = 1 << 4;
        const REMOVE_FILE: u64 = 1 << 5;
        const MAKE_CHAR: u64 = 1 << 6;
        const MAKE_DIR: u64 = 1 << 7;
        const MAKE_REG: u64 = 1 << 8;
        const MAKE_SOCK: u64 = 1 << 9;
        const MAKE_FIFO: u64 = 1 << 10;
        const MAKE_BLOCK: u64 = 1 << 11;
        const MAKE_SYM: u64 = 1 << 12;
        const REFER: u64 = 1 << 13;
        const TRUNCATE: u64 = 1 << 14;

        let mut bits = 0u64;
        if self.execute {
            bits |= EXEC;
        }
        if self.write_file {
            bits |= WRITE_FILE;
        }
        if self.read_file {
            bits |= READ_FILE;
        }
        if self.read_dir {
            bits |= READ_DIR;
        }
        if self.remove_dir {
            bits |= REMOVE_DIR;
        }
        if self.remove_file {
            bits |= REMOVE_FILE;
        }
        if self.make_char {
            bits |= MAKE_CHAR;
        }
        if self.make_dir {
            bits |= MAKE_DIR;
        }
        if self.make_reg {
            bits |= MAKE_REG;
        }
        if self.make_sock {
            bits |= MAKE_SOCK;
        }
        if self.make_fifo {
            bits |= MAKE_FIFO;
        }
        if self.make_block {
            bits |= MAKE_BLOCK;
        }
        if self.make_sym {
            bits |= MAKE_SYM;
        }
        if self.refer {
            bits |= REFER;
        }
        if self.truncate {
            bits |= TRUNCATE;
        }
        bits
    }
}

/// Ruleset of allowed paths and rights.
#[derive(Debug, Default)]
pub struct LandlockRuleset {
    pub rules: Vec<(PathBuf, AccessRights)>,
}

impl LandlockRuleset {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rule(mut self, path: impl AsRef<Path>, rights: AccessRights) -> Self {
        self.rules.push((path.as_ref().to_path_buf(), rights));
        self
    }

    pub fn av_daemon_default() -> Self {
        Self::new()
            .add_rule("/", AccessRights::read_only())
            .add_rule("/var/lib/winncore", AccessRights::read_write())
            .add_rule("/var/log/winncore", AccessRights::read_write())
            .add_rule("/var/lib/winncore/quarantine", AccessRights::full())
            .add_rule("/tmp/winncore", AccessRights::read_write())
            .add_rule("/etc/winncore", AccessRights::read_only())
            .add_rule("/run/winncore", AccessRights::read_write())
            .add_rule("/proc", AccessRights::read_only())
            .add_rule("/sys", AccessRights::read_only())
    }
}

#[derive(Debug)]
pub enum LandlockError {
    NotSupported,
    RulesetCreationFailed(std::io::Error),
    RuleAddFailed(PathBuf, std::io::Error),
    EnforceFailed(std::io::Error),
}

impl std::fmt::Display for LandlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LandlockError::NotSupported => write!(f, "Landlock not supported"),
            LandlockError::RulesetCreationFailed(e) => write!(f, "Failed to create ruleset: {}", e),
            LandlockError::RuleAddFailed(p, e) => {
                write!(f, "Failed to add rule for {:?}: {}", p, e)
            }
            LandlockError::EnforceFailed(e) => write!(f, "Failed to enforce ruleset: {}", e),
        }
    }
}

impl std::error::Error for LandlockError {}

#[cfg(target_os = "linux")]
pub fn is_landlock_supported() -> bool {
    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: 0,
    };
    let res = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if res >= 0 {
        unsafe {
            libc::close(res as i32);
        }
        true
    } else {
        let err = std::io::Error::last_os_error();
        err.raw_os_error() != Some(libc::ENOSYS) && err.raw_os_error() != Some(libc::EOPNOTSUPP)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn is_landlock_supported() -> bool {
    false
}

#[cfg(target_os = "linux")]
pub fn enforce_landlock(ruleset: &LandlockRuleset) -> Result<(), LandlockError> {
    use std::os::unix::io::AsRawFd;

    if !is_landlock_supported() {
        warn!("Landlock not supported; skipping");
        return Ok(());
    }

    const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
    const SYS_LANDLOCK_ADD_RULE: i64 = 445;
    const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    let all_access = AccessRights::full().to_bits();
    let attr = LandlockRulesetAttr {
        handled_access_fs: all_access,
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };

    if ruleset_fd < 0 {
        return Err(LandlockError::RulesetCreationFailed(
            std::io::Error::last_os_error(),
        ));
    }
    let ruleset_fd = ruleset_fd as i32;
    struct FdGuard(i32);
    impl Drop for FdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _guard = FdGuard(ruleset_fd);

    for (path, rights) in &ruleset.rules {
        if !path.exists() {
            debug!(path = %path.display(), "Skipping non-existent path");
            continue;
        }
        let file = match std::fs::File::open(path) {
            Ok(f) => f,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to open path");
                continue;
            }
        };
        let attr = LandlockPathBeneathAttr {
            allowed_access: rights.to_bits(),
            parent_fd: file.as_raw_fd(),
        };
        let res = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr as *const _,
                0u32,
            )
        };
        if res < 0 {
            warn!(
                path = %path.display(),
                error = %std::io::Error::last_os_error(),
                "Failed to add Landlock rule"
            );
        }
    }

    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(LandlockError::EnforceFailed(std::io::Error::last_os_error()));
        }
    }

    let res = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32) };
    if res < 0 {
        return Err(LandlockError::EnforceFailed(std::io::Error::last_os_error()));
    }
    info!(
        rules = ruleset.rules.len(),
        "Landlock filesystem sandbox enabled"
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn enforce_landlock(_ruleset: &LandlockRuleset) -> Result<(), LandlockError> {
    warn!("Landlock not available on this platform");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_bits() {
        let none = AccessRights::none();
        assert_eq!(none.to_bits(), 0);
        let ro = AccessRights::read_only();
        assert!(ro.to_bits() > 0);
    }

    #[test]
    fn ruleset_builder() {
        let rs = LandlockRuleset::new()
            .add_rule("/tmp", AccessRights::read_write())
            .add_rule("/etc", AccessRights::read_only());
        assert_eq!(rs.rules.len(), 2);
    }
}
