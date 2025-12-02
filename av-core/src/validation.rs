//! Input validation and sanitization utilities

use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Path is empty")]
    EmptyPath,
    #[error("Path contains null bytes")]
    NullBytes,
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Path is not absolute: {0}")]
    NotAbsolute(String),
    #[error("Path is not within allowed directory: {path} not in {allowed}")]
    OutsideAllowedDir { path: String, allowed: String },
    #[error("Symlink detected and not allowed: {0}")]
    SymlinkNotAllowed(String),
    #[error("Path too long: {len} > {max}")]
    PathTooLong { len: usize, max: usize },
    #[error("Invalid characters in path: {0}")]
    InvalidCharacters(String),
    #[error("Configuration value out of range: {field} = {value}, expected {min}-{max}")]
    OutOfRange {
        field: String,
        value: String,
        min: String,
        max: String,
    },
    #[error("Required field missing: {0}")]
    MissingField(String),
    #[error("Invalid format: {field}: {message}")]
    InvalidFormat { field: String, message: String },
}

pub type ValidationResult<T> = Result<T, ValidationError>;

/// Path validator with configurable rules
#[derive(Debug, Clone)]
pub struct PathValidator {
    pub require_absolute: bool,
    pub allow_symlinks: bool,
    pub max_length: usize,
    pub allowed_dirs: Vec<PathBuf>,
    pub blocked_patterns: Vec<String>,
}

impl Default for PathValidator {
    fn default() -> Self {
        Self {
            require_absolute: true,
            allow_symlinks: true,
            max_length: 4096,
            allowed_dirs: Vec::new(),
            blocked_patterns: vec!["..".to_string(), "\0".to_string()],
        }
    }
}

impl PathValidator {
    pub fn strict() -> Self {
        Self {
            require_absolute: true,
            allow_symlinks: false,
            max_length: 4096,
            allowed_dirs: Vec::new(),
            blocked_patterns: vec!["..".to_string(), "\0".to_string(), "//".to_string()],
        }
    }

    pub fn allow_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.allowed_dirs.push(dir.into());
        self
    }

    pub fn validate(&self, path: impl AsRef<Path>) -> ValidationResult<PathBuf> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();

        if path_str.is_empty() {
            return Err(ValidationError::EmptyPath);
        }

        if path_str.len() > self.max_length {
            return Err(ValidationError::PathTooLong {
                len: path_str.len(),
                max: self.max_length,
            });
        }

        for pattern in &self.blocked_patterns {
            if path_str.contains(pattern) {
                if pattern == ".." {
                    return Err(ValidationError::PathTraversal(path_str.to_string()));
                } else if pattern == "\0" {
                    return Err(ValidationError::NullBytes);
                } else {
                    return Err(ValidationError::InvalidCharacters(pattern.clone()));
                }
            }
        }

        if self.require_absolute && !path.is_absolute() {
            return Err(ValidationError::NotAbsolute(path_str.to_string()));
        }

        let canonical = if path.exists() {
            path.canonicalize()
                .map_err(|_| ValidationError::PathTraversal(path_str.to_string()))?
        } else {
            self.normalize_path(path)?
        };

        if !self.allow_symlinks && path.exists() {
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|_| ValidationError::SymlinkNotAllowed(path_str.to_string()))?;
            if metadata.file_type().is_symlink() {
                return Err(ValidationError::SymlinkNotAllowed(path_str.to_string()));
            }
        }

        if !self.allowed_dirs.is_empty() {
            let in_allowed = self
                .allowed_dirs
                .iter()
                .any(|allowed| canonical.starts_with(allowed));
            if !in_allowed {
                return Err(ValidationError::OutsideAllowedDir {
                    path: canonical.to_string_lossy().to_string(),
                    allowed: self
                        .allowed_dirs
                        .iter()
                        .map(|p| p.to_string_lossy().to_string())
                        .collect::<Vec<_>>()
                        .join(", "),
                });
            }
        }

        Ok(canonical)
    }

    fn normalize_path(&self, path: &Path) -> ValidationResult<PathBuf> {
        let mut components = Vec::new();

        for component in path.components() {
            match component {
                std::path::Component::ParentDir => {
                    return Err(ValidationError::PathTraversal(
                        path.to_string_lossy().to_string(),
                    ));
                }
                std::path::Component::CurDir => {}
                _ => components.push(component),
            }
        }

        Ok(components.iter().collect())
    }

    pub fn quick_check(&self, path: impl AsRef<Path>) -> bool {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();

        !path_str.is_empty()
            && path_str.len() <= self.max_length
            && !self.blocked_patterns.iter().any(|p| path_str.contains(p))
            && (!self.require_absolute || path.is_absolute())
    }
}

/// Configuration validator
#[derive(Debug, Default)]
pub struct ConfigValidator {
    errors: Vec<ValidationError>,
}

impl ConfigValidator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_range<T: PartialOrd + std::fmt::Display>(
        &mut self,
        field: &str,
        value: T,
        min: T,
        max: T,
    ) -> &mut Self {
        if value < min || value > max {
            self.errors.push(ValidationError::OutOfRange {
                field: field.to_string(),
                value: value.to_string(),
                min: min.to_string(),
                max: max.to_string(),
            });
        }
        self
    }

    pub fn validate_required<T>(&mut self, field: &str, value: &Option<T>) -> &mut Self {
        if value.is_none() {
            self.errors
                .push(ValidationError::MissingField(field.to_string()));
        }
        self
    }

    pub fn validate_not_empty(&mut self, field: &str, value: &str) -> &mut Self {
        if value.trim().is_empty() {
            self.errors
                .push(ValidationError::MissingField(field.to_string()));
        }
        self
    }

    pub fn validate_with<F>(&mut self, field: &str, message: &str, predicate: F) -> &mut Self
    where
        F: FnOnce() -> bool,
    {
        if !predicate() {
            self.errors.push(ValidationError::InvalidFormat {
                field: field.to_string(),
                message: message.to_string(),
            });
        }
        self
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn errors(&self) -> &[ValidationError] {
        &self.errors
    }

    pub fn finish(self) -> Result<(), Vec<ValidationError>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

/// Sanitize a filename by removing/replacing dangerous characters
pub fn sanitize_filename(name: &str) -> String {
    let dangerous_chars = ['/', '\\', '\0', ':', '*', '?', '"', '<', '>', '|'];
    let mut result = String::with_capacity(name.len());

    for c in name.chars() {
        if dangerous_chars.contains(&c) {
            result.push('_');
        } else if c.is_control() {
            // skip control chars
        } else {
            result.push(c);
        }
    }

    let reserved = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];

    let upper = result.to_uppercase();
    if reserved
        .iter()
        .any(|r| upper == *r || upper.starts_with(&format!("{}.", r)))
    {
        result = format!("_{}", result);
    }

    result = result.trim_matches(|c| c == '.' || c == ' ').to_string();
    if result.is_empty() {
        result = "unnamed".to_string();
    }

    result
}

/// Validate a SHA256 hash string
pub fn validate_sha256(hash: &str) -> ValidationResult<()> {
    if hash.len() != 64 {
        return Err(ValidationError::InvalidFormat {
            field: "sha256".to_string(),
            message: format!("Expected 64 characters, got {}", hash.len()),
        });
    }

    if !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ValidationError::InvalidFormat {
            field: "sha256".to_string(),
            message: "Contains non-hexadecimal characters".to_string(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_validator_rejects_traversal() {
        let validator = PathValidator::default();
        assert!(validator.validate("/etc/../etc/passwd").is_err());
        assert!(validator.validate("../../../etc/passwd").is_err());
    }

    #[test]
    fn test_path_validator_rejects_null_bytes() {
        let validator = PathValidator::default();
        assert!(validator.validate("/etc/passwd\0.txt").is_err());
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal.txt"), "normal.txt");
        assert_eq!(sanitize_filename("bad/file.txt"), "bad_file.txt");
        assert_eq!(sanitize_filename("bad\\file.txt"), "bad_file.txt");
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("...hidden"), "hidden");
        assert_eq!(sanitize_filename(""), "unnamed");
    }

    #[test]
    fn test_config_validator() {
        let mut validator = ConfigValidator::new();
        validator
            .validate_range("threads", 100, 1, 64)
            .validate_not_empty("name", "")
            .validate_required::<String>("optional", &None);
        assert!(!validator.is_valid());
        assert_eq!(validator.errors().len(), 3);
    }

    #[test]
    fn test_validate_sha256() {
        assert!(validate_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        .is_ok());
        assert!(validate_sha256("e3b0c44298fc1c149afbf4c8").is_err());
        assert!(validate_sha256(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85g"
        )
        .is_err());
    }
}
