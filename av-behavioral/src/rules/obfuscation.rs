use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    /// Base64 encoded command patterns.
    ///
    /// Detects patterns like:
    /// - `echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash`
    /// - `base64 -d <<< 'Y2F0IC9ldGMvcGFzc3dk' | bash`
    pub static ref BASE64_EXEC_PATTERN: Regex = Regex::new(
        r#"(?xi)
        (?:\becho\s+['"]?[A-Za-z0-9+/=]{4,}['"]?\s*\|\s*base64\s+(?:-d|--decode)\b\s*\|\s*(?:bash|sh|dash|zsh)\b)
        |(?:\bbase64\s+(?:-d|--decode)\b\s*<<<\s*['"]?[A-Za-z0-9+/=]{4,}['"]?\s*(?:\|\s*(?:bash|sh|dash|zsh)\b)?)
        |(?:\$\(\s*echo\s+['"]?[A-Za-z0-9+/=]{4,}['"]?\s*\|\s*base64\s+(?:-d|--decode)\b[^)]*\))
        "#
    )
    .unwrap();

    /// Double base64 encoding (evasion technique).
    ///
    /// Detects: `... base64 -d ... base64 -d ...`
    pub static ref DOUBLE_BASE64_PATTERN: Regex = Regex::new(
        r#"(?i)\bbase64\s+(?:-d|--decode)\b.*\bbase64\s+(?:-d|--decode)\b"#
    )
    .unwrap();

    /// Hex encoded command patterns.
    ///
    /// Detects patterns like:
    /// - `echo '636174202f6574632f706173737764' | xxd -r -p | bash`
    /// - `printf '\x63\x61\x74'`
    /// - `$'\x63\x61\x74'`
    pub static ref HEX_EXEC_PATTERN: Regex = Regex::new(
        r#"(?xi)
        (?:\becho\s+['"]?[0-9a-f]{6,}['"]?\s*\|\s*xxd\s+-r\s+-p\s*\|\s*(?:bash|sh|dash|zsh)\b)
        |(?:\bxxd\s+-r\s+-p\b)
        |(?:\bprintf\s+['"][^'"]*(?:\\x[0-9a-f]{2}){2,}[^'"]*['"])
        |(?:\$\s*'(?:\\x[0-9a-f]{2}){2,}')
        |(?:(?:\\x[0-9a-f]{2}){2,})
        "#
    )
    .unwrap();

    /// Octal encoded command patterns.
    ///
    /// Detects: `$'\143\141\164'` (cat in octal).
    pub static ref OCTAL_EXEC_PATTERN: Regex =
        Regex::new(r#"\$'(?:\\[0-7]{1,3}){2,}'"#).unwrap();

    /// String concatenation evasion.
    ///
    /// Detects patterns like:
    /// - `c'a't /e'tc'/pa'ss'wd`
    /// - `${c}${a}${t}`
    pub static ref CONCAT_EVASION_PATTERN: Regex = Regex::new(
        r#"(?xi)
        (?:[a-z](?:'|")[a-z](?:'|")[a-z])
        |(?:\$\{[^}]{1,32}\}\$\{[^}]{1,32}\}\$\{[^}]{1,32}\})
        "#
    )
    .unwrap();

    /// Environment variable slicing.
    ///
    /// Detects: `${PATH:0:1}${HOME:0:1}` to build commands.
    pub static ref ENV_SLICE_PATTERN: Regex = Regex::new(
        r#"(?x)\$\{[A-Z_]+:[0-9]+:[0-9]+\}.*\$\{[A-Z_]+:[0-9]+:[0-9]+\}"#
    )
    .unwrap();

    /// ROT13 encoding.
    ///
    /// Detects: `tr 'a-zA-Z' 'n-za-mN-ZA-M'` and similar.
    pub static ref ROT13_PATTERN: Regex = Regex::new(
        r#"(?xi)\btr\s+['"](?:a-zA-Z|A-Za-z)['"]\s+['"](?:n-za-mN-ZA-M|N-ZA-Mn-za-m)['"]"#
    )
    .unwrap();

    /// Brace expansion evasion.
    ///
    /// Detects: `{cat,/etc/passwd}`.
    pub static ref BRACE_EXPANSION_PATTERN: Regex =
        Regex::new(r#"\{[a-z]{2,},/[^}]+\}"#).unwrap();

    /// IFS manipulation.
    ///
    /// Detects patterns like:
    /// - `IFS=,;cat<<<$'cat,/etc/passwd'`
    /// - `IFS=... eval ...`
    pub static ref IFS_MANIPULATION_PATTERN: Regex =
        Regex::new(r#"(?i)(?:\bIFS=[^;\n]+;[^\n]*<<<|\bIFS=[^\n]+\beval\b)"#).unwrap();

    /// Backtick substitution with encoded content.
    ///
    /// Detects: `` `echo Y2F0Cg== | base64 -d` ``
    pub static ref BACKTICK_ENCODED_PATTERN: Regex =
        Regex::new(r#"`[^`]*(?:base64|xxd|printf)[^`]*`"#).unwrap();
}

/// Check if a command line contains obfuscation indicators.
pub fn detect_obfuscation(cmdline: &str) -> Option<ObfuscationType> {
    if BASE64_EXEC_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::Base64);
    }
    if DOUBLE_BASE64_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::DoubleBase64);
    }
    if HEX_EXEC_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::Hex);
    }
    if OCTAL_EXEC_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::Octal);
    }
    if CONCAT_EVASION_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::StringConcat);
    }
    if ENV_SLICE_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::EnvSlice);
    }
    if ROT13_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::Rot13);
    }
    if BRACE_EXPANSION_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::BraceExpansion);
    }
    if IFS_MANIPULATION_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::IfsManipulation);
    }
    if BACKTICK_ENCODED_PATTERN.is_match(cmdline) {
        return Some(ObfuscationType::BacktickEncoded);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationType {
    Base64,
    DoubleBase64,
    Hex,
    Octal,
    StringConcat,
    EnvSlice,
    Rot13,
    BraceExpansion,
    IfsManipulation,
    BacktickEncoded,
}

impl ObfuscationType {
    pub fn mitre_technique(&self) -> &'static str {
        "T1027" // Obfuscated Files or Information
    }

    pub fn severity(&self) -> &'static str {
        match self {
            Self::DoubleBase64 | Self::IfsManipulation => "critical",
            _ => "high",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_detection() {
        let cases = vec![
            ("echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash", true),
            ("echo 'aWQK' | base64 -d | sh", true),
            ("base64 -d <<< 'Y2F0IC9ldGMvcGFzc3dk' | bash", true),
            ("echo hello", false),
            ("base64 encode myfile", false),
        ];

        for (input, should_detect) in cases {
            let result = BASE64_EXEC_PATTERN.is_match(input);
            assert_eq!(result, should_detect, "Failed for: {}", input);
        }
    }

    #[test]
    fn test_double_base64_detection() {
        assert!(DOUBLE_BASE64_PATTERN.is_match("echo aWQ= | base64 -d | base64 -d | bash"));
        assert!(!DOUBLE_BASE64_PATTERN.is_match("echo aWQ= | base64 -d | bash"));
    }

    #[test]
    fn test_hex_detection() {
        let cases = vec![
            ("echo '636174' | xxd -r -p | bash", true),
            (r#"printf '\x63\x61\x74'"#, true),
            (r#"bash -c 'echo -e "\x69\x64"'"#, true),
            ("xxd myfile", false),
        ];

        for (input, should_detect) in cases {
            let result = HEX_EXEC_PATTERN.is_match(input);
            assert_eq!(result, should_detect, "Failed for: {}", input);
        }
    }

    #[test]
    fn test_octal_detection() {
        assert!(OCTAL_EXEC_PATTERN.is_match(r"$'\143\141\164'"));
        assert!(!OCTAL_EXEC_PATTERN.is_match("echo test"));
    }

    #[test]
    fn test_concat_detection() {
        assert!(CONCAT_EVASION_PATTERN.is_match("c'a't /etc/passwd"));
        assert!(CONCAT_EVASION_PATTERN.is_match("${c}${a}${t} /etc/passwd"));
        assert!(!CONCAT_EVASION_PATTERN.is_match("cat /etc/passwd"));
    }

    #[test]
    fn test_env_slice_detection() {
        assert!(ENV_SLICE_PATTERN.is_match("${PATH:0:1}${HOME:0:1}"));
        assert!(!ENV_SLICE_PATTERN.is_match("$PATH"));
    }

    #[test]
    fn test_rot13_detection() {
        assert!(ROT13_PATTERN.is_match("tr 'a-zA-Z' 'n-za-mN-ZA-M'"));
        assert!(!ROT13_PATTERN.is_match("tr 'a' 'b'"));
    }
}
