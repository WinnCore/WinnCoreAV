//! Compile-time string obfuscation helpers.
//! This is obfuscation, not cryptographic protection.

use std::sync::OnceLock;
use zeroize::Zeroize;

/// A compile-time encrypted string.
pub struct EncryptedString {
    encrypted: &'static [u8],
    key: &'static [u8],
    decrypted: OnceLock<DecryptedString>,
}

struct DecryptedString {
    data: Vec<u8>,
}

impl Drop for DecryptedString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl EncryptedString {
    pub const fn new(encrypted: &'static [u8], key: &'static [u8]) -> Self {
        Self {
            encrypted,
            key,
            decrypted: OnceLock::new(),
        }
    }

    pub fn get(&self) -> &str {
        let dec = self.decrypt_inner();
        std::str::from_utf8(dec).unwrap_or("")
    }

    pub fn get_bytes(&self) -> &[u8] {
        self.decrypt_inner()
    }

    fn decrypt_inner(&self) -> &[u8] {
        self.decrypted.get_or_init(|| {
            let mut data = Vec::with_capacity(self.encrypted.len());
            for (i, &b) in self.encrypted.iter().enumerate() {
                data.push(b ^ self.key[i % self.key.len()]);
            }
            DecryptedString { data }
        });
        &self.decrypted.get().unwrap().data
    }
}

impl std::fmt::Debug for EncryptedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedString")
            .field("len", &self.encrypted.len())
            .finish()
    }
}

/// Const XOR for compile-time encryption.
const fn xor_bytes<const N: usize, const K: usize>(bytes: [u8; N], key: [u8; K]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = bytes[i] ^ key[i % K];
        i += 1;
    }
    out
}

/// Macro to define an obfuscated string literal.
#[macro_export]
macro_rules! encrypted_string {
    ($s:expr) => {{
        const PLAINTEXT: &str = $s;
        const KEY: [u8; 8] = $crate::encrypted_strings::const_key(file!(), line!(), column!());
        const ENC: [u8; PLAINTEXT.len()] = $crate::encrypted_strings::xor_literal(PLAINTEXT, KEY);
        $crate::encrypted_strings::EncryptedString::new(&ENC, &KEY)
    }};
}

/// Build a pseudo-random key from file/line/column (deterministic).
pub const fn const_key(file: &str, line: u32, col: u32) -> [u8; 8] {
    let mut h: u64 = 0xcbf29ce484222325;
    let bytes = file.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        h ^= bytes[i] as u64;
        h = h.wrapping_mul(0x100000001b3);
        i += 1;
    }
    h ^= line as u64;
    h = h.wrapping_mul(0x100000001b3);
    h ^= col as u64;
    h = h.wrapping_mul(0x100000001b3);
    h.to_le_bytes()
}

/// XOR a string literal with a key at compile time.
pub const fn xor_literal<const N: usize>(s: &str, key: [u8; 8]) -> [u8; N] {
    let bytes = s.as_bytes();
    let mut arr = [0u8; N];
    let mut i = 0;
    while i < N {
        arr[i] = bytes[i] ^ key[i % key.len()];
        i += 1;
    }
    arr
}

/// Runtime-encrypted string with zeroizing key.
pub struct RuntimeEncrypted {
    encrypted: Vec<u8>,
    key: [u8; 32],
}

impl RuntimeEncrypted {
    pub fn new(plaintext: &str) -> Self {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).expect("Failed to get random bytes");
        let encrypted: Vec<u8> = plaintext
            .as_bytes()
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % 32])
            .collect();
        Self { encrypted, key }
    }

    pub fn decrypt(&self) -> String {
        let decrypted: Vec<u8> = self
            .encrypted
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.key[i % 32])
            .collect();
        String::from_utf8(decrypted).unwrap_or_default()
    }
}

impl Drop for RuntimeEncrypted {
    fn drop(&mut self) {
        self.encrypted.zeroize();
        self.key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_string_macro() {
        let s = encrypted_string!("hello");
        assert_eq!(s.get(), "hello");
    }

    #[test]
    fn test_runtime_encryption() {
        let enc = RuntimeEncrypted::new("secret");
        assert_eq!(enc.decrypt(), "secret");
    }
}
