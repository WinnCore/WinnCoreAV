//! Secure memory handling for sensitive data.
//! Provides zeroizing containers and helpers to reduce leakage.

use std::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Vec that zeroizes its contents on drop.
#[derive(ZeroizeOnDrop)]
pub struct SecretVec<T: Zeroize> {
    inner: Vec<T>,
}

impl<T: Zeroize + Default + Clone> SecretVec<T> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    pub fn from_vec(data: Vec<T>) -> Self {
        Self { inner: data }
    }

    pub fn from_slice(data: &[T]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    pub fn push(&mut self, value: T) {
        self.inner.push(value);
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.zeroize();
        self.inner.clear();
    }
}

impl<T: Zeroize> Deref for SecretVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize> DerefMut for SecretVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T: Zeroize> std::fmt::Debug for SecretVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretVec")
            .field("len", &self.inner.len())
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// A fixed-size secret buffer. Zeroized on drop. Attempts to mlock on Linux.
pub struct SecretBytes<const N: usize> {
    data: [u8; N],
    mlocked: bool,
}

impl<const N: usize> SecretBytes<N> {
    pub fn new() -> Self {
        let mut s = Self {
            data: [0u8; N],
            mlocked: false,
        };
        s.try_mlock();
        s
    }

    pub fn from_bytes(bytes: [u8; N]) -> Self {
        let mut s = Self {
            data: bytes,
            mlocked: false,
        };
        s.try_mlock();
        s
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), N, "Slice length must match SecretBytes size");
        let mut data = [0u8; N];
        data.copy_from_slice(slice);
        Self::from_bytes(data)
    }

    #[cfg(target_os = "linux")]
    fn try_mlock(&mut self) {
        unsafe {
            let ptr = self.data.as_ptr() as *const libc::c_void;
            if libc::mlock(ptr, N) == 0 {
                self.mlocked = true;
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn try_mlock(&mut self) {
        // Not available
    }

    #[cfg(target_os = "linux")]
    fn try_munlock(&mut self) {
        if self.mlocked {
            unsafe {
                let ptr = self.data.as_ptr() as *const libc::c_void;
                let _ = libc::munlock(ptr, N);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn try_munlock(&mut self) {}

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.data
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; N] {
        &mut self.data
    }
}

impl<const N: usize> Default for SecretBytes<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for SecretBytes<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<const N: usize> DerefMut for SecretBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.data.zeroize();
        self.try_munlock();
    }
}

impl<const N: usize> std::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBytes")
            .field("size", &N)
            .field("mlocked", &self.mlocked)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

/// Constant-time comparison to avoid timing side channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn secret_bytes_eq<const N: usize>(a: &SecretBytes<N>, b: &SecretBytes<N>) -> bool {
    constant_time_eq(&a.data, &b.data)
}

/// Disable core dumps to reduce secret exposure.
#[cfg(target_os = "linux")]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    use std::io::Error;
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err(Error::last_os_error());
        }
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let c = [1u8, 2, 4];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[test]
    fn test_secret_bytes() {
        let mut secret: SecretBytes<16> = SecretBytes::new();
        secret.as_bytes_mut().copy_from_slice(&[0xAA; 16]);
        assert_eq!(secret.as_bytes()[0], 0xAA);
    }
}
