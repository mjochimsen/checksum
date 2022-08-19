use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_sha256, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX,
};

use crate::{Background, Digest, DigestData, Generator};

/// A structure used to generate a SHA256 digest.
pub struct SHA256 {
    /// The OpenSSL context used to generate the digest.
    ctx: *mut EVP_MD_CTX,
    /// The OpenSSL SHA256 digest algorithm.
    sha256: *const EVP_MD,
}

impl SHA256 {
    /// The length of the SHA256 digest, in bytes.
    pub const LENGTH: usize = 32;

    /// Create a new SHA256 structure to generate a digest.
    ///
    /// ## Panics
    ///
    /// If we are unable to initialize the OpenSSL structures we use to
    /// compute the digest, a panic will occur. This should not occur
    /// unless the OpenSSL API has fallen out of sync.
    #[must_use]
    pub fn new() -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null());
        let sha256 = unsafe { EVP_sha256() };
        assert!(!sha256.is_null());
        let mut this = Self { ctx, sha256 };
        this.reset();
        this
    }

    /// Initialize the OpenSSL context for use computing an SHA256 digest.
    fn reset(&mut self) {
        unsafe { EVP_DigestInit(self.ctx, self.sha256) };
    }
}

impl Digest<{ Self::LENGTH }> for SHA256 {
    /// Update the SHA256 digest using the given `data`.
    fn update(&mut self, data: &[u8]) {
        unsafe {
            EVP_DigestUpdate(self.ctx, data.as_ptr().cast(), data.len());
        }
    }

    /// Finalize the SHA256 digest computation and return the result. The
    /// OpenSSL context is reset so that it can be reused.
    fn finish(&mut self) -> [u8; Self::LENGTH] {
        let mut len = 0;
        let mut buffer = [0u8; EVP_MAX_MD_SIZE as usize];
        unsafe { EVP_DigestFinal(self.ctx, buffer.as_mut_ptr(), &mut len) };
        assert!(Self::LENGTH == len as usize);
        self.reset();
        buffer[..Self::LENGTH].try_into().unwrap()
    }
}

impl Default for SHA256 {
    /// Create a default SHA256 structure to generate a digest.
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SHA256 {
    /// Clean up the OpenSSL context.
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

/// Structure used to compute an SHA256 digest in a separate thread.
pub struct BackgroundSHA256 {
    worker: Background<{ SHA256::LENGTH }>,
}

impl BackgroundSHA256 {
    /// Create a new `BackgroundSHA256` structure.
    pub fn new() -> Self {
        Self {
            worker: Background::new(SHA256::new),
        }
    }
}

impl Generator for BackgroundSHA256 {
    /// Add the given `data` to the SHA256 digest.
    fn append(&self, data: Arc<[u8]>) {
        self.worker.update(data);
    }

    /// Retrieve the SHA256 digest data, and reset the digest computation.
    fn result(&self) -> DigestData {
        DigestData::SHA256(self.worker.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn empty() {
        let mut sha256 = SHA256::new();
        assert_eq!(sha256.finish(), fixtures::sha256::EMPTY);
    }

    #[test]
    fn zero() {
        let mut sha256 = SHA256::new();
        sha256.update(&[0; 0x4000]);
        sha256.update(&[0; 0x0d]);
        assert_eq!(sha256.finish(), fixtures::sha256::ZERO_400D);
    }

    #[test]
    fn random() {
        let mut sha256 = SHA256::new();
        sha256.update(&fixtures::RANDOM_11171);
        assert_eq!(sha256.finish(), fixtures::sha256::RANDOM_11171);
    }

    #[test]
    fn multiple() {
        let mut sha256 = SHA256::new();
        assert_eq!(sha256.finish(), fixtures::sha256::EMPTY);
        sha256.update(&fixtures::ZERO_400D);
        assert_eq!(sha256.finish(), fixtures::sha256::ZERO_400D);
        sha256.update(&fixtures::RANDOM_11171);
        assert_eq!(sha256.finish(), fixtures::sha256::RANDOM_11171);
    }

    #[test]
    fn background() {
        let sha256 = BackgroundSHA256::new();
        assert_eq!(
            sha256.result(),
            DigestData::SHA256(fixtures::sha256::EMPTY)
        );
        sha256.append(Arc::from(fixtures::ZERO_400D));
        assert_eq!(
            sha256.result(),
            DigestData::SHA256(fixtures::sha256::ZERO_400D)
        );
        sha256.append(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(
            sha256.result(),
            DigestData::SHA256(fixtures::sha256::RANDOM_11171)
        );
    }
}
