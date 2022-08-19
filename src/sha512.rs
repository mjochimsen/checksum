use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_sha512, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX,
};

use crate::{Background, Digest, DigestData, Generator};

/// A structure used to generate a SHA512 digest.
pub struct SHA512 {
    /// The OpenSSL context used to generate the digest.
    ctx: *mut EVP_MD_CTX,
    /// The OpenSSL SHA512 digest algorithm.
    sha512: *const EVP_MD,
}

impl SHA512 {
    /// The length of the SHA512 digest, in bytes.
    pub const LENGTH: usize = 64;

    /// Create a new SHA512 structure to generate a digest.
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
        let sha512 = unsafe { EVP_sha512() };
        assert!(!sha512.is_null());
        let mut this = Self { ctx, sha512 };
        this.reset();
        this
    }

    /// Initialize the OpenSSL context for use computing an SHA512 digest.
    fn reset(&mut self) {
        unsafe { EVP_DigestInit(self.ctx, self.sha512) };
    }
}

impl Digest<{ Self::LENGTH }> for SHA512 {
    /// Update the SHA512 digest using the given `data`.
    fn update(&mut self, data: &[u8]) {
        unsafe {
            EVP_DigestUpdate(self.ctx, data.as_ptr().cast(), data.len());
        }
    }

    /// Finalize the SHA512 digest computation and return the result. The
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

impl Default for SHA512 {
    /// Create a default SHA512 structure to generate a digest.
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SHA512 {
    /// Clean up the OpenSSL context.
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

/// Structure used to compute an SHA512 digest in a separate thread.
pub struct BackgroundSHA512 {
    worker: Background<{ SHA512::LENGTH }>,
}

impl BackgroundSHA512 {
    /// Create a new `BackgroundSHA512` structure.
    pub fn new() -> Self {
        Self {
            worker: Background::new(SHA512::new),
        }
    }
}

impl Generator for BackgroundSHA512 {
    /// Add the given `data` to the SHA512 digest.
    fn append(&self, data: Arc<[u8]>) {
        self.worker.update(data);
    }

    /// Retrieve the SHA512 digest data, and reset the digest computation.
    fn result(&self) -> DigestData {
        DigestData::SHA512(self.worker.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn empty() {
        let mut sha512 = SHA512::new();
        assert_eq!(sha512.finish(), fixtures::sha512::EMPTY);
    }

    #[test]
    fn zero() {
        let mut sha512 = SHA512::new();
        sha512.update(&[0; 0x4000]);
        sha512.update(&[0; 0x0d]);
        assert_eq!(sha512.finish(), fixtures::sha512::ZERO_400D);
    }

    #[test]
    fn random() {
        let mut sha512 = SHA512::new();
        sha512.update(&fixtures::RANDOM_11171);
        assert_eq!(sha512.finish(), fixtures::sha512::RANDOM_11171);
    }

    #[test]
    fn multiple() {
        let mut sha512 = SHA512::new();
        assert_eq!(sha512.finish(), fixtures::sha512::EMPTY);
        sha512.update(&fixtures::ZERO_400D);
        assert_eq!(sha512.finish(), fixtures::sha512::ZERO_400D);
        sha512.update(&fixtures::RANDOM_11171);
        assert_eq!(sha512.finish(), fixtures::sha512::RANDOM_11171);
    }

    #[test]
    fn background() {
        let sha512 = BackgroundSHA512::new();
        assert_eq!(
            sha512.result(),
            DigestData::SHA512(fixtures::sha512::EMPTY)
        );
        sha512.append(Arc::from(fixtures::ZERO_400D));
        assert_eq!(
            sha512.result(),
            DigestData::SHA512(fixtures::sha512::ZERO_400D)
        );
        sha512.append(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(
            sha512.result(),
            DigestData::SHA512(fixtures::sha512::RANDOM_11171)
        );
    }
}
