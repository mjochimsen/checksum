use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_ripemd160, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX,
};

use crate::{Background, Digest, DigestData, Generator};

/// A structure used to generate a RMD160 digest.
pub struct RMD160 {
    /// The OpenSSL context used to generate the digest.
    ctx: *mut EVP_MD_CTX,
    /// The OpenSSL RMD160 digest algorithm.
    rmd160: *const EVP_MD,
}

impl RMD160 {
    /// The length of the RMD160 digest, in bytes.
    pub const LENGTH: usize = 20;

    /// Create a new RMD160 structure to generate a digest.
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
        let rmd160 = unsafe { EVP_ripemd160() };
        assert!(!rmd160.is_null());
        let mut this = Self { ctx, rmd160 };
        this.reset();
        this
    }

    /// Initialize the OpenSSL context for use computing an RMD160 digest.
    fn reset(&mut self) {
        unsafe { EVP_DigestInit(self.ctx, self.rmd160) };
    }
}

impl Digest<{ Self::LENGTH }> for RMD160 {
    /// Update the RMD160 digest using the given `data`.
    fn update(&mut self, data: &[u8]) {
        unsafe {
            EVP_DigestUpdate(self.ctx, data.as_ptr().cast(), data.len());
        }
    }

    /// Finalize the RMD160 digest computation and return the result. The
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

impl Default for RMD160 {
    /// Create a default RMD160 structure to generate a digest.
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RMD160 {
    /// Clean up the OpenSSL context.
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

/// Structure used to compute a RMD160 digest in a separate thread.
pub struct BackgroundRMD160 {
    worker: Background<{ RMD160::LENGTH }>,
}

impl BackgroundRMD160 {
    /// Create a new `BackgroundRMD160` structure.
    pub fn new() -> Self {
        Self {
            worker: Background::new(RMD160::new),
        }
    }
}

impl Generator for BackgroundRMD160 {
    /// Add the given `data` to the RMD160 digest.
    fn append(&self, data: Arc<[u8]>) {
        self.worker.update(data);
    }

    /// Retrieve the RMD160 digest data, and reset the digest computation.
    fn result(&self) -> DigestData {
        DigestData::RMD160(self.worker.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn empty() {
        let mut rmd160 = RMD160::new();
        assert_eq!(rmd160.finish(), fixtures::rmd160::EMPTY);
    }

    #[test]
    fn zero() {
        let mut rmd160 = RMD160::new();
        rmd160.update(&[0; 0x4000]);
        rmd160.update(&[0; 0x0d]);
        assert_eq!(rmd160.finish(), fixtures::rmd160::ZERO_400D);
    }

    #[test]
    fn random() {
        let mut rmd160 = RMD160::new();
        rmd160.update(&fixtures::RANDOM_11171);
        assert_eq!(rmd160.finish(), fixtures::rmd160::RANDOM_11171);
    }

    #[test]
    fn multiple() {
        let mut rmd160 = RMD160::new();
        assert_eq!(rmd160.finish(), fixtures::rmd160::EMPTY);
        rmd160.update(&fixtures::ZERO_400D);
        assert_eq!(rmd160.finish(), fixtures::rmd160::ZERO_400D);
        rmd160.update(&fixtures::RANDOM_11171);
        assert_eq!(rmd160.finish(), fixtures::rmd160::RANDOM_11171);
    }

    #[test]
    fn background() {
        let rmd160 = BackgroundRMD160::new();
        assert_eq!(
            rmd160.result(),
            DigestData::RMD160(fixtures::rmd160::EMPTY)
        );
        rmd160.append(Arc::from(fixtures::ZERO_400D));
        assert_eq!(
            rmd160.result(),
            DigestData::RMD160(fixtures::rmd160::ZERO_400D)
        );
        rmd160.append(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(
            rmd160.result(),
            DigestData::RMD160(fixtures::rmd160::RANDOM_11171)
        );
    }
}
