use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_md5, EVP_MAX_MD_SIZE, EVP_MD, EVP_MD_CTX,
};

use crate::{Background, Digest, DigestData, Generator};

/// A structure used to generated a MD5 digest.
pub struct MD5 {
    /// The OpenSSL context used to generate the digest.
    ctx: *mut EVP_MD_CTX,
    /// The OpenSSL MD5 digest algorithm.
    md5: *const EVP_MD,
}

impl MD5 {
    /// The length of the MD5 digest, in bytes.
    pub const LENGTH: usize = 16;

    /// Create a new MD5 structure to generate a digest.
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
        let md5 = unsafe { EVP_md5() };
        assert!(!md5.is_null());
        let this = Self { ctx, md5 };
        this.reset();
        this
    }

    /// Initialize the OpenSSL context for use computing an MD5 digest.
    fn reset(&self) {
        unsafe { EVP_DigestInit(self.ctx, self.md5) };
    }
}

impl Digest<{ Self::LENGTH }> for MD5 {
    /// Update the MD5 digest using the given `data`.
    fn update(&mut self, data: &[u8]) {
        unsafe {
            EVP_DigestUpdate(self.ctx, data.as_ptr().cast(), data.len());
        }
    }

    /// Finalize the MD5 digest computation and return the result. The
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

impl Default for MD5 {
    /// Create a default MD5 structure to generate a digest.
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for MD5 {
    /// Clean up the OpenSSL context.
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

/// Structure used to compute an MD5 digest in a separate thread.
pub struct BackgroundMD5 {
    worker: Background<{ MD5::LENGTH }>,
}

impl BackgroundMD5 {
    /// Create a new `BackgroundMD5` structure.
    pub fn new() -> Self {
        Self {
            worker: Background::new(MD5::new),
        }
    }
}

impl Generator for BackgroundMD5 {
    /// Add the given `data` to the MD5 digest.
    fn append(&self, data: Arc<[u8]>) {
        self.worker.update(data);
    }

    /// Retrieve the MD5 digest data, and reset the digest computation.
    fn result(&self) -> DigestData {
        DigestData::MD5(self.worker.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn md5_empty() {
        let mut md5 = MD5::new();
        assert_eq!(md5.finish(), fixtures::md5::EMPTY);
    }

    #[test]
    fn md5_zero() {
        let mut md5 = MD5::new();
        md5.update(&[0; 0x4000]);
        md5.update(&[0; 0x0d]);
        assert_eq!(md5.finish(), fixtures::md5::ZERO_400D);
    }

    #[test]
    fn md5_random() {
        let mut md5 = MD5::new();
        md5.update(&fixtures::RANDOM_11171);
        assert_eq!(md5.finish(), fixtures::md5::RANDOM_11171);
    }

    #[test]
    fn md5_multiple() {
        let mut md5 = MD5::new();
        assert_eq!(md5.finish(), fixtures::md5::EMPTY);
        md5.update(&fixtures::ZERO_400D);
        assert_eq!(md5.finish(), fixtures::md5::ZERO_400D);
        md5.update(&fixtures::RANDOM_11171);
        assert_eq!(md5.finish(), fixtures::md5::RANDOM_11171);
    }

    #[test]
    fn background_md5() {
        let md5 = BackgroundMD5::new();
        assert_eq!(md5.result(), DigestData::MD5(fixtures::md5::EMPTY));
        md5.append(Arc::from(fixtures::ZERO_400D));
        assert_eq!(md5.result(), DigestData::MD5(fixtures::md5::ZERO_400D));
        md5.append(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(
            md5.result(),
            DigestData::MD5(fixtures::md5::RANDOM_11171)
        );
    }
}
