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
    const LENGTH: usize = 16;

    /// Create a new MD5 structure to generate a digest.
    pub fn new() -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null());
        let md5 = unsafe { EVP_md5() };
        assert!(!md5.is_null());
        let this = Self { ctx, md5 };
        this.reset();
        this
    }

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

impl Drop for MD5 {
    /// Clean up the OpenSSL context.
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

pub struct BackgroundMD5 {
    worker: Background<{ MD5::LENGTH }>,
}

impl BackgroundMD5 {
    pub fn new() -> Self {
        Self {
            worker: Background::new(MD5::new),
        }
    }
}

impl Generator for BackgroundMD5 {
    fn append(&self, data: Arc<[u8]>) {
        self.worker.update(data);
    }

    fn result(&self) -> DigestData {
        DigestData::MD5(self.worker.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_digests;

    #[test]
    fn md5_empty() {
        let mut md5 = MD5::new();

        let digest = md5.finish();

        assert_eq!(DigestData::MD5(digest), test_digests::md5::EMPTY);
    }

    #[test]
    fn md5_data() {
        let mut md5 = MD5::new();

        md5.update(&[0; 0x4000]);
        md5.update(&[0; 0x0d]);

        let digest = md5.finish();

        assert_eq!(DigestData::MD5(digest), test_digests::md5::ZERO_400D);
    }

    #[test]
    fn md5_multiple() {
        let mut md5 = MD5::new();

        let digest = md5.finish();

        assert_eq!(DigestData::MD5(digest), test_digests::md5::EMPTY);

        let data = [0; 0x4000];
        md5.update(&data);
        let data = [0; 0x0d];
        md5.update(&data);

        let digest = md5.finish();

        assert_eq!(DigestData::MD5(digest), test_digests::md5::ZERO_400D);

        let digest = md5.finish();

        assert_eq!(DigestData::MD5(digest), test_digests::md5::EMPTY);
    }

    #[test]
    fn background_md5_empty() {
        let md5 = BackgroundMD5::new();

        let digest = md5.result();

        assert_eq!(digest, test_digests::md5::EMPTY);
    }

    #[test]
    fn background_md5_data() {
        let md5 = BackgroundMD5::new();

        let data = Arc::from([0; 0x4000]);
        md5.append(data);
        let data = Arc::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        assert_eq!(digest, test_digests::md5::ZERO_400D);
    }

    #[test]
    fn background_md5_multiple() {
        let md5 = BackgroundMD5::new();

        let digest = md5.result();

        assert_eq!(digest, test_digests::md5::EMPTY);

        let data = Arc::from([0; 0x4000]);
        md5.append(data);
        let data = Arc::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        assert_eq!(digest, test_digests::md5::ZERO_400D);

        let digest = md5.result();

        assert_eq!(digest, test_digests::md5::EMPTY);
    }
}
