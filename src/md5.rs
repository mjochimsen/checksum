use std::ptr::null_mut;
use std::sync::mpsc;
use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_md5, EVP_MAX_MD_SIZE, EVP_MD_CTX,
};

use crate::{Digest, DigestData, Generator};

/// A structure used to generated a MD5 digest.
pub struct MD5 {
    /// The OpenSSL context used to generate the digest.
    ctx: *mut EVP_MD_CTX,
    /// The digest data (once the digest is fully computed).
    digest: [u8; Self::LENGTH],
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
        unsafe { EVP_DigestInit(ctx, md5) };
        Self {
            ctx,
            digest: [0; Self::LENGTH],
        }
    }
}

impl Digest<{ MD5::LENGTH }> for MD5 {
    /// The length of the MD5 digest, in bytes.
    fn length(&self) -> usize {
        Self::LENGTH
    }

    /// Update the MD5 digest using the given `data`.
    fn update(&mut self, data: &[u8]) {
        if !self.ctx.is_null() {
            unsafe {
                EVP_DigestUpdate(self.ctx, data.as_ptr().cast(), data.len());
            }
        }
    }

    /// Finalize the MD5 digest computation and return the result.
    fn digest(&mut self) -> [u8; MD5::LENGTH] {
        if !self.ctx.is_null() {
            let mut len = 0;
            let mut buffer = [0u8; EVP_MAX_MD_SIZE as usize];
            unsafe {
                EVP_DigestFinal(self.ctx, buffer.as_mut_ptr(), &mut len)
            };
            assert!(Self::LENGTH == len as usize);
            self.digest[..Self::LENGTH]
                .copy_from_slice(&buffer[..Self::LENGTH]);
            unsafe { EVP_MD_CTX_free(self.ctx) };
            self.ctx = null_mut();
        }
        self.digest
    }
}

impl Drop for MD5 {
    /// Clean up the OpenSSL context.
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { EVP_MD_CTX_free(self.ctx) };
            self.ctx = null_mut();
        }
    }
}

pub struct BackgroundMD5 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; MD5::LENGTH]>,
}

impl BackgroundMD5 {
    pub fn new() -> Self {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_md5(&rx_input, &tx_result);
        });

        Self {
            tx_input,
            rx_result,
        }
    }
}

impl Generator for BackgroundMD5 {
    fn append(&self, data: Arc<[u8]>) {
        self.tx_input
            .send(Message::Append(data))
            .expect("unexpected error appending to digest");
    }

    fn result(&self) -> DigestData {
        use std::time::Duration;

        self.tx_input
            .send(Message::Finish)
            .expect("unexpected error finishing digest");

        let timeout = Duration::new(5, 0);
        let result = self
            .rx_result
            .recv_timeout(timeout)
            .expect("unable to retrieve digest value");

        DigestData::MD5(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_md5(
    rx_input: &mpsc::Receiver<Message>,
    tx_result: &mpsc::Sender<[u8; MD5::LENGTH]>,
) {
    let mut md5 = MD5::new();
    let mut digest;

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => md5.update(&data),
            Ok(Message::Finish) => {
                digest = md5.digest();
                md5 = MD5::new();
                tx_result.send(digest).unwrap();
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_digests::*;
    use super::*;

    #[test]
    fn md5_empty() {
        let mut md5 = MD5::new();

        let digest = md5.digest();

        if let DigestData::MD5(expected) = MD5_ZERO_0 {
            assert_eq!(digest, expected);
        } else {
            assert!(
                false,
                "unexpected value for MD5_ZERO_0 ({:?})",
                MD5_ZERO_0
            );
        }
    }

    #[test]
    fn md5_data() {
        let mut md5 = MD5::new();

        md5.update(&[0; 0x4000]);
        md5.update(&[0; 0x0d]);

        let digest = md5.digest();

        if let DigestData::MD5(expected) = MD5_ZERO_400D {
            assert_eq!(digest, expected);
        } else {
            assert!(
                false,
                "unexpected value for MD5_ZERO_400D ({:?})",
                MD5_ZERO_400D
            );
        }
    }

    #[test]
    fn background_md5_empty() {
        let md5 = BackgroundMD5::new();

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_0);
    }

    #[test]
    fn background_md5_data() {
        let md5 = BackgroundMD5::new();

        let data = Arc::from([0; 0x4000]);
        md5.append(data);
        let data = Arc::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_400D);
    }

    #[test]
    fn background_md5_multiple() {
        let md5 = BackgroundMD5::new();

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_0);

        let data = Arc::from([0; 0x4000]);
        md5.append(data);
        let data = Arc::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_400D);

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_0);
    }
}
