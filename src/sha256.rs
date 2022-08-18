use std::sync::mpsc;
use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_sha256, EVP_MAX_MD_SIZE, EVP_MD_CTX,
};

use crate::{DigestData, Generator};

pub struct SHA256 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; 32]>,
}

impl SHA256 {
    pub fn new() -> SHA256 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_sha256(&rx_input, &tx_result);
        });

        SHA256 {
            tx_input,
            rx_result,
        }
    }
}

impl Generator for SHA256 {
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

        DigestData::SHA256(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_sha256(
    rx_input: &mpsc::Receiver<Message>,
    tx_result: &mpsc::Sender<[u8; 32]>,
) {
    let mut ctx = Context::new();

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => ctx.update(&data),
            Ok(Message::Finish) => {
                let digest = ctx.result();
                tx_result.send(digest).unwrap();
                ctx.reset();
            }
            Err(_) => break,
        };
    }
}

struct Context {
    ctx: *mut EVP_MD_CTX,
}

impl Context {
    const LENGTH: usize = 32;

    pub fn new() -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null());
        let mut this = Self { ctx };
        this.reset();
        this
    }

    pub fn reset(&mut self) {
        let sha256 = unsafe { EVP_sha256() };
        assert!(!sha256.is_null());
        unsafe { EVP_DigestInit(self.ctx, sha256) };
    }

    pub fn update(&mut self, data: &[u8]) {
        unsafe {
            EVP_DigestUpdate(self.ctx, data.as_ptr().cast(), data.len());
        }
    }

    pub fn result(&mut self) -> [u8; Self::LENGTH] {
        let mut len = 0;
        let mut buffer = [0u8; EVP_MAX_MD_SIZE as usize];
        unsafe { EVP_DigestFinal(self.ctx, buffer.as_mut_ptr(), &mut len) };
        assert!(Self::LENGTH == len as usize);
        let mut digest = [0; Self::LENGTH];
        digest[..Self::LENGTH].copy_from_slice(&buffer[..Self::LENGTH]);
        self.reset();
        digest
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { EVP_MD_CTX_free(self.ctx) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn sha256_empty() {
        let sha256 = SHA256::new();

        let digest = sha256.result();

        assert_eq!(digest, DigestData::SHA256(fixtures::sha256::EMPTY));
    }

    #[test]
    fn sha256_data() {
        let sha256 = SHA256::new();

        let data = Arc::from([0; 0x4000]);
        sha256.append(data);
        let data = Arc::from([0; 0x0d]);
        sha256.append(data);

        let digest = sha256.result();

        assert_eq!(digest, DigestData::SHA256(fixtures::sha256::ZERO_400D));
    }

    #[test]
    fn sha256_multiple() {
        let sha256 = SHA256::new();

        let digest = sha256.result();

        assert_eq!(digest, DigestData::SHA256(fixtures::sha256::EMPTY));

        let data = Arc::from([0; 0x4000]);
        sha256.append(data);
        let data = Arc::from([0; 0x0d]);
        sha256.append(data);

        let digest = sha256.result();

        assert_eq!(digest, DigestData::SHA256(fixtures::sha256::ZERO_400D));

        let digest = sha256.result();

        assert_eq!(digest, DigestData::SHA256(fixtures::sha256::EMPTY));
    }
}
