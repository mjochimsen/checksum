use std::sync::mpsc;
use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_sha512, EVP_MAX_MD_SIZE, EVP_MD_CTX,
};

use crate::{DigestData, Generator};

pub struct SHA512 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; 64]>,
}

impl SHA512 {
    pub fn new() -> SHA512 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_sha512(&rx_input, &tx_result);
        });

        SHA512 {
            tx_input,
            rx_result,
        }
    }
}

impl Generator for SHA512 {
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

        DigestData::SHA512(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_sha512(
    rx_input: &mpsc::Receiver<Message>,
    tx_result: &mpsc::Sender<[u8; 64]>,
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
        }
    }
}

struct Context {
    ctx: *mut EVP_MD_CTX,
}

impl Context {
    const LENGTH: usize = 64;

    pub fn new() -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null());
        let mut this = Self { ctx };
        this.reset();
        this
    }

    pub fn reset(&mut self) {
        let sha512 = unsafe { EVP_sha512() };
        assert!(!sha512.is_null());
        unsafe { EVP_DigestInit(self.ctx, sha512) };
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
    fn sha512_empty() {
        let sha512 = SHA512::new();

        let digest = sha512.result();

        assert_eq!(digest, DigestData::SHA512(fixtures::sha512::EMPTY));
    }

    #[test]
    fn sha512_data() {
        let sha512 = SHA512::new();

        let data = Arc::from([0; 0x4000]);
        sha512.append(data);
        let data = Arc::from([0; 0x0d]);
        sha512.append(data);

        let digest = sha512.result();

        assert_eq!(digest, DigestData::SHA512(fixtures::sha512::ZERO_400D));
    }

    #[test]
    fn sha512_multiple() {
        let sha512 = SHA512::new();

        let digest = sha512.result();

        assert_eq!(digest, DigestData::SHA512(fixtures::sha512::EMPTY));

        let data = Arc::from([0; 0x4000]);
        sha512.append(data);
        let data = Arc::from([0; 0x0d]);
        sha512.append(data);

        let digest = sha512.result();

        assert_eq!(digest, DigestData::SHA512(fixtures::sha512::ZERO_400D));

        let digest = sha512.result();

        assert_eq!(digest, DigestData::SHA512(fixtures::sha512::EMPTY));
    }
}
