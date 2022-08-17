use std::sync::mpsc;
use std::sync::Arc;

use openssl_sys::{
    EVP_DigestFinal, EVP_DigestInit, EVP_DigestUpdate, EVP_MD_CTX_free,
    EVP_MD_CTX_new, EVP_ripemd160, EVP_MAX_MD_SIZE, EVP_MD_CTX,
};

use crate::{DigestData, Generator};

pub struct RMD160 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; 20]>,
}

impl RMD160 {
    pub fn new() -> RMD160 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_rmd160(&rx_input, &tx_result);
        });

        RMD160 {
            tx_input,
            rx_result,
        }
    }
}

impl Generator for RMD160 {
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

        DigestData::RMD160(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_rmd160(
    rx_input: &mpsc::Receiver<Message>,
    tx_result: &mpsc::Sender<[u8; 20]>,
) {
    let mut ctx = Context::new();

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => ctx.update(&data),
            Ok(Message::Finish) => {
                let digest = ctx.result();
                tx_result.send(digest).unwrap();
            }
            Err(_) => break,
        }
    }
}

struct Context {
    ctx: *mut EVP_MD_CTX,
}

impl Context {
    const LENGTH: usize = 20;

    pub fn new() -> Self {
        let ctx = unsafe { EVP_MD_CTX_new() };
        assert!(!ctx.is_null());
        let mut this = Self { ctx };
        this.reset();
        this
    }

    pub fn reset(&mut self) {
        let ripemd160 = unsafe { EVP_ripemd160() };
        assert!(!ripemd160.is_null());
        unsafe { EVP_DigestInit(self.ctx, ripemd160) };
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
    use crate::test_digests;

    #[test]
    fn rmd160_empty() {
        let rmd160 = RMD160::new();

        let digest = rmd160.result();

        assert_eq!(digest, test_digests::rmd160::EMPTY);
    }

    #[test]
    fn rmd160_data() {
        let rmd160 = RMD160::new();

        let data = Arc::from([0; 0x4000]);
        rmd160.append(data);
        let data = Arc::from([0; 0x0d]);
        rmd160.append(data);

        let digest = rmd160.result();

        assert_eq!(digest, test_digests::rmd160::ZERO_400D);
    }

    #[test]
    fn rmd160_multiple() {
        let rmd160 = RMD160::new();

        let digest = rmd160.result();

        assert_eq!(digest, test_digests::rmd160::EMPTY);

        let data = Arc::from([0; 0x4000]);
        rmd160.append(data);
        let data = Arc::from([0; 0x0d]);
        rmd160.append(data);

        let digest = rmd160.result();

        assert_eq!(digest, test_digests::rmd160::ZERO_400D);

        let digest = rmd160.result();

        assert_eq!(digest, test_digests::rmd160::EMPTY);
    }
}
