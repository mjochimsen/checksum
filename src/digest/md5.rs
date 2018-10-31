use std::sync::mpsc;
use std::sync::Arc;

use digest::{Digest, Generator};

pub struct MD5 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; 16]>,
}

impl MD5 {
    pub fn new() -> MD5 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_md5(rx_input, tx_result);
        });

        MD5 { tx_input, rx_result }
    }
}

impl Generator for MD5 {
    fn append(&self, data: Arc<[u8]>) {
        self.tx_input.send(Message::Append(data))
            .expect("unexpected error appending to digest");
    }

    fn result(&self) -> Digest {
        use std::time::Duration;

        self.tx_input.send(Message::Finish)
            .expect("unexpected error finishing digest");

        let timeout = Duration::new(5, 0);
        let result = self.rx_result.recv_timeout(timeout)
            .expect("unable to retrieve digest value");

        Digest::MD5(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_md5(rx_input: mpsc::Receiver<Message>,
                  tx_result: mpsc::Sender<[u8; 16]>) {
    extern crate crypto;
    use crypto::digest::Digest as DigestTrait;

    let mut md5 = crypto::md5::Md5::new();

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => md5.input(&*data),
            Ok(Message::Finish) => {
                let mut result = [0u8; 16];
                md5.result(&mut result);

                tx_result.send(result).unwrap();
                md5.reset()
            },
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::test_digests::*;

    #[test]
    fn md5_empty() {
        let md5 = MD5::new();

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_EMPTY);
    }

    #[test]
    fn md5_data() {
        let md5 = MD5::new();

        let data = Arc::from([0; 0x4000]);
        md5.append(data);
        let data = Arc::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_400D);
    }

    #[test]
    fn md5_multiple() {
        let md5 = MD5::new();

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_EMPTY);

        let data = Arc::from([0; 0x4000]);
        md5.append(data);
        let data = Arc::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_400D);

        let digest = md5.result();

        assert_eq!(digest, MD5_ZERO_EMPTY);
    }
}

