use std::sync::mpsc;
use std::sync::Arc;

use digest::{Digest, Generator};

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
            background_sha512(rx_input, tx_result);
        });

        SHA512 { tx_input, rx_result }
    }
}

impl Generator for SHA512 {
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

        Digest::SHA512(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_sha512(rx_input: mpsc::Receiver<Message>,
                     tx_result: mpsc::Sender<[u8; 64]>) {
    use crypto::digest::Digest as DigestTrait;

    let mut sha512 = crypto::sha2::Sha512::new();

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => sha512.input(&*data),
            Ok(Message::Finish) => {
                let mut result = [0u8; 64];
                sha512.result(&mut result);

                tx_result.send(result).unwrap();
                sha512.reset()
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
    fn sha512_empty() {
        let sha512 = SHA512::new();

        let digest = sha512.result();

        assert_eq!(digest, SHA512_ZERO_EMPTY);
    }

    #[test]
    fn sha512_data() {
        let sha512 = SHA512::new();

        let data = Arc::from([0; 0x4000]);
        sha512.append(data);
        let data = Arc::from([0; 0x0d]);
        sha512.append(data);

        let digest = sha512.result();

        assert_eq!(digest, SHA512_ZERO_400D);
    }

    #[test]
    fn sha512_multiple() {
        let sha512 = SHA512::new();

        let digest = sha512.result();

        assert_eq!(digest, SHA512_ZERO_EMPTY);

        let data = Arc::from([0; 0x4000]);
        sha512.append(data);
        let data = Arc::from([0; 0x0d]);
        sha512.append(data);

        let digest = sha512.result();

        assert_eq!(digest, SHA512_ZERO_400D);

        let digest = sha512.result();

        assert_eq!(digest, SHA512_ZERO_EMPTY);
    }
}

