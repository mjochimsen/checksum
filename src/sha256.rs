use std::sync::mpsc;
use std::sync::Arc;

use digest::{Digest, Generator};

pub struct SHA256 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; 32]>,
}

impl SHA256 {
    fn new() -> SHA256 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_sha256(rx_input, tx_result);
        });

        SHA256 { tx_input, rx_result }
    }
}

impl Generator for SHA256 {
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

        Digest::SHA256(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_sha256(rx_input: mpsc::Receiver<Message>,
                     tx_result: mpsc::Sender<[u8; 32]>) {
    extern crate crypto;
    use crypto::digest::Digest as DigestTrait;

    let mut sha256 = crypto::sha2::Sha256::new();

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => sha256.input(&*data),
            Ok(Message::Finish) => {
                let mut result = [0u8; 32];
                sha256.result(&mut result);

                tx_result.send(result).unwrap();
                sha256.reset()
            },
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ZERO_EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
    ];
    const ZERO_400D: [u8; 32] = [
        0x10, 0xbb, 0x1d, 0xbb, 0x5b, 0xcf, 0xb2, 0x03,
        0xd5, 0x83, 0x0e, 0x8a, 0x5b, 0xf4, 0xff, 0x49,
        0xba, 0x1d, 0x0b, 0xd9, 0x18, 0x69, 0x72, 0x50,
        0xf8, 0x94, 0x71, 0xab, 0x22, 0xf4, 0xa5, 0x99
    ];

    #[test]
    fn sha256_empty() {
        let sha256 = SHA256::new();

        let digest = sha256.result();

        match digest {
            Digest::SHA256(value) => assert_eq!(value, ZERO_EMPTY),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };
    }

    #[test]
    fn sha256_data() {
        let sha256 = SHA256::new();

        let data = Arc::from([0; 0x4000]);
        sha256.append(data);
        let data = Arc::from([0; 0x0d]);
        sha256.append(data);

        let digest = sha256.result();

        match digest {
            Digest::SHA256(value) => assert_eq!(value, ZERO_400D),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };
    }

    #[test]
    fn sha256_multiple() {
        let sha256 = SHA256::new();

        let digest = sha256.result();

        match digest {
            Digest::SHA256(value) => assert_eq!(value, ZERO_EMPTY),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };

        let data = Arc::from([0; 0x4000]);
        sha256.append(data);
        let data = Arc::from([0; 0x0d]);
        sha256.append(data);

        let digest = sha256.result();

        match digest {
            Digest::SHA256(value) => assert_eq!(value, ZERO_400D),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };

        let digest = sha256.result();

        match digest {
            Digest::SHA256(value) => assert_eq!(value, ZERO_EMPTY),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };
    }
}

