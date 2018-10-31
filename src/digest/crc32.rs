use std::sync::mpsc;
use std::sync::Arc;

use digest::{Digest, Generator};

pub struct CRC32 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<u32>,
}

impl CRC32 {
    pub fn new() -> CRC32 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_crc32(rx_input, tx_result);
        });

        CRC32 { tx_input, rx_result }
    }
}

impl Generator for CRC32 {
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

        Digest::CRC32(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_crc32(rx_input: mpsc::Receiver<Message>,
                    tx_result: mpsc::Sender<u32>) {
    extern crate crc;
    use crc::{crc32, Hasher32};

    let mut crc32 = crc32::Digest::new(crc32::IEEE);

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => crc32.write(&*data),
            Ok(Message::Finish) => {
                let mut result = crc32.sum32();

                tx_result.send(result).unwrap();
                crc32.reset()
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
    fn crc32_empty() {
        let crc32 = CRC32::new();

        let digest = crc32.result();

        assert_eq!(digest, CRC32_ZERO_EMPTY);
    }

    #[test]
    fn crc32_data() {
        let crc32 = CRC32::new();

        let data = Arc::from([0; 0x4000]);
        crc32.append(data);
        let data = Arc::from([0; 0x0d]);
        crc32.append(data);

        let digest = crc32.result();

        assert_eq!(digest, CRC32_ZERO_400D);
    }

    #[test]
    fn crc32_multiple() {
        let crc32 = CRC32::new();

        let digest = crc32.result();

        assert_eq!(digest, CRC32_ZERO_EMPTY);

        let data = Arc::from([0; 0x4000]);
        crc32.append(data);
        let data = Arc::from([0; 0x0d]);
        crc32.append(data);

        let digest = crc32.result();

        assert_eq!(digest, CRC32_ZERO_400D);

        let digest = crc32.result();

        assert_eq!(digest, CRC32_ZERO_EMPTY);
    }
}

