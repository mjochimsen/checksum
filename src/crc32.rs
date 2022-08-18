use std::sync::mpsc;
use std::sync::Arc;

use crate::{DigestData, Generator};
use libz_sys::crc32;

pub struct CRC32 {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; 4]>,
}

impl CRC32 {
    pub fn new() -> CRC32 {
        use std::thread;

        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        thread::spawn(move || {
            background_crc32(&rx_input, &tx_result);
        });

        CRC32 {
            tx_input,
            rx_result,
        }
    }
}

impl Generator for CRC32 {
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

        DigestData::CRC32(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_crc32(
    rx_input: &mpsc::Receiver<Message>,
    tx_result: &mpsc::Sender<[u8; 4]>,
) {
    let mut crc: u32 = 0;

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => {
                let len = data
                    .len()
                    .try_into()
                    .expect("data block is too large for CRC32 processing");
                let crc_sys =
                    unsafe { crc32(crc.into(), data.as_ptr(), len) };
                crc = crc_sys
                    .try_into()
                    .expect("unexpected CRC32 value > u32::MAX");
            }
            Ok(Message::Finish) => {
                tx_result.send(crc.to_be_bytes()).unwrap();
                crc = 0;
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn zlib_crc32() {
        let data = [0; 32];
        let crc = unsafe {
            crc32(0, data.as_ptr(), data.len().try_into().unwrap())
        };
        assert_eq!(crc, 0x190a_55ad);
    }

    #[test]
    fn crc32_empty() {
        let crc32 = CRC32::new();

        let digest = crc32.result();

        assert_eq!(digest, DigestData::CRC32(fixtures::crc32::EMPTY));
    }

    #[test]
    fn crc32_data() {
        let crc32 = CRC32::new();

        let data = Arc::from([0; 0x4000]);
        crc32.append(data);
        let data = Arc::from([0; 0x0d]);
        crc32.append(data);

        let digest = crc32.result();

        assert_eq!(digest, DigestData::CRC32(fixtures::crc32::ZERO_400D));
    }

    #[test]
    fn crc32_multiple() {
        let crc32 = CRC32::new();

        let digest = crc32.result();

        assert_eq!(digest, DigestData::CRC32(fixtures::crc32::EMPTY));

        let data = Arc::from([0; 0x4000]);
        crc32.append(data);
        let data = Arc::from([0; 0x0d]);
        crc32.append(data);

        let digest = crc32.result();

        assert_eq!(digest, DigestData::CRC32(fixtures::crc32::ZERO_400D));

        let digest = crc32.result();

        assert_eq!(digest, DigestData::CRC32(fixtures::crc32::EMPTY));
    }
}
