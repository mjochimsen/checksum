use std::sync::mpsc;
use std::sync::Arc;

use crate::digest::{Digest, Generator};

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
            background_rmd160(rx_input, tx_result);
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

    fn result(&self) -> Digest {
        use std::time::Duration;

        self.tx_input
            .send(Message::Finish)
            .expect("unexpected error finishing digest");

        let timeout = Duration::new(5, 0);
        let result = self
            .rx_result
            .recv_timeout(timeout)
            .expect("unable to retrieve digest value");

        Digest::RMD160(result)
    }
}

enum Message {
    Append(Arc<[u8]>),
    Finish,
}

fn background_rmd160(
    rx_input: mpsc::Receiver<Message>,
    tx_result: mpsc::Sender<[u8; 20]>,
) {
    let mut ctx = super::super::openssl::RIPEMD160_CTX::new();

    loop {
        let msg = rx_input.recv();

        match msg {
            Ok(Message::Append(data)) => ctx.update(&*data),
            Ok(Message::Finish) => {
                let digest = ctx.result();

                tx_result.send(digest).unwrap();
                ctx.reset()
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_digests::*;
    use super::*;

    #[ignore]
    #[test]
    fn rmd160_empty() {
        let rmd160 = RMD160::new();

        let digest = rmd160.result();

        assert_eq!(digest, RMD160_ZERO_EMPTY);
    }

    #[ignore]
    #[test]
    fn rmd160_data() {
        let rmd160 = RMD160::new();

        let data = Arc::from([0; 0x4000]);
        rmd160.append(data);
        let data = Arc::from([0; 0x0d]);
        rmd160.append(data);

        let digest = rmd160.result();

        assert_eq!(digest, RMD160_ZERO_400D);
    }

    #[ignore]
    #[test]
    fn rmd160_multiple() {
        let rmd160 = RMD160::new();

        let digest = rmd160.result();

        assert_eq!(digest, RMD160_ZERO_EMPTY);

        let data = Arc::from([0; 0x4000]);
        rmd160.append(data);
        let data = Arc::from([0; 0x0d]);
        rmd160.append(data);

        let digest = rmd160.result();

        assert_eq!(digest, RMD160_ZERO_400D);

        let digest = rmd160.result();

        assert_eq!(digest, RMD160_ZERO_EMPTY);
    }
}
