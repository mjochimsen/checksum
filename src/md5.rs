use std::sync::mpsc;

use digest::Digest;

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

    pub fn append(&self, data: Box<[u8]>) {
        self.tx_input.send(Message::Append(data))
            .expect("unexpected error appending to digest");
    }

    pub fn result(&self) -> Digest {
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
    Append(Box<[u8]>),
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

    #[test]
    fn md5_empty() {
        let md5 = MD5::new();

        let digest = md5.result();

        match digest {
            Digest::MD5(value) =>
                assert_eq!(value, [
                    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
                ]),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };
    }

    #[test]
    fn md5_data() {
        let md5 = MD5::new();

        let data = Box::from([0; 0x4000]);
        md5.append(data);
        let data = Box::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        match digest {
            Digest::MD5(value) =>
                assert_eq!(value, [
                    0x96, 0xf6, 0x4e, 0x17, 0x9f, 0x77, 0x7e, 0x6e,
                    0xda, 0x0c, 0xaa, 0x2d, 0x87, 0x93, 0x56, 0xc9
                ]),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };
    }

    #[test]
    fn md5_multiple() {
        let md5 = MD5::new();

        let digest = md5.result();

        match digest {
            Digest::MD5(value) =>
                assert_eq!(value, [
                    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
                ]),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };

        let data = Box::from([0; 0x4000]);
        md5.append(data);
        let data = Box::from([0; 0x0d]);
        md5.append(data);

        let digest = md5.result();

        match digest {
            Digest::MD5(value) =>
                assert_eq!(value, [
                    0x96, 0xf6, 0x4e, 0x17, 0x9f, 0x77, 0x7e, 0x6e,
                    0xda, 0x0c, 0xaa, 0x2d, 0x87, 0x93, 0x56, 0xc9
                ]),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };

        let digest = md5.result();

        match digest {
            Digest::MD5(value) =>
                assert_eq!(value, [
                    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
                ]),
            digest => assert!(false, "unexpected digest: {:?}", digest),
        };

    }
}

