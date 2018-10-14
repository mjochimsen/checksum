extern crate crypto;

use std::sync::mpsc;

pub struct Block {
    pub size: usize,
    pub data: Box<[u8; 0x4000]>,
}

#[derive(Debug)]
pub enum Digest {
    MD5([u8; 16]),
    // SHA256([u8; 32]),
    // SHA512([u8; 64]),
    // RMD160([u8; 20]),
}

pub fn md5(rx: mpsc::Receiver<Block>) -> Digest {
    let mut digest = crypto::md5::Md5::new();
    let mut result = [0u8; 16];

    {
        use crypto::digest::Digest;
        loop {
            let block = rx.recv().unwrap();

            if block.size == 0 {
                break;
            }

            digest.input(&block.data[0..block.size]);
        }

        digest.result(&mut result);
    }

    Digest::MD5(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::spawn;

    const ZERO_DATA: [u8; 0x4000] = [0; 0x4000];

    #[test]
    fn md5_empty() {
        let (tx, rx) = mpsc::channel::<Block>();
        let (tx_digest, rx_digest) = mpsc::channel::<Digest>();

        spawn(move || {
            let digest = md5(rx);
            tx_digest.send(digest).unwrap();
        });

        let block = Block { size: 0, data: Box::new(ZERO_DATA) };
        tx.send(block).unwrap();

        let digest = rx_digest.recv();
        match digest {
            Ok(Digest::MD5(value)) =>
                assert_eq!(value, [
                    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
                ]),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_multiple_sends() {
        let (tx, rx) = mpsc::channel::<Block>();
        let (tx_digest, rx_digest) = mpsc::channel::<Digest>();

        spawn(move || {
            let digest = md5(rx);
            tx_digest.send(digest).unwrap();
        });

        let block = Block { size: 0x4000, data: Box::new(ZERO_DATA) };
        tx.send(block).unwrap();
        let block = Block { size: 0x0d, data: Box::new(ZERO_DATA) };
        tx.send(block).unwrap();
        let block = Block { size: 0, data: Box::new(ZERO_DATA) };
        tx.send(block).unwrap();

        let digest = rx_digest.recv();
        match digest {
            Ok(Digest::MD5(value)) => assert_eq!(value, [
                0x96, 0xf6, 0x4e, 0x17, 0x9f, 0x77, 0x7e, 0x6e,
                0xda, 0x0c, 0xaa, 0x2d, 0x87, 0x93, 0x56, 0xc9
                ]),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }
}
