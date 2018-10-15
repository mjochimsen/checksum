extern crate crypto;

use std::thread::spawn;
use std::sync::mpsc::{channel, Receiver, Sender};

#[derive(Debug)]
pub enum Digest {
    MD5([u8; 16]),
    SHA256([u8; 32]),
    // SHA512([u8; 64]),
    // RMD160([u8; 20]),
}

use std::fmt;

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let digest = match self {
            Digest::MD5(digest) => digest.iter(),
            Digest::SHA256(digest) => digest.iter(),
        };
        let digest = digest.fold("".to_string(), |acc, byte| {
            format!("{}{:02x}", acc, byte)
        });
        write!(f, "{}", digest)
    }
}

pub fn background_md5() -> (Sender<Box<[u8]>>, Receiver<Digest>) {
    let (tx_data, rx_data) = channel();
    let (tx_digest, rx_digest) = channel();

    spawn(move || {
        let digest = md5(rx_data);
        tx_digest.send(digest).unwrap();
    });

    (tx_data, rx_digest)
}

fn md5(rx: Receiver<Box<[u8]>>) -> Digest {
    let mut digest = crypto::md5::Md5::new();
    let mut result = [0u8; 16];

    {
        use crypto::digest::Digest;

        loop {
            let data = rx.recv().unwrap();

            if data.len() == 0 {
                break;
            }

            digest.input(&*data);
        }

        digest.result(&mut result);
    }

    Digest::MD5(result)
}

pub fn background_sha256() -> (Sender<Box<[u8]>>, Receiver<Digest>) {
    let (tx_data, rx_data) = channel();
    let (tx_digest, rx_digest) = channel();

    spawn(move || {
        let digest = sha256(rx_data);
        tx_digest.send(digest).unwrap();
    });

    (tx_data, rx_digest)
}

fn sha256(rx: Receiver<Box<[u8]>>) -> Digest {
    let mut digest = crypto::sha2::Sha256::new();
    let mut result = [0u8; 32];

    {
        use crypto::digest::Digest;

        loop {
            let data = rx.recv().unwrap();

            if data.len() == 0 {
                break;
            }

            digest.input(&*data);
        }

        digest.result(&mut result);
    }

    Digest::SHA256(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn background_md5_empty() {
        let (tx, rx) = background_md5();

        tx.send(Box::new([])).unwrap();

        let digest = rx.recv();
        match digest {
            Ok(Digest::MD5(value)) =>
                assert_eq!(value, [
                    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                    0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn background_md5_multiple_sends() {
        let (tx, rx) = background_md5();

        let data = Box::from([0; 0x4000]);
        tx.send(data).unwrap();
        let data = Box::from([0; 0x0d]);
        tx.send(data).unwrap();
        let data = Box::new([]);
        tx.send(data).unwrap();

        let digest = rx.recv();
        match digest {
            Ok(Digest::MD5(value)) =>
                assert_eq!(value, [
                    0x96, 0xf6, 0x4e, 0x17, 0x9f, 0x77, 0x7e, 0x6e,
                    0xda, 0x0c, 0xaa, 0x2d, 0x87, 0x93, 0x56, 0xc9
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_format() {
        let md5 = Digest::MD5([0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                               0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]);
        assert_eq!(format!("{}", md5), "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn background_sha256_empty() {
        let (tx, rx) = background_sha256();

        tx.send(Box::new([])).unwrap();

        let digest = rx.recv();
        match digest {
            Ok(Digest::SHA256(value)) =>
                assert_eq!(value, [
                    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
                    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
                    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn background_sha256_multiple_sends() {
        let (tx, rx) = background_sha256();

        let data = Box::from([0; 0x4000]);
        tx.send(data).unwrap();
        let data = Box::from([0; 0x0d]);
        tx.send(data).unwrap();
        let data = Box::new([]);
        tx.send(data).unwrap();

        let digest = rx.recv();
        match digest {
            Ok(Digest::SHA256(value)) =>
                assert_eq!(value, [
                    0x10, 0xbb, 0x1d, 0xbb, 0x5b, 0xcf, 0xb2, 0x03,
                    0xd5, 0x83, 0x0e, 0x8a, 0x5b, 0xf4, 0xff, 0x49,
                    0xba, 0x1d, 0x0b, 0xd9, 0x18, 0x69, 0x72, 0x50,
                    0xf8, 0x94, 0x71, 0xab, 0x22, 0xf4, 0xa5, 0x99
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn sha256_format() {
        let sha256 = Digest::SHA256([
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        ]);
        assert_eq!(format!("{}", sha256), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
