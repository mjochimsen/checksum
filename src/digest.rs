extern crate crypto;

use std::thread::spawn;
use std::sync::mpsc::{channel, Receiver, Sender};

#[derive(Debug)]
pub enum Digest {
    MD5([u8; 16]),
    // SHA256([u8; 32]),
    // SHA512([u8; 64]),
    // RMD160([u8; 20]),
}

use std::fmt;

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let digest = match self {
            Digest::MD5(digest) => digest.iter(),
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
            Ok(Digest::MD5(value)) => assert_eq!(value, [
                0x96, 0xf6, 0x4e, 0x17, 0x9f, 0x77, 0x7e, 0x6e,
                0xda, 0x0c, 0xaa, 0x2d, 0x87, 0x93, 0x56, 0xc9
                ]),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_format() {
        let md5 = Digest::MD5([0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                               0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]);
        assert_eq!(format!("{}", md5), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
