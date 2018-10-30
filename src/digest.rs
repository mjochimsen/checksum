extern crate crypto;

use std::sync::Arc;

#[derive(Debug)]
pub enum Digest {
    MD5([u8; 16]),
    SHA256([u8; 32]),
    // SHA512([u8; 64]),
    // RMD160([u8; 20]),
}

pub trait Generator {
    fn append(&self, Arc<[u8]>);
    fn result(&self) -> Digest;
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

pub fn md5() -> Box<Generator> {
    let md5 = super::md5::MD5::new();
    Box::new(md5)
}

pub fn sha256() -> Box<Generator> {
    let sha256 = super::sha256::SHA256::new();
    Box::new(sha256)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_format() {
        let md5 = Digest::MD5([0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04,
                               0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e]);
        assert_eq!(format!("{}", md5), "d41d8cd98f00b204e9800998ecf8427e");
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
