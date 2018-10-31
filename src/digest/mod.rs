extern crate crypto;

mod md5;
mod sha256;

use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
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
    let md5 = md5::MD5::new();
    Box::new(md5)
}

pub fn sha256() -> Box<Generator> {
    let sha256 = sha256::SHA256::new();
    Box::new(sha256)
}

#[cfg(test)]
pub mod test_digests;

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_digests::*;

    #[test]
    fn md5_eq() {
        assert!(MD5_ZERO_EMPTY == MD5_ZERO_EMPTY);
        assert!(MD5_ZERO_EMPTY != MD5_ZERO_400D);
        assert!(MD5_ZERO_EMPTY != SHA256_ZERO_EMPTY);

        assert_eq!(MD5_ZERO_EMPTY, MD5_ZERO_EMPTY);
    }

    #[test]
    fn sha256_eq() {
        assert!(SHA256_ZERO_EMPTY == SHA256_ZERO_EMPTY);
        assert!(SHA256_ZERO_EMPTY != SHA256_ZERO_400D);
        assert!(SHA256_ZERO_EMPTY != MD5_ZERO_EMPTY);

        assert_eq!(SHA256_ZERO_EMPTY, SHA256_ZERO_EMPTY);
    }

    #[test]
    fn md5_format() {
        assert_eq!(format!("{}", MD5_ZERO_EMPTY),
                   "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn sha256_format() {
        assert_eq!(format!("{}", SHA256_ZERO_EMPTY),
                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }

    #[test]
    fn md5_generator() {
        let md5 = md5();
        let digest = md5.result();
        assert_eq!(digest, MD5_ZERO_EMPTY);
    }

    #[test]
    fn sha256_generator() {
        let sha256 = sha256();
        let digest = sha256.result();
        assert_eq!(digest, SHA256_ZERO_EMPTY);
    }
}
