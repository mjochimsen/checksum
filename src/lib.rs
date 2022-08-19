#![warn(clippy::all, clippy::pedantic)]

use std::fmt;
use std::sync::Arc;

mod digest;
pub use digest::Digest;

mod background;
pub use background::Background;

mod crc32;
mod md5;
mod rmd160;
mod sha256;
mod sha512;

pub use md5::MD5;

#[derive(Clone, Copy, Eq)]
pub enum DigestData {
    CRC32([u8; 4]),
    MD5([u8; 16]),
    SHA256([u8; 32]),
    SHA512([u8; 64]),
    RMD160([u8; 20]),
}

impl PartialEq for DigestData {
    fn eq(&self, other: &DigestData) -> bool {
        match (self, other) {
            (DigestData::CRC32(left), DigestData::CRC32(right)) => {
                left == right
            }
            (DigestData::MD5(left), DigestData::MD5(right)) => left == right,
            (DigestData::SHA256(left), DigestData::SHA256(right)) => {
                left == right
            }
            (DigestData::SHA512(left), DigestData::SHA512(right)) => {
                left == right
            }
            (DigestData::RMD160(left), DigestData::RMD160(right)) => {
                left == right
            }
            _ => false,
        }
    }
}

impl fmt::Debug for DigestData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DigestData::CRC32(digest) => {
                write!(f, "CRC32(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            DigestData::MD5(digest) => {
                write!(f, "MD5(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            DigestData::SHA256(digest) => {
                write!(f, "SHA256(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            DigestData::SHA512(digest) => {
                write!(f, "SHA512(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            DigestData::RMD160(digest) => {
                write!(f, "RMD160(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for DigestData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DigestData::CRC32(digest) => format_bytes(f, digest),
            DigestData::MD5(digest) => format_bytes(f, digest),
            DigestData::SHA256(digest) => format_bytes(f, digest),
            DigestData::SHA512(digest) => format_bytes(f, digest),
            DigestData::RMD160(digest) => format_bytes(f, digest),
        }
    }
}

fn format_bytes(f: &mut fmt::Formatter, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}

pub trait Generator {
    fn append(&self, data: Arc<[u8]>);
    fn result(&self) -> DigestData;
}

#[must_use]
pub fn crc32() -> Box<dyn Generator> {
    let crc32 = crc32::BackgroundCRC32::new();
    Box::new(crc32)
}

#[must_use]
pub fn md5() -> Box<dyn Generator> {
    let md5 = md5::BackgroundMD5::new();
    Box::new(md5)
}

#[must_use]
pub fn sha256() -> Box<dyn Generator> {
    let sha256 = sha256::BackgroundSHA256::new();
    Box::new(sha256)
}

#[must_use]
pub fn sha512() -> Box<dyn Generator> {
    let sha512 = sha512::BackgroundSHA512::new();
    Box::new(sha512)
}

#[must_use]
pub fn rmd160() -> Box<dyn Generator> {
    let rmd160 = rmd160::BackgroundRMD160::new();
    Box::new(rmd160)
}

#[cfg(test)]
#[path = "../tests/fixtures.rs"]
pub mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_data_eq() {
        const DIGESTS: [DigestData; 5] = [
            DigestData::CRC32(fixtures::crc32::EMPTY),
            DigestData::MD5(fixtures::md5::EMPTY),
            DigestData::SHA256(fixtures::sha256::EMPTY),
            DigestData::SHA512(fixtures::sha512::EMPTY),
            DigestData::RMD160(fixtures::rmd160::EMPTY),
        ];
        for (i, left) in DIGESTS.iter().enumerate() {
            for (j, right) in DIGESTS.iter().enumerate() {
                if i == j {
                    assert_eq!(left, right);
                } else {
                    assert_ne!(left, right);
                }
            }
        }

        assert_ne!(
            DigestData::CRC32(fixtures::crc32::EMPTY),
            DigestData::CRC32(fixtures::crc32::ZERO_400D)
        );
        assert_ne!(
            DigestData::MD5(fixtures::md5::EMPTY),
            DigestData::MD5(fixtures::md5::ZERO_400D)
        );
        assert_ne!(
            DigestData::SHA256(fixtures::sha256::EMPTY),
            DigestData::SHA256(fixtures::sha256::ZERO_400D)
        );
        assert_ne!(
            DigestData::SHA512(fixtures::sha512::EMPTY),
            DigestData::SHA512(fixtures::sha512::ZERO_400D)
        );
        assert_ne!(
            DigestData::RMD160(fixtures::rmd160::EMPTY),
            DigestData::RMD160(fixtures::rmd160::ZERO_400D)
        );
    }

    #[test]
    fn crc32_format() {
        assert_eq!(
            format!("{}", DigestData::CRC32(fixtures::crc32::ZERO_400D)),
            "26a348bb"
        );
    }

    #[test]
    fn md5_format() {
        assert_eq!(
            format!("{}", DigestData::MD5(fixtures::md5::EMPTY)),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    #[test]
    fn sha256_format() {
        assert_eq!(
            format!("{}", DigestData::SHA256(fixtures::sha256::EMPTY)),
            concat!(
                "e3b0c44298fc1c149afbf4c8996fb924",
                "27ae41e4649b934ca495991b7852b855"
            )
        );
    }

    #[test]
    fn sha512_format() {
        assert_eq!(
            format!("{}", DigestData::SHA512(fixtures::sha512::EMPTY)),
            concat!(
                "cf83e1357eefb8bdf1542850d66d8007",
                "d620e4050b5715dc83f4a921d36ce9ce",
                "47d0d13c5d85f2b0ff8318d2877eec2f",
                "63b931bd47417a81a538327af927da3e"
            )
        );
    }

    #[test]
    fn rmd160_format() {
        assert_eq!(
            format!("{}", DigestData::RMD160(fixtures::rmd160::EMPTY)),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
    }

    #[test]
    fn crc32_generator() {
        let crc32 = crc32();
        let digest = crc32.result();
        assert_eq!(digest, DigestData::CRC32(fixtures::crc32::EMPTY));
    }

    #[test]
    fn md5_generator() {
        let md5 = md5();
        let digest = md5.result();
        assert_eq!(digest, DigestData::MD5(fixtures::md5::EMPTY));
    }

    #[test]
    fn sha256_generator() {
        let sha256 = sha256();
        let digest = sha256.result();
        assert_eq!(digest, DigestData::SHA256(fixtures::sha256::EMPTY));
    }

    #[test]
    fn sha512_generator() {
        let sha512 = sha512();
        let digest = sha512.result();
        assert_eq!(digest, DigestData::SHA512(fixtures::sha512::EMPTY));
    }

    #[test]
    fn rmd160_generator() {
        let rmd160 = rmd160();
        let digest = rmd160.result();
        assert_eq!(digest, DigestData::RMD160(fixtures::rmd160::EMPTY));
    }
}
