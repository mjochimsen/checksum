mod crc32;
mod md5;
mod sha256;
mod sha512;
mod rmd160;

use std::sync::Arc;

pub enum Digest {
    CRC32(u32),
    MD5([u8; 16]),
    SHA256([u8; 32]),
    SHA512([u8; 64]),
    RMD160([u8; 20]),
}

impl PartialEq for Digest {
    fn eq(&self, other: &Digest) -> bool {
        match (self, other) {
            (Digest::CRC32(left), Digest::CRC32(right)) =>
                left == right,
            (Digest::MD5(left), Digest::MD5(right)) =>
                left == right,
            (Digest::SHA256(left), Digest::SHA256(right)) =>
                left == right,
            (Digest::SHA512(left), Digest::SHA512(right)) =>
                left[..31] == right[..31] &&
                left[32..] == right[32..],
            (Digest::RMD160(left), Digest::RMD160(right)) =>
                left == right,
            _ => false,
        }
    }
}

impl Eq for Digest {}

use std::fmt;

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Digest::CRC32(digest) => {
                write!(f, "CRC32(")?;
                format_u32(f, *digest)?;
                write!(f, ")")
            }
            Digest::MD5(digest) => {
                write!(f, "MD5(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            Digest::SHA256(digest) => {
                write!(f, "SHA256(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            Digest::SHA512(digest) => {
                write!(f, "SHA512(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
            Digest::RMD160(digest) => {
                write!(f, "RMD160(")?;
                format_bytes(f, digest)?;
                write!(f, ")")
            }
        }
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Digest::CRC32(digest) => format_u32(f, *digest),
            Digest::MD5(digest) => format_bytes(f, digest),
            Digest::SHA256(digest) => format_bytes(f, digest),
            Digest::SHA512(digest) => format_bytes(f, digest),
            Digest::RMD160(digest) => format_bytes(f, digest),
        }
    }
}

fn format_u32(f: &mut fmt::Formatter, value: u32) -> fmt::Result {
    write!(f, "{:08x}", value)
}

fn format_bytes(f: &mut fmt::Formatter, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{:02x}", byte)?;
    }
    Ok(())
}

pub trait Generator {
    fn append(&self, Arc<[u8]>);
    fn result(&self) -> Digest;
}

pub fn crc32() -> Box<Generator> {
    let crc32 = crc32::CRC32::new();
    Box::new(crc32)
}

pub fn md5() -> Box<Generator> {
    let md5 = md5::MD5::new();
    Box::new(md5)
}

pub fn sha256() -> Box<Generator> {
    let sha256 = sha256::SHA256::new();
    Box::new(sha256)
}

pub fn sha512() -> Box<Generator> {
    let sha512 = sha512::SHA512::new();
    Box::new(sha512)
}

pub fn rmd160() -> Box<Generator> {
    let rmd160 = rmd160::RMD160::new();
    Box::new(rmd160)
}

#[cfg(test)]
pub mod test_digests;

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_digests::*;

    #[test]
    fn crc32_eq() {
        assert!(CRC32_ZERO_EMPTY == CRC32_ZERO_EMPTY);
        assert!(CRC32_ZERO_EMPTY != CRC32_ZERO_400D);
        assert!(CRC32_ZERO_EMPTY != MD5_ZERO_EMPTY);
        assert!(CRC32_ZERO_EMPTY != SHA256_ZERO_EMPTY);
        assert!(CRC32_ZERO_EMPTY != SHA512_ZERO_EMPTY);
        assert!(CRC32_ZERO_EMPTY != RMD160_ZERO_EMPTY);

        assert_eq!(CRC32_ZERO_EMPTY, CRC32_ZERO_EMPTY);
    }

    #[test]
    fn md5_eq() {
        assert!(MD5_ZERO_EMPTY == MD5_ZERO_EMPTY);
        assert!(MD5_ZERO_EMPTY != MD5_ZERO_400D);
        assert!(MD5_ZERO_EMPTY != CRC32_ZERO_EMPTY);
        assert!(MD5_ZERO_EMPTY != SHA256_ZERO_EMPTY);
        assert!(MD5_ZERO_EMPTY != SHA512_ZERO_EMPTY);
        assert!(MD5_ZERO_EMPTY != RMD160_ZERO_EMPTY);

        assert_eq!(MD5_ZERO_EMPTY, MD5_ZERO_EMPTY);
    }

    #[test]
    fn sha256_eq() {
        assert!(SHA256_ZERO_EMPTY == SHA256_ZERO_EMPTY);
        assert!(SHA256_ZERO_EMPTY != SHA256_ZERO_400D);
        assert!(SHA256_ZERO_EMPTY != CRC32_ZERO_EMPTY);
        assert!(SHA256_ZERO_EMPTY != MD5_ZERO_EMPTY);
        assert!(SHA256_ZERO_EMPTY != SHA512_ZERO_EMPTY);
        assert!(SHA256_ZERO_EMPTY != RMD160_ZERO_EMPTY);

        assert_eq!(SHA256_ZERO_EMPTY, SHA256_ZERO_EMPTY);
    }

    #[test]
    fn sha512_eq() {
        assert!(SHA512_ZERO_EMPTY == SHA512_ZERO_EMPTY);
        assert!(SHA512_ZERO_EMPTY != SHA512_ZERO_400D);
        assert!(SHA512_ZERO_EMPTY != CRC32_ZERO_EMPTY);
        assert!(SHA512_ZERO_EMPTY != MD5_ZERO_EMPTY);
        assert!(SHA512_ZERO_EMPTY != SHA256_ZERO_EMPTY);
        assert!(SHA512_ZERO_EMPTY != RMD160_ZERO_EMPTY);

        assert_eq!(SHA512_ZERO_EMPTY, SHA512_ZERO_EMPTY);
    }

    #[test]
    fn rmd160_eq() {
        assert!(RMD160_ZERO_EMPTY == RMD160_ZERO_EMPTY);
        assert!(RMD160_ZERO_EMPTY != RMD160_ZERO_400D);
        assert!(RMD160_ZERO_EMPTY != CRC32_ZERO_EMPTY);
        assert!(RMD160_ZERO_EMPTY != MD5_ZERO_EMPTY);
        assert!(RMD160_ZERO_EMPTY != SHA256_ZERO_EMPTY);
        assert!(RMD160_ZERO_EMPTY != SHA512_ZERO_EMPTY);

        assert_eq!(RMD160_ZERO_EMPTY, RMD160_ZERO_EMPTY);
    }

    #[test]
    fn crc32_format() {
        assert_eq!(format!("{}", CRC32_ZERO_EMPTY), "00000000");
        assert_eq!(format!("{}", CRC32_ZERO_400D), "26a348bb");
    }

    #[test]
    fn md5_format() {
        assert_eq!(format!("{}", MD5_ZERO_EMPTY),
                   "d41d8cd98f00b204e9800998ecf8427e");
    }

    #[test]
    fn sha256_format() {
        assert_eq!(format!("{}", SHA256_ZERO_EMPTY),
                   concat!("e3b0c44298fc1c149afbf4c8996fb924",
                           "27ae41e4649b934ca495991b7852b855"));
    }

    #[test]
    fn sha512_format() {
        assert_eq!(format!("{}", SHA512_ZERO_EMPTY),
                   concat!("cf83e1357eefb8bdf1542850d66d8007",
                           "d620e4050b5715dc83f4a921d36ce9ce",
                           "47d0d13c5d85f2b0ff8318d2877eec2f",
                           "63b931bd47417a81a538327af927da3e"));
    }

    #[test]
    fn rmd160_format() {
        assert_eq!(format!("{}", RMD160_ZERO_EMPTY),
                   "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    }

    #[test]
    fn crc32_generator() {
        let crc32 = crc32();
        let digest = crc32.result();
        assert_eq!(digest, CRC32_ZERO_EMPTY);
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

    #[test]
    fn sha512_generator() {
        let sha512 = sha512();
        let digest = sha512.result();
        assert_eq!(digest, SHA512_ZERO_EMPTY);
    }

    #[test]
    fn rmd160_generator() {
        let rmd160 = rmd160();
        let digest = rmd160.result();
        assert_eq!(digest, RMD160_ZERO_EMPTY);
    }
}
