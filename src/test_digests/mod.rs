use super::Digest;

pub const ZERO_0: [u8; 0] = *include_bytes!("zero-0");
pub const ZERO_400D: [u8; 0x400D] = *include_bytes!("zero-400d");
pub const ZERO_11171: [u8; 0x11171] = *include_bytes!("zero-11171");
pub const RANDOM_11171: [u8; 0x11171] = *include_bytes!("random-11171");

pub const CRC32_ZERO_0: Digest = Digest::CRC32(0x00000000);
pub const CRC32_ZERO_400D: Digest = Digest::CRC32(0x26a348bb);
pub const CRC32_ZERO_11171: Digest = Digest::CRC32(0x5dc1d8ba);
pub const CRC32_RANDOM_11171: Digest = Digest::CRC32(0xff70a8ee);

pub const MD5_ZERO_0: Digest = Digest::MD5(*include_bytes!("zero-0.md5"));
pub const MD5_ZERO_400D: Digest =
    Digest::MD5(*include_bytes!("zero-400d.md5"));
pub const MD5_ZERO_11171: Digest =
    Digest::MD5(*include_bytes!("zero-11171.md5"));
pub const MD5_RANDOM_11171: Digest =
    Digest::MD5(*include_bytes!("random-11171.md5"));

pub const SHA256_ZERO_0: Digest =
    Digest::SHA256(*include_bytes!("zero-0.sha256"));
pub const SHA256_ZERO_400D: Digest =
    Digest::SHA256(*include_bytes!("zero-400d.sha256"));
pub const SHA256_ZERO_11171: Digest =
    Digest::SHA256(*include_bytes!("zero-11171.sha256"));
pub const SHA256_RANDOM_11171: Digest =
    Digest::SHA256(*include_bytes!("random-11171.sha256"));

pub const SHA512_ZERO_0: Digest =
    Digest::SHA512(*include_bytes!("zero-0.sha512"));
pub const SHA512_ZERO_400D: Digest =
    Digest::SHA512(*include_bytes!("zero-400d.sha512"));
pub const SHA512_ZERO_11171: Digest =
    Digest::SHA512(*include_bytes!("zero-11171.sha512"));
pub const SHA512_RANDOM_11171: Digest =
    Digest::SHA512(*include_bytes!("random-11171.sha512"));

pub const RMD160_ZERO_0: Digest =
    Digest::RMD160(*include_bytes!("zero-0.rmd160"));
pub const RMD160_ZERO_400D: Digest =
    Digest::RMD160(*include_bytes!("zero-400d.rmd160"));
pub const RMD160_ZERO_11171: Digest =
    Digest::RMD160(*include_bytes!("zero-11171.rmd160"));
pub const RMD160_RANDOM_11171: Digest =
    Digest::RMD160(*include_bytes!("random-11171.rmd160"));
