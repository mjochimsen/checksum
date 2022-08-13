use super::DigestData;

pub const ZERO_0: [u8; 0] = *include_bytes!("zero-0");
pub const ZERO_400D: [u8; 0x400D] = *include_bytes!("zero-400d");
pub const ZERO_11171: [u8; 0x11171] = *include_bytes!("zero-11171");
pub const RANDOM_11171: [u8; 0x11171] = *include_bytes!("random-11171");

pub const CRC32_ZERO_0: DigestData = DigestData::CRC32(0x00000000);
pub const CRC32_ZERO_400D: DigestData = DigestData::CRC32(0x26a348bb);
pub const CRC32_ZERO_11171: DigestData = DigestData::CRC32(0x5dc1d8ba);
pub const CRC32_RANDOM_11171: DigestData = DigestData::CRC32(0xff70a8ee);

pub const MD5_ZERO_0: DigestData =
    DigestData::MD5(*include_bytes!("zero-0.md5"));
pub const MD5_ZERO_400D: DigestData =
    DigestData::MD5(*include_bytes!("zero-400d.md5"));
pub const MD5_ZERO_11171: DigestData =
    DigestData::MD5(*include_bytes!("zero-11171.md5"));
pub const MD5_RANDOM_11171: DigestData =
    DigestData::MD5(*include_bytes!("random-11171.md5"));

pub const SHA256_ZERO_0: DigestData =
    DigestData::SHA256(*include_bytes!("zero-0.sha256"));
pub const SHA256_ZERO_400D: DigestData =
    DigestData::SHA256(*include_bytes!("zero-400d.sha256"));
pub const SHA256_ZERO_11171: DigestData =
    DigestData::SHA256(*include_bytes!("zero-11171.sha256"));
pub const SHA256_RANDOM_11171: DigestData =
    DigestData::SHA256(*include_bytes!("random-11171.sha256"));

pub const SHA512_ZERO_0: DigestData =
    DigestData::SHA512(*include_bytes!("zero-0.sha512"));
pub const SHA512_ZERO_400D: DigestData =
    DigestData::SHA512(*include_bytes!("zero-400d.sha512"));
pub const SHA512_ZERO_11171: DigestData =
    DigestData::SHA512(*include_bytes!("zero-11171.sha512"));
pub const SHA512_RANDOM_11171: DigestData =
    DigestData::SHA512(*include_bytes!("random-11171.sha512"));

pub const RMD160_ZERO_0: DigestData =
    DigestData::RMD160(*include_bytes!("zero-0.rmd160"));
pub const RMD160_ZERO_400D: DigestData =
    DigestData::RMD160(*include_bytes!("zero-400d.rmd160"));
pub const RMD160_ZERO_11171: DigestData =
    DigestData::RMD160(*include_bytes!("zero-11171.rmd160"));
pub const RMD160_RANDOM_11171: DigestData =
    DigestData::RMD160(*include_bytes!("random-11171.rmd160"));
