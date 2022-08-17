pub const EMPTY: [u8; 0] = *include_bytes!("empty");
pub const ZERO_400D: [u8; 0x400D] = *include_bytes!("zero-400d");
pub const RANDOM_11171: [u8; 0x11171] = *include_bytes!("random-11171");

pub mod crc32 {
    use crate::DigestData;

    pub const EMPTY: DigestData = DigestData::CRC32(0x00000000);
    pub const ZERO_400D: DigestData = DigestData::CRC32(0x26a348bb);
    pub const RANDOM_11171: DigestData = DigestData::CRC32(0xff70a8ee);
}

pub mod md5 {
    use crate::DigestData;

    pub const EMPTY: DigestData =
        DigestData::MD5(*include_bytes!("empty.md5"));
    pub const ZERO_400D: DigestData =
        DigestData::MD5(*include_bytes!("zero-400d.md5"));
    pub const RANDOM_11171: DigestData =
        DigestData::MD5(*include_bytes!("random-11171.md5"));
}

pub mod sha256 {
    use crate::DigestData;

    pub const EMPTY: DigestData =
        DigestData::SHA256(*include_bytes!("empty.sha256"));
    pub const ZERO_400D: DigestData =
        DigestData::SHA256(*include_bytes!("zero-400d.sha256"));
    pub const RANDOM_11171: DigestData =
        DigestData::SHA256(*include_bytes!("random-11171.sha256"));
}

pub mod sha512 {
    use crate::DigestData;

    pub const EMPTY: DigestData =
        DigestData::SHA512(*include_bytes!("empty.sha512"));
    pub const ZERO_400D: DigestData =
        DigestData::SHA512(*include_bytes!("zero-400d.sha512"));
    pub const RANDOM_11171: DigestData =
        DigestData::SHA512(*include_bytes!("random-11171.sha512"));
}

pub mod rmd160 {
    use crate::DigestData;

    pub const EMPTY: DigestData =
        DigestData::RMD160(*include_bytes!("empty.rmd160"));
    pub const ZERO_400D: DigestData =
        DigestData::RMD160(*include_bytes!("zero-400d.rmd160"));
    pub const RANDOM_11171: DigestData =
        DigestData::RMD160(*include_bytes!("random-11171.rmd160"));
}
