pub const EMPTY: [u8; 0] = *include_bytes!("empty");
pub const ZERO_400D: [u8; 0x400D] = *include_bytes!("zero-400d");
pub const RANDOM_11171: [u8; 0x11171] = *include_bytes!("random-11171");

pub mod crc32 {
    pub const EMPTY: [u8; 4] = *include_bytes!("empty.crc32");
    pub const ZERO_400D: [u8; 4] = *include_bytes!("zero-400d.crc32");
    pub const RANDOM_11171: [u8; 4] = *include_bytes!("random-11171.crc32");
}

pub mod md5 {
    pub const EMPTY: [u8; 16] = *include_bytes!("empty.md5");
    pub const ZERO_400D: [u8; 16] = *include_bytes!("zero-400d.md5");
    pub const RANDOM_11171: [u8; 16] = *include_bytes!("random-11171.md5");
}

pub mod sha256 {
    pub const EMPTY: [u8; 32] = *include_bytes!("empty.sha256");
    pub const ZERO_400D: [u8; 32] = *include_bytes!("zero-400d.sha256");
    pub const RANDOM_11171: [u8; 32] = *include_bytes!("random-11171.sha256");
}

pub mod sha512 {
    pub const EMPTY: [u8; 64] = *include_bytes!("empty.sha512");
    pub const ZERO_400D: [u8; 64] = *include_bytes!("zero-400d.sha512");
    pub const RANDOM_11171: [u8; 64] = *include_bytes!("random-11171.sha512");
}

pub mod rmd160 {
    pub const EMPTY: [u8; 20] = *include_bytes!("empty.rmd160");
    pub const ZERO_400D: [u8; 20] = *include_bytes!("zero-400d.rmd160");
    pub const RANDOM_11171: [u8; 20] = *include_bytes!("random-11171.rmd160");
}

pub mod count {
    pub const EMPTY: [u8; 1] = [0x00];
    pub const ZERO_400D: [u8; 1] = [0x0d];
    pub const RANDOM_11171: [u8; 1] = [0x71];
}

pub mod xor {
    pub const EMPTY: [u8; 1] = [0x00];
    pub const ZERO_400D: [u8; 1] = [0x00];
    pub const RANDOM_11171: [u8; 1] = [0xac];
}
