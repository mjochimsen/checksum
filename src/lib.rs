#![warn(clippy::all, clippy::pedantic)]

mod digest;

pub use digest::{crc32, md5, rmd160, sha256, sha512, Digest, Generator};
