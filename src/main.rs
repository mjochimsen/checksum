extern crate crc;
extern crate crypto;

use std::env::args;
use std::fs;
use std::io;
use std::io::Read;
use std::path;
use std::process::exit;
use std::sync::Arc;

use crc::{crc32, Hasher32};

mod config;
mod digest;
mod md5;
mod sha256;

use digest::Generator;

use config::Config;

fn main() {
    let config = Config::new(args());

    match run(config) {
        Ok(()) => (),

        Err(reason) => {
            eprintln!("{}", reason);
            exit(1)
        }
    }
}

fn run(config: Config) -> Result<(), String> {
    for filename in config.files {
        let path = path::Path::new(&filename);

        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_error) => {
                let error = format!("unable to get metadata for {}", filename);
                return Err(error);
            },
        };

        let size = metadata.len();

        println!("SIZE ({}): {}", filename, size);

        let crc32 = match crc32(&path) {
            Ok(crc32) => crc32,
            Err(_error) => {
                let error = format!("unable to read {}", filename);
                return Err(error);
            },
        };

        println!("CRC32 ({}): {:08x}", filename, crc32);

        let md5 = match md5(&path) {
            Ok(md5) => md5,
            Err(_error) => {
                let error = format!("unable to read {}", filename);
                return Err(error);
            },
        };

        println!("MD5 ({}): {}", filename, md5);

        let sha256 = match sha256(&path) {
            Ok(sha256) => sha256,
            Err(_error) => {
                let error = format!("unable to read {}", filename);
                return Err(error);
            },
        };

        println!("SHA256 ({}): {}", filename, sha256);
    }

    Ok(())
}

fn crc32(path: &path::Path) -> Result<u32, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];
    let mut digest = crc32::Digest::new(crc32::IEEE);

    loop {
        let count = input.read(&mut buffer)?;
        if count > 0 {
            digest.write(&buffer[0..count]);
        } else {
            break;
        }
    }

    Ok(digest.sum32())
}

fn md5(path: &path::Path) -> Result<digest::Digest, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];

    let md5 = md5::MD5::new();

    loop {
        let count = input.read(&mut buffer)?;
        let data = Arc::from(&buffer[0..count]);
        if count > 0 {
            md5.append(data);
        } else {
            break;
        }
    }

    Ok(md5.result())
}

fn sha256(path: &path::Path) -> Result<digest::Digest, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];

    let sha256 = sha256::SHA256::new();

    loop {
        let count = input.read(&mut buffer)?;
        let data = Arc::from(&buffer[0..count]);
        if count > 0 {
            sha256.append(data);
        } else {
            break;
        }
    }

    Ok(sha256.result())
}

#[cfg(test)]
mod tests {
    use super::*;
    use config::Config;
    use std::path::Path;

    #[test]
    fn fake_run() {
        let config = Config::new(vec!("test/zero.data", "test/random.data").iter());
        assert_eq!(run(config), Ok(()));
    }

    #[test]
    fn crc32_zero() {
        let zero = Path::new("test/zero.data");
        match crc32(zero) {
            Ok(value) => assert_eq!(value, 0x5dc1d8ba),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn crc32_random() {
        let random = Path::new("test/random.data");
        match crc32(random) {
            Ok(value) => assert_eq!(value, 0xff70a8ee),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_zero() {
        let zero = Path::new("test/zero.data");
        match md5(zero) {
            Ok(digest::Digest::MD5(value)) =>
                assert_eq!(value, [
                    0x41, 0xa2, 0x2d, 0x1e, 0xe7, 0x89, 0xde, 0xcb,
                    0xfb, 0xd4, 0x92, 0x4e, 0xc2, 0x1e, 0x53, 0xc9
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_random() {
        let random = Path::new("test/random.data");
        match md5(random) {
            Ok(digest::Digest::MD5(value)) =>
                assert_eq!(value, [
                    0xff, 0x8a, 0xe3, 0xcf, 0x94, 0x4c, 0xdd, 0xde,
                    0xa7, 0x19, 0x1c, 0x90, 0x6a, 0xfe, 0x0c, 0x81
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn sha256_zero() {
        let zero = Path::new("test/zero.data");
        match sha256(zero) {
            Ok(digest::Digest::SHA256(value)) =>
                assert_eq!(value, [
                    0xb3, 0xae, 0x04, 0xa0, 0x71, 0x30, 0x26, 0xc8,
                    0xcb, 0xf8, 0x8b, 0x6c, 0xbf, 0xf1, 0x73, 0xf6,
                    0x8a, 0x27, 0xcd, 0x37, 0x64, 0x14, 0xc4, 0x66,
                    0x45, 0xdd, 0x1a, 0x22, 0x93, 0x48, 0x6c, 0x99
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn sha256_random() {
        let random = Path::new("test/random.data");
        match sha256(random) {
            Ok(digest::Digest::SHA256(value)) =>
                assert_eq!(value, [
                    0x51, 0x52, 0xc2, 0xfe, 0xad, 0x7d, 0x46, 0xcd,
                    0x79, 0x11, 0x5c, 0xd0, 0x93, 0x53, 0x46, 0x47,
                    0xd8, 0x06, 0xd7, 0x4d, 0xa1, 0xaf, 0xda, 0x90,
                    0xbd, 0xc0, 0x6d, 0x4e, 0x7e, 0x40, 0xc5, 0x2d
                ]),
            Ok(digest) => assert!(false, "unexpected digest: {:?}", digest),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }
}
