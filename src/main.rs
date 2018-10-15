extern crate crc;
extern crate crypto;

use std::env::args;
use std::fs;
use std::io;
use std::io::Read;
use std::path;
use std::process::exit;
use crc::{crc32, Hasher32};

mod config;
mod digest;

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

    let (tx, rx) = digest::background_md5();

    loop {
        let count = input.read(&mut buffer)?;
        let data = Box::from(&buffer[0..count]);
        tx.send(data).unwrap();
        if count == 0 {
            break;
        }
    }

    let digest = rx.recv();

    match digest {
        Ok(digest) => Ok(digest),
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "error receiving checksum data")),
    }
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
            Ok(digest::Digest::MD5(value)) => assert_eq!(value, [
                0x41, 0xa2, 0x2d, 0x1e, 0xe7, 0x89, 0xde, 0xcb,
                0xfb, 0xd4, 0x92, 0x4e, 0xc2, 0x1e, 0x53, 0xc9
                ]),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_random() {
        let random = Path::new("test/random.data");
        match md5(random) {
            Ok(digest::Digest::MD5(value)) => assert_eq!(value, [
                0xff, 0x8a, 0xe3, 0xcf, 0x94, 0x4c, 0xdd, 0xde,
                0xa7, 0x19, 0x1c, 0x90, 0x6a, 0xfe, 0x0c, 0x81
                ]),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }
}
