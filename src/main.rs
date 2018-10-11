extern crate crc;

use std::env::args;
use std::fs;
use std::io;
use std::io::Read;
use std::path;
use std::process::exit;
use crc::{crc32, Hasher32};

mod config;

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

        println!("SIZE({}): {}", filename, size);

        let xor = match xor(&path) {
            Ok(xor) => xor,
            Err(_error) => {
                let error = format!("unable to read {}", filename);
                return Err(error);
            },
        };

        println!("XOR({}): {:02x}", filename, xor);

        let crc32 = match crc32(&path) {
            Ok(crc32) => crc32,
            Err(_error) => {
                let error = format!("unable to read {}", filename);
                return Err(error);
            },
        };

        println!("CRC32({}): {:08x}", filename, crc32);
    }

    Ok(())
}

fn xor(path: &path::Path) -> Result<u8, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];
    let mut xor: u8 = 0;

    loop {
        let count = input.read(&mut buffer)?;
        if count > 0 {
            xor = buffer.iter().fold(xor, |acc, byte| {
                acc ^ byte
            });
        } else {
            break;
        }
    }

    Ok(xor)
}

fn crc32(path: &path::Path) -> Result<u32, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];
    let mut digest = crc32::Digest::new(crc32::IEEE);

    loop {
        let count = input.read(&mut buffer)?;
        if count > 0 {
            digest.write(&buffer);
        } else {
            break;
        }
    }

    Ok(digest.sum32())
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
    fn xor_zero() {
        let zero = Path::new("test/zero.data");
        match xor(zero) {
            Ok(value) => assert_eq!(value, 0),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn xor_random() {
        let random = Path::new("test/random.data");
        match xor(random) {
            Ok(value) => assert_eq!(value, 0x0f),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn crc32_zero() {
        let zero = Path::new("test/zero.data");
        match crc32(zero) {
            Ok(value) => assert_eq!(value, 0xd7978eeb),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn crc32_random() {
        let random = Path::new("test/random.data");
        match crc32(random) {
            Ok(value) => assert_eq!(value, 0xaa442759),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }
}
