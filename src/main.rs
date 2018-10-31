extern crate crc;
extern crate crypto;

use std::env::args;
use std::fs;
use std::io;
use std::io::Read;
use std::path;
use std::process::exit;
use std::sync::Arc;

mod config;
mod digest;

use config::Config;
use digest::{Digest, Generator};

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

        println!("CRC32 ({}): {}", filename, crc32);

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

fn digest_file(path: &path::Path, generators: Vec<Box<Generator>>) ->
        Result<Vec<Digest>, io::Error> {

    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];

    loop {
        let count = input.read(&mut buffer)?;
        if count > 0 {
            let data: Arc<[u8]> = Arc::from(&buffer[0..count]);

            for generator in generators.iter() {
                generator.append(data.clone());
            }
        } else {
            break;
        }
    }

    let digests = generators.iter()
                            .map(|generator| generator.result())
                            .collect();

    Ok(digests)
}

fn crc32(path: &path::Path) -> Result<Digest, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];

    let crc32 = digest::crc32();

    loop {
        let count = input.read(&mut buffer)?;
        let data = Arc::from(&buffer[0..count]);
        if count > 0 {
            crc32.append(data);
        } else {
            break;
        }
    }

    Ok(crc32.result())
}

fn md5(path: &path::Path) -> Result<Digest, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];

    let md5 = digest::md5();

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

fn sha256(path: &path::Path) -> Result<Digest, io::Error> {
    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x4000];

    let sha256 = digest::sha256();

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
    use digest::test_digests::*;

    #[test]
    fn fake_run() {
        let config = Config::new(vec!("test/zero-11171", "test/random-11171").iter());
        assert_eq!(run(config), Ok(()));
    }

    #[test]
    fn digest_missing() {
        let missing = Path::new("test/missing");
        let generators = generators();

        let error = digest_file(missing, generators).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn digest_empty() {
        let empty = Path::new("test/zero-0");
        let generators = generators();

        let digests = digest_file(empty, generators).unwrap();

        assert_eq!(digests, vec![CRC32_ZERO_EMPTY,
                                 MD5_ZERO_EMPTY,
                                 SHA256_ZERO_EMPTY]);
    }

    #[test]
    fn digest_zero() {
        let empty = Path::new("test/zero-11171");
        let generators = generators();

        let digests = digest_file(empty, generators).unwrap();

        assert_eq!(digests, vec![CRC32_ZERO_11171,
                                 MD5_ZERO_11171,
                                 SHA256_ZERO_11171]);
    }

    #[test]
    fn digest_random() {
        let empty = Path::new("test/random-11171");
        let generators = generators();

        let digests = digest_file(empty, generators).unwrap();

        assert_eq!(digests, vec![CRC32_RANDOM_11171,
                                 MD5_RANDOM_11171,
                                 SHA256_RANDOM_11171]);
    }

    fn generators() -> Vec<Box<Generator>> {
        vec![digest::crc32(), digest::md5(), digest::sha256()]
    }

    #[test]
    fn crc32_zero() {
        let zero = Path::new("test/zero-11171");
        match crc32(zero) {
            Ok(digest) => assert_eq!(digest, CRC32_ZERO_11171),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn crc32_random() {
        let random = Path::new("test/random-11171");
        match crc32(random) {
            Ok(digest) => assert_eq!(digest, CRC32_RANDOM_11171),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_zero() {
        let zero = Path::new("test/zero-11171");
        match md5(zero) {
            Ok(digest) => assert_eq!(digest, MD5_ZERO_11171),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn md5_random() {
        let random = Path::new("test/random-11171");
        match md5(random) {
            Ok(digest) => assert_eq!(digest, MD5_RANDOM_11171),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn sha256_zero() {
        let zero = Path::new("test/zero-11171");
        match sha256(zero) {
            Ok(digest) => assert_eq!(digest, SHA256_ZERO_11171),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }

    #[test]
    fn sha256_random() {
        let random = Path::new("test/random-11171");
        match sha256(random) {
            Ok(digest) => assert_eq!(digest, SHA256_RANDOM_11171),
            Err(error) => assert!(false, "unexpected error: {:?}", error),
        };
    }
}
