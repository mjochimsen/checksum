extern crate libc;

use std::env::args;
use std::fs;
use std::io;
use std::io::Read;
use std::path;
use std::process::exit;
use std::sync::Arc;

mod config;
mod digest;
mod openssl;

use config::Config;
use digest::*;

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
    let generators = vec![crc32(), md5(), sha256(), sha512(), rmd160()];

    for filename in config.files {
        let path = path::Path::new(&filename);

        let digests = digest_file(path, &generators);

        let digests = match digests {
            Ok(digests) => digests,
            Err(_error) => {
                let error = format!("unable to process {}", filename);
                return Err(error);
            }
        };

        for digest in digests {
            let name = match digest {
                Digest::CRC32(_) => "CRC32",
                Digest::MD5(_) => "MD5",
                Digest::SHA256(_) => "SHA256",
                Digest::SHA512(_) => "SHA512",
                Digest::RMD160(_) => "RMD160",
            };

            println!("{} ({}) = {}", name, filename, digest);
        }
    }

    Ok(())
}

fn digest_file(path: &path::Path, generators: &Vec<Box<Generator>>) ->
        Result<Vec<Digest>, io::Error> {

    let mut input = fs::File::open(path)?;
    let mut buffer = [0u8; 0x10_0000];

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

        let error = digest_file(missing, &generators).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn digest_empty() {
        let empty = Path::new("test/zero-0");
        let generators = generators();

        let digests = digest_file(empty, &generators).unwrap();

        assert_eq!(digests, vec![CRC32_ZERO_EMPTY,
                                 MD5_ZERO_EMPTY,
                                 SHA256_ZERO_EMPTY,
                                 SHA512_ZERO_EMPTY,
                                 RMD160_ZERO_EMPTY]);
    }

    #[test]
    fn digest_zero() {
        let empty = Path::new("test/zero-11171");
        let generators = generators();

        let digests = digest_file(empty, &generators).unwrap();

        assert_eq!(digests, vec![CRC32_ZERO_11171,
                                 MD5_ZERO_11171,
                                 SHA256_ZERO_11171,
                                 SHA512_ZERO_11171,
                                 RMD160_ZERO_11171]);
    }

    #[test]
    fn digest_random() {
        let empty = Path::new("test/random-11171");
        let generators = generators();

        let digests = digest_file(empty, &generators).unwrap();

        assert_eq!(digests, vec![CRC32_RANDOM_11171,
                                 MD5_RANDOM_11171,
                                 SHA256_RANDOM_11171,
                                 SHA512_RANDOM_11171,
                                 RMD160_RANDOM_11171]);
    }

    fn generators() -> Vec<Box<Generator>> {
        vec![crc32(), md5(), sha256(), sha512(), rmd160()]
    }
}
