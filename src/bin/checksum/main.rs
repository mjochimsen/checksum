#![warn(clippy::all, clippy::pedantic)]

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use checksum::{crc32, md5, rmd160, sha256, sha512, DigestData, Generator};

mod cli;
use cli::CLI;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let mut args = std::env::args_os();
    let _program = args.next();
    let cli = match CLI::parse(args) {
        Ok(cli) => cli,
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1)
        }
    };

    if cli.help {
        show_usage();
    } else if cli.version {
        show_version();
    } else if cli.paths.is_empty() {
        digest_stdin(&cli.digests)
            .unwrap_or_else(|_err| std::process::exit(1));
    } else {
        digest_files(&cli.digests, &cli.paths)
            .unwrap_or_else(|_err| std::process::exit(1));
    }
}

fn show_usage() {
    print!("{}", CLI::USAGE);
}

fn show_version() {
    print!("{}", VERSION);
}

fn digest_stdin(digests: &[DigestKind]) -> Result<(), ()> {
    // Create the generators based on the digests listed in the config.
    let generators = create_generators(digests);

    let input = io::stdin();
    if let Ok(digests) = digest_file(input, &generators) {
        print_digests(&digests, None);
    } else {
        print_error(&Error::StdinReadError);
        return Err(());
    }
    Ok(())
}

fn digest_files(digests: &[DigestKind], paths: &[PathBuf]) -> Result<(), ()> {
    // Create the generators based on the digests listed in the config.
    let generators = create_generators(digests);
    let mut error = false;

    for path in paths {
        let file = if let Ok(file) = fs::File::open(&path) {
            file
        } else {
            print_error(&Error::FileOpenError(path.clone()));
            error = true;
            continue;
        };
        if let Ok(digests) = digest_file(file, &generators) {
            print_digests(&digests, Some(path));
        } else {
            print_error(&Error::FileReadError(path.clone()));
            error = true;
            continue;
        }
    }

    if error {
        Err(())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidOption(String),
    FileOpenError(PathBuf),
    FileReadError(PathBuf),
    StdinReadError,
}

fn print_error(error: &Error) {
    eprintln!("{}", error);
}

fn print_digests(digests: &[DigestData], path: Option<&Path>) {
    for digest in digests {
        print_digest(digest, path);
    }
}

fn print_digest(digest: &DigestData, path: Option<&Path>) {
    let digest_name = match digest {
        DigestData::CRC32(_) => "CRC32",
        DigestData::MD5(_) => "MD5",
        DigestData::SHA256(_) => "SHA256",
        DigestData::SHA512(_) => "SHA512",
        DigestData::RMD160(_) => "RMD160",
    };

    match path {
        Some(path) => {
            let pathstr = path.to_str().unwrap();
            println!("{} ({}) = {}", digest_name, pathstr, digest);
        }
        None => {
            println!("{} = {}", digest_name, digest);
        }
    };
}

type Generators = Vec<Box<dyn Generator>>;

fn create_generators(digests: &[DigestKind]) -> Generators {
    digests
        .iter()
        .map(|digest| match digest {
            DigestKind::CRC32 => crc32(),
            DigestKind::MD5 => md5(),
            DigestKind::SHA256 => sha256(),
            DigestKind::SHA512 => sha512(),
            DigestKind::RMD160 => rmd160(),
        })
        .collect()
}

type DigestResult = Result<Vec<DigestData>, io::Error>;

fn digest_file<R: io::Read>(
    mut input: R,
    generators: &Generators,
) -> DigestResult {
    let mut buffer = [0u8; 0x4_0000];

    loop {
        let count = input.read(&mut buffer)?;
        if count > 0 {
            update_digests(generators, &buffer[0..count]);
        } else {
            break;
        }
    }

    let digests = generators
        .iter()
        .map(|generator| generator.result())
        .collect();

    Ok(digests)
}

fn update_digests(generators: &[Box<dyn Generator>], data: &[u8]) {
    let data: std::sync::Arc<[u8]> = std::sync::Arc::from(data);
    for generator in generators.iter() {
        generator.append(data.clone());
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidOption(option) => {
                write!(f, "invalid option '{}'", option)
            }
            Error::FileOpenError(path) => {
                let pathstr = path.to_str().unwrap();
                write!(f, "unable to open '{}'", pathstr)
            }
            Error::FileReadError(path) => {
                let pathstr = path.to_str().unwrap();
                write!(f, "unable to read from '{}'", pathstr)
            }
            Error::StdinReadError => write!(f, "unable to read from stdin"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestKind {
    CRC32,
    MD5,
    SHA256,
    SHA512,
    RMD160,
}

#[cfg(test)]
#[path = "../../../tests/fixtures/mod.rs"]
pub mod fixtures;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn format_error() {
        let error = Error::InvalidOption(String::from("--foo"));
        assert_eq!(format!("{}", error), "invalid option '--foo'");
    }

    #[test]
    fn create_generators() {
        let digests = vec![
            DigestKind::MD5,
            DigestKind::SHA256,
            DigestKind::SHA512,
            DigestKind::RMD160,
            DigestKind::CRC32,
        ];
        let generators = super::create_generators(&digests);
        assert_eq!(generators.len(), 5);
        let digest = &generators[0];
        assert_eq!(digest.result(), DigestData::MD5(fixtures::md5::EMPTY));
        let digest = &generators[1];
        assert_eq!(
            digest.result(),
            DigestData::SHA256(fixtures::sha256::EMPTY)
        );
        let digest = &generators[2];
        assert_eq!(
            digest.result(),
            DigestData::SHA512(fixtures::sha512::EMPTY)
        );
        let digest = &generators[3];
        assert_eq!(
            digest.result(),
            DigestData::RMD160(fixtures::rmd160::EMPTY)
        );
        let digest = &generators[4];
        assert_eq!(
            digest.result(),
            DigestData::CRC32(fixtures::crc32::EMPTY)
        );
    }

    #[test]
    fn update_digests() {
        let generators = generators();
        let data = fixtures::ZERO_400D;

        super::update_digests(&generators, &data);

        let digests: Vec<checksum::DigestData> = generators
            .iter()
            .map(|generator| generator.result())
            .collect();

        assert_eq!(
            digests,
            vec![
                DigestData::CRC32(fixtures::crc32::ZERO_400D),
                DigestData::MD5(fixtures::md5::ZERO_400D),
                DigestData::SHA256(fixtures::sha256::ZERO_400D),
                DigestData::SHA512(fixtures::sha512::ZERO_400D),
                DigestData::RMD160(fixtures::rmd160::ZERO_400D)
            ]
        );
    }

    #[test]
    fn digest_stdin() {
        let mut child = process::Command::new("/bin/cat")
            .arg(fixture_data("zero-400d"))
            .stdout(process::Stdio::piped())
            .spawn()
            .expect("failed to execute /bin/cat");
        child.wait().expect("failed to wait on child");
        let child_stdout =
            child.stdout.expect("unable to retrieve child stdout");
        let generators = generators();

        let digests = digest_file(child_stdout, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                DigestData::CRC32(fixtures::crc32::ZERO_400D),
                DigestData::MD5(fixtures::md5::ZERO_400D),
                DigestData::SHA256(fixtures::sha256::ZERO_400D),
                DigestData::SHA512(fixtures::sha512::ZERO_400D),
                DigestData::RMD160(fixtures::rmd160::ZERO_400D)
            ]
        );
    }

    #[test]
    fn digest_empty() {
        let empty = fs::File::open(fixture_data("empty")).unwrap();
        let generators = generators();

        let digests = digest_file(empty, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                DigestData::CRC32(fixtures::crc32::EMPTY),
                DigestData::MD5(fixtures::md5::EMPTY),
                DigestData::SHA256(fixtures::sha256::EMPTY),
                DigestData::SHA512(fixtures::sha512::EMPTY),
                DigestData::RMD160(fixtures::rmd160::EMPTY)
            ]
        );
    }

    #[test]
    fn digest_zero() {
        let zero = fs::File::open(fixture_data("zero-400d")).unwrap();
        let generators = generators();

        let digests = digest_file(zero, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                DigestData::CRC32(fixtures::crc32::ZERO_400D),
                DigestData::MD5(fixtures::md5::ZERO_400D),
                DigestData::SHA256(fixtures::sha256::ZERO_400D),
                DigestData::SHA512(fixtures::sha512::ZERO_400D),
                DigestData::RMD160(fixtures::rmd160::ZERO_400D)
            ]
        );
    }

    #[test]
    fn digest_random() {
        let random = fs::File::open(fixture_data("random-11171")).unwrap();
        let generators = generators();

        let digests = digest_file(random, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                DigestData::CRC32(fixtures::crc32::RANDOM_11171),
                DigestData::MD5(fixtures::md5::RANDOM_11171),
                DigestData::SHA256(fixtures::sha256::RANDOM_11171),
                DigestData::SHA512(fixtures::sha512::RANDOM_11171),
                DigestData::RMD160(fixtures::rmd160::RANDOM_11171)
            ]
        );
    }

    fn generators() -> Vec<Box<dyn Generator>> {
        vec![crc32(), md5(), sha256(), sha512(), rmd160()]
    }

    fn fixture_data(filename: &str) -> PathBuf {
        PathBuf::from_iter(&["tests", "fixtures", filename])
    }
}
