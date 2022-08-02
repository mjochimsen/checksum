extern crate libc;

use std::fmt;
use std::fs;
use std::io;
use std::path;

mod config;
mod digest;
mod openssl;

use config::Config;
use digest::*;

fn main() {
    let config = match Config::new(std::env::args()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1)
        }
    };

    let result = match choose_action(config) {
        Action::ShowHelp => show_help(),
        Action::DigestStdin(digests) => digest_stdin(digests),
        Action::DigestFiles(digests, paths) => digest_files(digests, paths),
    };

    match result {
        Ok(_) => return,
        Err(_) => std::process::exit(1),
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Action {
    ShowHelp,
    DigestStdin(Vec<config::Digest>),
    DigestFiles(Vec<config::Digest>, Vec<path::PathBuf>),
}

fn choose_action(config: Config) -> Action {
    if config.help {
        Action::ShowHelp
    } else if config.use_stdin() {
        Action::DigestStdin(config.digests)
    } else {
        Action::DigestFiles(config.digests, config.paths)
    }
}

fn show_help() -> Result<(), ()> {
    print!("{}", Config::help());
    Ok(())
}

fn digest_stdin(digests: Vec<config::Digest>) -> Result<(), ()> {
    // Create the generators based on the digests listed in the config.
    let generators = create_generators(&digests);

    let input = io::stdin();
    match digest_file(input, &generators) {
        Ok(digests) => print_digests(digests, None),
        Err(_) => {
            print_error(Error::StdinReadError);
            return Err(());
        }
    }
    Ok(())
}

fn digest_files(
    digests: Vec<config::Digest>,
    paths: Vec<path::PathBuf>,
) -> Result<(), ()> {
    // Create the generators based on the digests listed in the config.
    let generators = create_generators(&digests);
    let mut error = false;

    for path in paths {
        let file = match fs::File::open(&path) {
            Ok(file) => file,
            Err(_) => {
                print_error(Error::FileOpenError(path));
                error = true;
                continue;
            }
        };
        match digest_file(file, &generators) {
            Ok(digests) => print_digests(digests, Some(&path)),
            Err(_) => {
                print_error(Error::FileReadError(path));
                error = true;
                continue;
            }
        }
    }

    if error {
        Err(())
    } else {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    FileOpenError(path::PathBuf),
    FileReadError(path::PathBuf),
    StdinReadError,
}

fn print_error(error: Error) {
    eprintln!("{}", error);
}

fn print_digests(digests: Vec<Digest>, path: Option<&path::Path>) {
    for digest in digests {
        print_digest(digest, path);
    }
}

fn print_digest(digest: Digest, path: Option<&path::Path>) {
    let digest_name = match digest {
        Digest::CRC32(_) => "CRC32",
        Digest::MD5(_) => "MD5",
        Digest::SHA256(_) => "SHA256",
        Digest::SHA512(_) => "SHA512",
        Digest::RMD160(_) => "RMD160",
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

fn create_generators(digests: &Vec<config::Digest>) -> Generators {
    digests
        .iter()
        .map(|digest| match digest {
            config::Digest::CRC32 => crc32(),
            config::Digest::MD5 => md5(),
            config::Digest::SHA256 => sha256(),
            config::Digest::SHA512 => sha512(),
            config::Digest::RMD160 => rmd160(),
        })
        .collect()
}

type DigestResult = Result<Vec<Digest>, io::Error>;

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

fn update_digests(generators: &Vec<Box<dyn Generator>>, data: &[u8]) {
    let data: std::sync::Arc<[u8]> = std::sync::Arc::from(data);
    for generator in generators.iter() {
        generator.append(data.clone());
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use config;
    use digest::test_digests::*;
    use std::process;

    #[test]
    fn choose_actions() {
        let cli = vec!["checksum", "--help"];
        let config = config::Config::new(cli.iter()).unwrap();
        let action = choose_action(config);
        assert_eq!(action, Action::ShowHelp);

        let cli = vec!["checksum", "--md5"];
        let config = config::Config::new(cli.iter()).unwrap();
        let action = choose_action(config);
        assert_eq!(action, Action::DigestStdin(vec![config::Digest::MD5]));

        let cli = vec!["checksum", "--md5", "foo"];
        let config = config::Config::new(cli.iter()).unwrap();
        let action = choose_action(config);
        assert_eq!(
            action,
            Action::DigestFiles(
                vec![config::Digest::MD5],
                vec![path::PathBuf::from("foo")]
            )
        );
    }

    #[test]
    fn create_generators() {
        let digests = vec![
            config::Digest::MD5,
            config::Digest::SHA256,
            config::Digest::SHA512,
            config::Digest::RMD160,
            config::Digest::CRC32,
        ];
        let generators = super::create_generators(&digests);
        assert_eq!(generators.len(), 5);
        let digest = &generators[0];
        assert_eq!(digest.result(), MD5_ZERO_EMPTY);
        let digest = &generators[1];
        assert_eq!(digest.result(), SHA256_ZERO_EMPTY);
        let digest = &generators[2];
        assert_eq!(digest.result(), SHA512_ZERO_EMPTY);
        let digest = &generators[3];
        assert_eq!(digest.result(), RMD160_ZERO_EMPTY);
        let digest = &generators[4];
        assert_eq!(digest.result(), CRC32_ZERO_EMPTY);
    }

    #[test]
    fn update_digests() {
        let generators = generators();
        let data = [0u8; 0x400d];

        super::update_digests(&generators, &data);

        let digests: Vec<digest::Digest> = generators
            .iter()
            .map(|generator| generator.result())
            .collect();

        assert_eq!(
            digests,
            vec![
                CRC32_ZERO_400D,
                MD5_ZERO_400D,
                SHA256_ZERO_400D,
                SHA512_ZERO_400D,
                RMD160_ZERO_400D
            ]
        );
    }

    #[test]
    fn digest_stdin() {
        let mut child = process::Command::new("/bin/cat")
            .arg(test_data("zero-400d"))
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
                CRC32_ZERO_400D,
                MD5_ZERO_400D,
                SHA256_ZERO_400D,
                SHA512_ZERO_400D,
                RMD160_ZERO_400D
            ]
        );
    }

    #[test]
    fn digest_empty() {
        let empty = fs::File::open(test_data("zero-0")).unwrap();
        let generators = generators();

        let digests = digest_file(empty, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                CRC32_ZERO_EMPTY,
                MD5_ZERO_EMPTY,
                SHA256_ZERO_EMPTY,
                SHA512_ZERO_EMPTY,
                RMD160_ZERO_EMPTY
            ]
        );
    }

    #[test]
    fn digest_zero() {
        let zero = fs::File::open(test_data("zero-11171")).unwrap();
        let generators = generators();

        let digests = digest_file(zero, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                CRC32_ZERO_11171,
                MD5_ZERO_11171,
                SHA256_ZERO_11171,
                SHA512_ZERO_11171,
                RMD160_ZERO_11171
            ]
        );
    }

    #[test]
    fn digest_random() {
        let random = fs::File::open(test_data("random-11171")).unwrap();
        let generators = generators();

        let digests = digest_file(random, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                CRC32_RANDOM_11171,
                MD5_RANDOM_11171,
                SHA256_RANDOM_11171,
                SHA512_RANDOM_11171,
                RMD160_RANDOM_11171
            ]
        );
    }

    fn generators() -> Vec<Box<dyn Generator>> {
        vec![crc32(), md5(), sha256(), sha512(), rmd160()]
    }

    fn test_data(filename: &str) -> path::PathBuf {
        path::PathBuf::from_iter(&["tests", "data", filename])
    }
}
