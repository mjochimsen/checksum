#![warn(clippy::all, clippy::pedantic)]

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use checksum::{crc32, md5, rmd160, sha256, sha512, DigestData, Generator};

fn main() {
    let config = match Config::new(std::env::args()) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("{}", error);
            std::process::exit(1)
        }
    };

    let result = match choose_action(config) {
        Action::ShowHelp => {
            show_help();
            Ok(())
        }
        Action::DigestStdin(digests) => digest_stdin(&digests),
        Action::DigestFiles(digests, paths) => digest_files(&digests, paths),
    };

    if result.is_err() {
        std::process::exit(1);
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Action {
    ShowHelp,
    DigestStdin(Vec<DigestKind>),
    DigestFiles(Vec<DigestKind>, Vec<PathBuf>),
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

fn show_help() {
    print!("{}", Config::HELP);
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

fn digest_files(
    digests: &[DigestKind],
    paths: Vec<PathBuf>,
) -> Result<(), ()> {
    // Create the generators based on the digests listed in the config.
    let generators = create_generators(digests);
    let mut error = false;

    for path in paths {
        let file = if let Ok(file) = fs::File::open(&path) {
            file
        } else {
            print_error(&Error::FileOpenError(path));
            error = true;
            continue;
        };
        if let Ok(digests) = digest_file(file, &generators) {
            print_digests(&digests, Some(&path));
        } else {
            print_error(&Error::FileReadError(path));
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
    DuplicateOption(String),
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
            Error::DuplicateOption(option) => {
                write!(f, "duplicate digest option '{}'", option)
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
enum DigestKind {
    CRC32,
    MD5,
    SHA256,
    SHA512,
    RMD160,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    pub cmd: String,
    pub help: bool,
    pub paths: Vec<PathBuf>,
    pub digests: Vec<DigestKind>,
}

impl Config {
    pub const HELP: &'static str = include_str!("usage.txt");

    pub fn new<T: Iterator<Item = impl ToString>>(
        mut args: T,
    ) -> Result<Config, Error> {
        // Pull the fist argument. This is the command name.
        let cmd = args.next().unwrap().to_string();

        // Convert the arguments into the components which will be
        // used in the Config structure.
        let mut help = false;
        let mut digests: Vec<DigestKind> = vec![];
        let mut paths: Vec<PathBuf> = vec![];

        for arg in args {
            // Parse the argument.
            match Argument::parse(&arg.to_string()) {
                Argument::Help => {
                    // Set the help flag.
                    help = true;
                }
                Argument::Digest(digest) => {
                    // Add the digest to list of digests. We don't
                    // permit the same digest to appear more than
                    // once. If it does, return an error.
                    if digests.contains(&digest) {
                        let error = Error::DuplicateOption(arg.to_string());
                        return Err(error);
                    }
                    digests.push(digest);
                }
                Argument::Filename(filename) => {
                    // Convert the filename to a PathBuf and add it
                    // to the list of paths.
                    let path = PathBuf::from(filename);
                    paths.push(path);
                }
                Argument::Error(error) => {
                    // If we encounter an error parsing the argument
                    // return an InvalidOption error.
                    return Err(Error::InvalidOption(error));
                }
            }
        }

        // If no digests were set, use a default set of MD5, SHA256,
        // SHA512, and RMD160.
        if digests.is_empty() && !help {
            digests = vec![
                DigestKind::MD5,
                DigestKind::SHA256,
                DigestKind::SHA512,
                DigestKind::RMD160,
            ];
        }

        Ok(Config {
            cmd,
            help,
            paths,
            digests,
        })
    }

    pub fn use_stdin(&self) -> bool {
        self.paths.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Argument {
    Error(String),
    Help,
    Digest(DigestKind),
    Filename(String),
}

impl Argument {
    fn parse(arg: &str) -> Argument {
        match arg {
            "--help" | "-h" => Argument::Help,
            "--crc32" => Argument::Digest(DigestKind::CRC32),
            "--md5" => Argument::Digest(DigestKind::MD5),
            "--sha256" => Argument::Digest(DigestKind::SHA256),
            "--sha512" => Argument::Digest(DigestKind::SHA512),
            "--rmd160" => Argument::Digest(DigestKind::RMD160),
            arg if arg.starts_with('-') => Argument::Error(arg.to_string()),
            filename => Argument::Filename(filename.to_string()),
        }
    }
}

#[cfg(test)]
use checksum::MD5;

#[cfg(test)]
#[path = "../../test_digests/mod.rs"]
pub mod test_digests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process;

    #[test]
    fn parse_argument() {
        assert_eq!(Argument::parse("--help"), Argument::Help);
        assert_eq!(Argument::parse("-h"), Argument::Help);

        assert_eq!(
            Argument::parse("--crc32"),
            Argument::Digest(DigestKind::CRC32)
        );
        assert_eq!(
            Argument::parse("--md5"),
            Argument::Digest(DigestKind::MD5)
        );
        assert_eq!(
            Argument::parse("--sha256"),
            Argument::Digest(DigestKind::SHA256)
        );
        assert_eq!(
            Argument::parse("--sha512"),
            Argument::Digest(DigestKind::SHA512)
        );
        assert_eq!(
            Argument::parse("--rmd160"),
            Argument::Digest(DigestKind::RMD160)
        );

        assert_eq!(
            Argument::parse("foo"),
            Argument::Filename("foo".to_string())
        );

        assert_eq!(Argument::parse("-q"), Argument::Error("-q".to_string()));
        assert_eq!(
            Argument::parse("--foo"),
            Argument::Error("--foo".to_string())
        );
    }

    #[test]
    fn parse_help_cli() {
        let cli = vec!["checksum", "--help"];
        let config = Config::new(cli.iter()).unwrap();

        assert_eq!(config.cmd, "checksum");
        assert!(config.help);
        assert_eq!(config.paths.len(), 0);
        assert_eq!(config.digests.len(), 0);
    }

    #[test]
    fn parse_digests_cli() {
        let cli = vec![
            "checksum", "--crc32", "--md5", "--sha256", "--sha512",
            "--rmd160",
        ];
        let config = Config::new(cli.iter()).unwrap();

        assert_eq!(config.cmd, "checksum");
        assert!(!config.help);
        assert_eq!(config.paths.len(), 0);
        assert_eq!(
            config.digests,
            vec![
                DigestKind::CRC32,
                DigestKind::MD5,
                DigestKind::SHA256,
                DigestKind::SHA512,
                DigestKind::RMD160
            ]
        );
    }

    #[test]
    fn parse_default_digests() {
        let cli = vec!["checksum"];
        let config = Config::new(cli.iter()).unwrap();

        assert_eq!(config.cmd, "checksum");
        assert!(!config.help);
        assert_eq!(config.paths.len(), 0);
        assert_eq!(
            config.digests,
            vec![
                DigestKind::MD5,
                DigestKind::SHA256,
                DigestKind::SHA512,
                DigestKind::RMD160
            ]
        );
    }

    #[test]
    fn parse_filenames() {
        let cli = vec!["checksum", "some", "files"];
        let config = Config::new(cli.iter()).unwrap();

        assert_eq!(config.cmd, "checksum");
        assert!(!config.help);
        assert_eq!(
            config.digests,
            vec![
                DigestKind::MD5,
                DigestKind::SHA256,
                DigestKind::SHA512,
                DigestKind::RMD160
            ]
        );
        assert_eq!(
            config.paths,
            vec![PathBuf::from("some"), PathBuf::from("files")]
        );
    }

    #[test]
    fn use_stdin() {
        let cli = vec!["checksum", "file"];
        let config = Config::new(cli.iter()).unwrap();
        assert!(!config.use_stdin());

        let cli = vec!["checksum"];
        let config = Config::new(cli.iter()).unwrap();
        assert!(config.use_stdin());
    }

    #[test]
    fn parse_invalid_option() {
        let cli = vec!["checksum", "--foo"];
        let error = Config::new(cli.iter()).unwrap_err();
        assert_eq!(error, Error::InvalidOption(String::from("--foo")));
    }

    #[test]
    fn parse_duplicate_digest() {
        let cli = vec!["checksum", "--md5", "--md5"];
        let error = Config::new(cli.iter()).unwrap_err();
        assert_eq!(error, Error::DuplicateOption(String::from("--md5")));
    }

    #[test]
    fn format_error() {
        let error = Error::InvalidOption(String::from("--foo"));
        assert_eq!(format!("{}", error), "invalid option '--foo'");

        let error = Error::DuplicateOption(String::from("--crc32"));
        assert_eq!(format!("{}", error), "duplicate digest option '--crc32'");

        let error = Error::DuplicateOption(String::from("--md5"));
        assert_eq!(format!("{}", error), "duplicate digest option '--md5'");

        let error = Error::DuplicateOption(String::from("--sha256"));
        assert_eq!(
            format!("{}", error),
            "duplicate digest option '--sha256'"
        );

        let error = Error::DuplicateOption(String::from("--sha512"));
        assert_eq!(
            format!("{}", error),
            "duplicate digest option '--sha512'"
        );

        let error = Error::DuplicateOption(String::from("--rmd160"));
        assert_eq!(
            format!("{}", error),
            "duplicate digest option '--rmd160'"
        );
    }

    #[test]
    fn help_text() {
        assert!(Config::HELP.contains("--help"));
        assert!(Config::HELP.contains("--crc32"));
        assert!(Config::HELP.contains("--md5"));
        assert!(Config::HELP.contains("--sha256"));
        assert!(Config::HELP.contains("--sha512"));
        assert!(Config::HELP.contains("--rmd160"));
    }

    #[test]
    fn choose_actions() {
        let cli = vec!["checksum", "--help"];
        let config = Config::new(cli.iter()).unwrap();
        let action = choose_action(config);
        assert_eq!(action, Action::ShowHelp);

        let cli = vec!["checksum", "--md5"];
        let config = Config::new(cli.iter()).unwrap();
        let action = choose_action(config);
        assert_eq!(action, Action::DigestStdin(vec![DigestKind::MD5]));

        let cli = vec!["checksum", "--md5", "foo"];
        let config = Config::new(cli.iter()).unwrap();
        let action = choose_action(config);
        assert_eq!(
            action,
            Action::DigestFiles(
                vec![DigestKind::MD5],
                vec![PathBuf::from("foo")]
            )
        );
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
        assert_eq!(
            digest.result(),
            DigestData::MD5(test_digests::md5::EMPTY)
        );
        let digest = &generators[1];
        assert_eq!(digest.result(), test_digests::sha256::EMPTY);
        let digest = &generators[2];
        assert_eq!(digest.result(), test_digests::sha512::EMPTY);
        let digest = &generators[3];
        assert_eq!(digest.result(), test_digests::rmd160::EMPTY);
        let digest = &generators[4];
        assert_eq!(digest.result(), test_digests::crc32::EMPTY);
    }

    #[test]
    fn update_digests() {
        let generators = generators();
        let data = test_digests::ZERO_400D;

        super::update_digests(&generators, &data);

        let digests: Vec<checksum::DigestData> = generators
            .iter()
            .map(|generator| generator.result())
            .collect();

        assert_eq!(
            digests,
            vec![
                test_digests::crc32::ZERO_400D,
                DigestData::MD5(test_digests::md5::ZERO_400D),
                test_digests::sha256::ZERO_400D,
                test_digests::sha512::ZERO_400D,
                test_digests::rmd160::ZERO_400D
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
                test_digests::crc32::ZERO_400D,
                DigestData::MD5(test_digests::md5::ZERO_400D),
                test_digests::sha256::ZERO_400D,
                test_digests::sha512::ZERO_400D,
                test_digests::rmd160::ZERO_400D
            ]
        );
    }

    #[test]
    fn digest_empty() {
        let empty = fs::File::open(test_data("empty")).unwrap();
        let generators = generators();

        let digests = digest_file(empty, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                test_digests::crc32::EMPTY,
                DigestData::MD5(test_digests::md5::EMPTY),
                test_digests::sha256::EMPTY,
                test_digests::sha512::EMPTY,
                test_digests::rmd160::EMPTY
            ]
        );
    }

    #[test]
    fn digest_zero() {
        let zero = fs::File::open(test_data("zero-400d")).unwrap();
        let generators = generators();

        let digests = digest_file(zero, &generators).unwrap();

        assert_eq!(
            digests,
            vec![
                test_digests::crc32::ZERO_400D,
                DigestData::MD5(test_digests::md5::ZERO_400D),
                test_digests::sha256::ZERO_400D,
                test_digests::sha512::ZERO_400D,
                test_digests::rmd160::ZERO_400D
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
                test_digests::crc32::RANDOM_11171,
                DigestData::MD5(test_digests::md5::RANDOM_11171),
                test_digests::sha256::RANDOM_11171,
                test_digests::sha512::RANDOM_11171,
                test_digests::rmd160::RANDOM_11171
            ]
        );
    }

    fn generators() -> Vec<Box<dyn Generator>> {
        vec![crc32(), md5(), sha256(), sha512(), rmd160()]
    }

    fn test_data(filename: &str) -> PathBuf {
        PathBuf::from_iter(&["src", "test_digests", filename])
    }
}
