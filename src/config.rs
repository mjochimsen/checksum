use std::fmt;
use std::path;

#[derive(Clone, PartialEq, Debug)]
pub struct Config {
    pub cmd: String,
    pub help: bool,
    pub paths: Vec<path::PathBuf>,
    pub digests: Vec<Digest>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Digest {
    CRC32,
    MD5,
    SHA256,
    SHA512,
    RMD160,
}

#[derive(Clone, PartialEq, Debug)]
pub enum Error {
    InvalidOption(String),
    DuplicateOption(String),
}

impl Config {
    pub const HELP: &'static str = include_str!("usage.txt");

    pub fn new<T: Iterator<Item = impl ToString>>(
        args: T,
    ) -> Result<Config, Error> {
        // Collect the arguments into a vector of strings.
        let mut args: Vec<String> = args.map(|arg| arg.to_string()).collect();

        // Pull the fist argument. This is the command name.
        let cmd: String = args.remove(0);

        // Convert the arguments into the components which will be
        // used in the Config structure.
        let mut help = false;
        let mut digests: Vec<Digest> = vec![];
        let mut paths: Vec<path::PathBuf> = vec![];

        for arg in &args {
            // Parse the argument.
            match Argument::parse(arg) {
                Argument::Help => {
                    // Set the help flag.
                    help = true;
                }
                Argument::Digest(digest) => {
                    // Add the digest to list of digests. We don't
                    // permit the same digest to appear more than
                    // once. If it does, return an error.
                    if digests.contains(&digest) {
                        let error = Error::DuplicateOption(arg.clone());
                        return Err(error);
                    }
                    digests.push(digest);
                }
                Argument::Filename(filename) => {
                    // Convert the filename to a PathBuf and add it
                    // to the list of paths.
                    let path = path::PathBuf::from(filename);
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
                Digest::MD5,
                Digest::SHA256,
                Digest::SHA512,
                Digest::RMD160,
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidOption(option) => {
                write!(f, "invalid option '{}'", option)
            }
            Error::DuplicateOption(option) => {
                write!(f, "duplicate digest option '{}'", option)
            }
        }
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Argument {
    Error(String),
    Help,
    Digest(Digest),
    Filename(String),
}

impl Argument {
    fn parse(arg: &String) -> Argument {
        if arg == "--help" || arg == "-h" {
            Argument::Help
        } else if arg == "--crc32" {
            Argument::Digest(Digest::CRC32)
        } else if arg == "--md5" {
            Argument::Digest(Digest::MD5)
        } else if arg == "--sha256" {
            Argument::Digest(Digest::SHA256)
        } else if arg == "--sha512" {
            Argument::Digest(Digest::SHA512)
        } else if arg == "--rmd160" {
            Argument::Digest(Digest::RMD160)
        } else if arg.starts_with('-') {
            Argument::Error(arg.clone())
        } else {
            Argument::Filename(arg.clone())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_argument() {
        let help_arg = String::from("--help");
        assert_eq!(Argument::parse(&help_arg), Argument::Help);
        let help_arg = String::from("-h");
        assert_eq!(Argument::parse(&help_arg), Argument::Help);

        let digest_arg = String::from("--crc32");
        assert_eq!(
            Argument::parse(&digest_arg),
            Argument::Digest(Digest::CRC32)
        );
        let digest_arg = String::from("--md5");
        assert_eq!(
            Argument::parse(&digest_arg),
            Argument::Digest(Digest::MD5)
        );
        let digest_arg = String::from("--sha256");
        assert_eq!(
            Argument::parse(&digest_arg),
            Argument::Digest(Digest::SHA256)
        );
        let digest_arg = String::from("--sha512");
        assert_eq!(
            Argument::parse(&digest_arg),
            Argument::Digest(Digest::SHA512)
        );
        let digest_arg = String::from("--rmd160");
        assert_eq!(
            Argument::parse(&digest_arg),
            Argument::Digest(Digest::RMD160)
        );

        let filename_arg = String::from("foo");
        assert_eq!(
            Argument::parse(&filename_arg),
            Argument::Filename("foo".to_string())
        );

        let error_arg = String::from("-q");
        assert_eq!(
            Argument::parse(&error_arg),
            Argument::Error("-q".to_string())
        );
        let error_arg = String::from("--foo");
        assert_eq!(
            Argument::parse(&error_arg),
            Argument::Error("--foo".to_string())
        );
    }

    #[test]
    fn parse_help_cli() {
        let cli = vec!["checksum", "--help"];
        let config = Config::new(cli.iter());
        assert!(config.is_ok());
        let config = config.unwrap();

        assert_eq!(config.cmd, "checksum");
        assert_eq!(config.help, true);
        assert_eq!(config.paths.len(), 0);
        assert_eq!(config.digests.len(), 0);
    }

    #[test]
    fn parse_digests_cli() {
        let cli = vec![
            "checksum", "--crc32", "--md5", "--sha256", "--sha512",
            "--rmd160",
        ];
        let config = Config::new(cli.iter());
        assert!(config.is_ok());
        let config = config.unwrap();

        assert_eq!(config.cmd, "checksum");
        assert_eq!(config.help, false);
        assert_eq!(config.paths.len(), 0);
        assert_eq!(
            config.digests,
            vec![
                Digest::CRC32,
                Digest::MD5,
                Digest::SHA256,
                Digest::SHA512,
                Digest::RMD160
            ]
        );
    }

    #[test]
    fn parse_default_digests() {
        let cli = vec!["checksum"];
        let config = Config::new(cli.iter());
        assert!(config.is_ok());
        let config = config.unwrap();

        assert_eq!(config.cmd, "checksum");
        assert_eq!(config.help, false);
        assert_eq!(config.paths.len(), 0);
        assert_eq!(
            config.digests,
            vec![Digest::MD5, Digest::SHA256, Digest::SHA512, Digest::RMD160]
        );
    }

    #[test]
    fn parse_filenames() {
        let cli = vec!["checksum", "some", "files"];
        let config = Config::new(cli.iter());
        assert!(config.is_ok());
        let config = config.unwrap();

        assert_eq!(config.cmd, "checksum");
        assert_eq!(config.help, false);
        assert_eq!(
            config.digests,
            vec![Digest::MD5, Digest::SHA256, Digest::SHA512, Digest::RMD160]
        );
        assert_eq!(
            config.paths,
            vec![path::PathBuf::from("some"), path::PathBuf::from("files")]
        );
    }

    #[test]
    fn use_stdin() {
        let cli = vec!["checksum", "file"];
        let config = Config::new(cli.iter());
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(!config.use_stdin());

        let cli = vec!["checksum"];
        let config = Config::new(cli.iter());
        assert!(config.is_ok());
        let config = config.unwrap();
        assert!(config.use_stdin());
    }

    #[test]
    fn parse_invalid_option() {
        let cli = vec!["checksum", "--foo"];
        let config = Config::new(cli.iter());
        let error = config.err();
        let expected = Error::InvalidOption(String::from("--foo"));
        assert_eq!(error, Some(expected));
    }

    #[test]
    fn parse_duplicate_digest() {
        let cli = vec!["checksum", "--md5", "--md5"];
        let config = Config::new(cli.iter());
        let error = config.err();
        let expected = Error::DuplicateOption(String::from("--md5"));
        assert_eq!(error, Some(expected));
    }

    #[test]
    fn format_error() {
        let error = Error::InvalidOption(String::from("--foo"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "invalid option '--foo'");

        let error = Error::DuplicateOption(String::from("--crc32"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--crc32'");

        let error = Error::DuplicateOption(String::from("--md5"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--md5'");

        let error = Error::DuplicateOption(String::from("--sha256"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--sha256'");

        let error = Error::DuplicateOption(String::from("--sha512"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--sha512'");

        let error = Error::DuplicateOption(String::from("--rmd160"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--rmd160'");
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
}
