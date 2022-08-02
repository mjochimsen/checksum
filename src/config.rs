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
    DuplicateDigest(Digest),
}

impl Config {
    pub fn help() -> &'static str {
        r#"usage: checksum [option]... [file]...
       checksum [--help|-h]

Compute checksums against a list of files. If no files are listed
then the checksum is computed against stdin. Possible checksums
include:

    --crc32     32 bit Cyclic Redundancy Check (CRC)
    --md5       MD5 Message Digest
    --sha256    256-bit Secure Hash Algorithm 2 (SHA-2)
    --sha512    512-bit Secure Hash Algorithm 2 (SHA-2)
    --rmd160    160-bit RACE Integrity Primitives Evaluation
                Message Digest (RIPEMD)

If no checksum option is supplied then a default set of '--md5
--sha256 --sha512 --rmd160' is used. The computed checksum is output
in the following format:

    [ALGORITHM] (filename) = [HEXDIGEST]

For example:

    MD5 (somefile) = d41d8cd98f00b204e9800998ecf8427e

Computing checksums on stdin will omit the filename from the output,
like this:

    MD5 = d41d8cd98f00b204e9800998ecf8427e

Using the '--help' or '-h' option will print this text.
"#
    }

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

        for arg in args.iter() {
            // Parse the argument.
            let arg = Argument::parse(arg);

            match arg {
                Argument::Help => {
                    // Set the help flag.
                    help = true
                }
                Argument::Digest(digest) => {
                    // Add the digest to list of digests. We don't
                    // permit the same digest to appear more than
                    // once. If it does, return an error.
                    if !digests.contains(&digest) {
                        digests.push(digest);
                    } else {
                        let error = Error::DuplicateDigest(digest);
                        return Err(error);
                    }
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
            digests,
            paths,
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
            Error::DuplicateDigest(digest) => {
                let digest_option = match digest {
                    Digest::CRC32 => "--crc32",
                    Digest::MD5 => "--md5",
                    Digest::SHA256 => "--sha256",
                    Digest::SHA512 => "--sha512",
                    Digest::RMD160 => "--rmd160",
                };
                write!(f, "duplicate digest option '{}'", digest_option)
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
        } else {
            if arg.starts_with("-") {
                Argument::Error(arg.clone())
            } else {
                Argument::Filename(arg.clone())
            }
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
        let expected = Error::DuplicateDigest(Digest::MD5);
        assert_eq!(error, Some(expected));
    }

    #[test]
    fn format_error() {
        let error = Error::InvalidOption(String::from("--foo"));
        let errstr = format!("{}", error);
        assert_eq!(errstr, "invalid option '--foo'");

        let error = Error::DuplicateDigest(Digest::CRC32);
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--crc32'");

        let error = Error::DuplicateDigest(Digest::MD5);
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--md5'");

        let error = Error::DuplicateDigest(Digest::SHA256);
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--sha256'");

        let error = Error::DuplicateDigest(Digest::SHA512);
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--sha512'");

        let error = Error::DuplicateDigest(Digest::RMD160);
        let errstr = format!("{}", error);
        assert_eq!(errstr, "duplicate digest option '--rmd160'");
    }

    #[test]
    fn help_text() {
        let help_text = Config::help();
        assert!(help_text.contains("--help"));
        assert!(help_text.contains("--crc32"));
        assert!(help_text.contains("--md5"));
        assert!(help_text.contains("--sha256"));
        assert!(help_text.contains("--sha512"));
        assert!(help_text.contains("--rmd160"));
    }
}
