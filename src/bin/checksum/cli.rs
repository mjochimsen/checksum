use std::ffi::OsString;
use std::path::PathBuf;

use crate::{DigestKind as Kind, Error};

/// A structure describing command line parameters.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub struct CLI {
    /// The `--help` (`-h`) flag was set.
    pub help: bool,
    /// The `--version` (`-V`) flag was set.
    pub version: bool,
    /// The list of the digests to compute.
    pub digests: Vec<Kind>,
    /// The filenames to compute the digests for.
    pub paths: Vec<PathBuf>,
}

impl CLI {
    pub const USAGE: &'static str = include_str!("usage.txt");

    /// Parse a set of command line parameters into a `CLI` structure.
    /// Duplicate options are ignored. If no digest options are provided,
    /// then a default set of `--md5`, `--sha256`, `--sha512`, and
    /// `--rmd160` are used.
    ///
    /// ## Errors
    ///
    /// If an unknown option is provided then an `Error::InvalidOption` is
    /// returned with the offending option.
    pub fn parse<I, A>(args: I) -> Result<Self, Error>
    where
        I: IntoIterator<Item = A>,
        A: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into);
        let mut help = false;
        let mut version = false;
        let mut digests = Vec::new();
        let mut paths = Vec::new();
        for os_arg in args {
            let arg = os_arg.to_string_lossy().to_string();
            match arg.as_str() {
                "--help" | "-h" => help = true,
                "--version" | "-V" => version = true,
                "--crc32" => {
                    if !digests.contains(&Kind::CRC32) {
                        digests.push(Kind::CRC32);
                    }
                }
                "--md5" => {
                    if !digests.contains(&Kind::MD5) {
                        digests.push(Kind::MD5);
                    }
                }
                "--sha256" => {
                    if !digests.contains(&Kind::SHA256) {
                        digests.push(Kind::SHA256);
                    }
                }
                "--sha512" => {
                    if !digests.contains(&Kind::SHA512) {
                        digests.push(Kind::SHA512);
                    }
                }
                "--rmd160" => {
                    if !digests.contains(&Kind::RMD160) {
                        digests.push(Kind::RMD160);
                    }
                }
                arg if arg.starts_with('-') => {
                    return Err(Error::InvalidOption(arg.to_string()))
                }
                filename => paths.push(filename.into()),
            }
        }

        // If no digests were set, use a default set of MD5, SHA256,
        // SHA512, and RMD160.
        if digests.is_empty() && !help && !version {
            digests =
                vec![Kind::MD5, Kind::SHA256, Kind::SHA512, Kind::RMD160];
        }

        Ok(Self {
            help,
            version,
            digests,
            paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parse_help() {
        let cli = CLI::parse(&["--help"]).unwrap();
        assert!(cli.help);
        let cli = CLI::parse(&["-h"]).unwrap();
        assert!(cli.help);
    }

    #[test]
    fn parse_version() {
        let cli = CLI::parse(&["--version"]).unwrap();
        assert!(cli.version);
        let cli = CLI::parse(&["-V"]).unwrap();
        assert!(cli.version);
    }

    #[test]
    fn parse_digests() {
        let cli = CLI::parse(&["--crc32"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::CRC32]);
        let cli = CLI::parse(&["--md5"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::MD5]);
        let cli = CLI::parse(&["--sha256"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::SHA256]);
        let cli = CLI::parse(&["--sha512"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::SHA512]);
        let cli = CLI::parse(&["--rmd160"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::RMD160]);
    }

    #[test]
    fn parse_paths() {
        let cli = CLI::parse(&["foo", "bar"]).unwrap();
        assert_eq!(cli.paths, vec![Path::new("foo"), Path::new("bar")]);
    }

    #[test]
    fn parse_defaults() {
        let cli = CLI::parse(&[] as &[&str]).unwrap();
        assert!(!cli.help);
        assert!(!cli.version);
        assert_eq!(
            cli.digests,
            vec![Kind::MD5, Kind::SHA256, Kind::SHA512, Kind::RMD160]
        );
        assert!(cli.paths.is_empty());
    }

    #[test]
    fn parse_duplicate_digests() {
        let cli = CLI::parse(&["--crc32", "--crc32"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::CRC32]);
        let cli = CLI::parse(&["--md5", "--md5"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::MD5]);
        let cli = CLI::parse(&["--sha256", "--sha256"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::SHA256]);
        let cli = CLI::parse(&["--sha512", "--sha512"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::SHA512]);
        let cli = CLI::parse(&["--rmd160", "--rmd160"]).unwrap();
        assert_eq!(cli.digests, vec![Kind::RMD160]);
    }

    #[test]
    fn parse_invalid_option() {
        let err = CLI::parse(&["--foo"]).unwrap_err();
        assert_eq!(err, Error::InvalidOption("--foo".to_string()));
    }

    #[test]
    fn usage_text() {
        assert!(CLI::USAGE.contains("--help"));
        assert!(CLI::USAGE.contains("--version"));
        assert!(CLI::USAGE.contains("--crc32"));
        assert!(CLI::USAGE.contains("--md5"));
        assert!(CLI::USAGE.contains("--sha256"));
        assert!(CLI::USAGE.contains("--sha512"));
        assert!(CLI::USAGE.contains("--rmd160"));
    }
}
