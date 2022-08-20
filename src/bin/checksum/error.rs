use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidOption(String),
    FileOpen(PathBuf),
    FileRead(PathBuf),
    StdinRead,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidOption(option) => {
                write!(f, "invalid option '{}'", option)
            }
            Error::FileOpen(path) => {
                let pathstr = path.to_str().unwrap();
                write!(f, "unable to open '{}'", pathstr)
            }
            Error::FileRead(path) => {
                let pathstr = path.to_str().unwrap();
                write!(f, "unable to read from '{}'", pathstr)
            }
            Error::StdinRead => write!(f, "unable to read from stdin"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_error() {
        let error = Error::InvalidOption(String::from("--foo"));
        assert_eq!(format!("{}", error), "invalid option '--foo'");
        let error = Error::FileOpen(PathBuf::from("foo"));
        assert_eq!(format!("{}", error), "unable to open 'foo'");
        let error = Error::FileRead(PathBuf::from("foo"));
        assert_eq!(format!("{}", error), "unable to read from 'foo'");
        let error = Error::StdinRead;
        assert_eq!(format!("{}", error), "unable to read from stdin");
    }
}
