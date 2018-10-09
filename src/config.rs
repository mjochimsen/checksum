#[derive(Debug)]
pub struct Config {
    pub files: Vec<String>,
}

impl Config {
    pub fn new<I: Iterator<Item = impl ToString>>(args: I) -> Config {
        // Skip the first arg; it's the command.
        // Collect the rest of the args into a list of filenames.
        let files = args.skip(1)
            .map(|filename| { filename.to_string() })
            .collect();

        Config { files }
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn create_new_config() {
        let args = vec!("a", "list", "of", "files");
        let config = Config::new(args.iter());
        assert_eq!(config.files, vec!("list", "of", "files"));
    }
}
