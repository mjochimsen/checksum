use std::env::args;
use std::fs;

mod config;

use config::Config;
use std::process::exit;

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
        let path = std::path::Path::new(&filename);

        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_error) => {
                let error = format!("unable to get metadata for {}", filename);
                return Err(error);
            },
        };

        let size = metadata.len();

        println!("SIZE({}): {}", filename, size);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run;
    use config::Config;

    #[test]
    fn fake_run() {
        let config = Config::new(vec!("Cargo.toml", "src/main.rs").iter());
        assert_eq!(run(config), Ok(()));
    }
}
