use std::env::args;

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

fn run(config: Config) -> Result<(), &'static str> {
    println!("checksum config: {:?}", config);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::run;
    use config::Config;

    #[test]
    fn fake_run() {
        let config = Config::new(vec!("a", "list", "of", "files").iter());
        assert_eq!(run(config), Ok(()));
    }
}
