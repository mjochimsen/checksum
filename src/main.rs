use std::env::args;

mod config;

fn main() {
    let config = config::Config::new(args());
    println!("Hello, config: {:?}", config);
}
