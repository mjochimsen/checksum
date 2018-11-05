use std::path;
use std::process;

fn main() {
    match openssl_path() {
        Some(path) => {
            println!("cargo:rustc-link-search={}", &path.display());
        }
        None => {
            eprintln!("{}", "Unable to locate static OpenSSL library");
            process::exit(1)
        }
    }
}

fn openssl_path() -> Option<path::PathBuf> {
    // Find the first entry in the list of library paths containing
    // the OpenSSL libs.
    for path in openssl_lib_paths() {
        if has_openssl_lib(&path) {
            return Some(path);
        }
    }
    None
}

fn has_openssl_lib(lib_path: &path::PathBuf) -> bool {
    // Check to see if the given library path has 'libcrypto.a' in it.
    let crypto_path = path::PathBuf::from(lib_path)
        .join("libcrypto.a");

    match std::fs::metadata(&crypto_path) {
        Ok(metadata) => {
            if metadata.is_file() {
                true
            } else {
                false
            }
        }
        Err(_) => false
    }
}

fn openssl_lib_paths() -> Vec<path::PathBuf> {
    if cfg!(unix) {
        // On Unix OpenSSL is generally in /opt/local/lib, /usr/local/lib,
        // /opt/lib, /usr/lib, or /lib. We'll search them in this order.
        let mut paths = vec![
            path::PathBuf::from("/opt/local/lib"),
            path::PathBuf::from("/usr/local/lib"),
            path::PathBuf::from("/opt/lib"),
            path::PathBuf::from("/usr/lib"),
            path::PathBuf::from("/lib"),
        ];
        if cfg!(target_os = "macos") {
            // If we're on MacOS, check for a Homebrew install, and
            // prefix it to the list of possible paths if we find it.
            if let Some(brew_prefix) = brew_prefix() {
                let openssl_brew_lib = brew_prefix
                    .join("opt")
                    .join("openssl")
                    .join("lib");

                paths.insert(0, openssl_brew_lib);
            }
        }
        paths
    } else {
        // Location of OpenSSL on Windows or any other OS family is
        // unknown.
        vec![]
    }
}

fn brew_prefix() -> Option<path::PathBuf> {
    // Attempt to get a prefix for a Homebrew installation on macOS.
    match process::Command::new("brew").arg("--prefix").output() {
        Ok(output) => {
            match String::from_utf8(output.stdout) {
                Ok(prefix) => {
                    let prefix = prefix.trim();
                    Some(path::PathBuf::from(prefix))
                }
                Err(_) => None
            }
        }
        Err(_) => None
    }
}
