use std::path;
use std::process;

fn main() {
    if let Some(path) = openssl_path() {
        println!("cargo:rustc-link-search={}", &path.display());
    }
}

fn openssl_path() -> Option<path::PathBuf> {
    // Unixish operating systems will generally provide a correct path,
    // but MacOS may have the OpenSSL libs in the HomeBrew path, which
    // will need to be added.
    // We don't know how Windows should be handled.
    if cfg!(target_os = "macos") {
        if let Some(brew_prefix) = brew_prefix() {
            let openssl_brew_lib =
                brew_prefix.join("opt").join("openssl").join("lib");
            if has_openssl_lib(&openssl_brew_lib) {
                return Some(openssl_brew_lib);
            }
        }
    }
    None
}

fn has_openssl_lib(lib_path: &path::PathBuf) -> bool {
    // Check to see if the given library path has 'libcrypto.a' in it.
    let crypto_path = path::PathBuf::from(lib_path).join("libcrypto.a");

    match std::fs::metadata(&crypto_path) {
        Ok(metadata) => {
            if metadata.is_file() {
                true
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn brew_prefix() -> Option<path::PathBuf> {
    // Attempt to get a prefix for a Homebrew installation on macOS.
    match process::Command::new("brew").arg("--prefix").output() {
        Ok(output) => match String::from_utf8(output.stdout) {
            Ok(prefix) => {
                let prefix = prefix.trim();
                Some(path::PathBuf::from(prefix))
            }
            Err(_) => None,
        },
        Err(_) => None,
    }
}
