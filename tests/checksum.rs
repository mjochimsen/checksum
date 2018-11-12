use std::path;
use std::process;
use std::io;

type Lines = Vec<String>;

#[test]
fn checksum_help() {
    let mut child = run_checksum(&["--help"], &[]);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 0);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert!(!lines.is_empty());
    let help_text = lines.join("\n");
    assert!(help_text.contains("checksum"));
    assert!(help_text.contains("--help"));
    assert!(help_text.contains("--crc32"));
    assert!(help_text.contains("--md5"));
    assert!(help_text.contains("--sha256"));
    assert!(help_text.contains("--sha512"));
    assert!(help_text.contains("--rmd160"));

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert!(lines.is_empty());
}

#[test]
fn checksum_stdin() {
    let mut child = run_checksum(&["--rmd160", "--md5", "--crc32"], &[]);

    let count = child_write(&mut child, &[0u8; 0x400d])
        .expect("error writing to checksum stdin");
    assert_eq!(count, 0x400d);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 0);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert_eq!(lines, [
        "RMD160 = 81e44bc5416e987e7cdba7c8cd2935ecf15bddcd",
        "MD5 = 96f64e179f777e6eda0caa2d879356c9",
        "CRC32 = 26a348bb",
    ]);

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert!(lines.is_empty());
}

#[test]
fn checksum_files() {
    let mut child = run_checksum(&["--rmd160", "--md5", "--crc32"],
                                 &["zero-11171", "random-11171"]);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 0);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert_eq!(lines, [
        "RMD160 (tests/data/zero-11171) = f2288b605a62a21a264abffdc1d036ec45ef1d6c",
        "MD5 (tests/data/zero-11171) = 41a22d1ee789decbfbd4924ec21e53c9",
        "CRC32 (tests/data/zero-11171) = 5dc1d8ba",
        "RMD160 (tests/data/random-11171) = cb4f956b435d16bf03bad5607ed2e06af9eefd7b",
        "MD5 (tests/data/random-11171) = ff8ae3cf944cdddea7191c906afe0c81",
        "CRC32 (tests/data/random-11171) = ff70a8ee",
    ]);

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert!(lines.is_empty());
}

#[test]
fn checksum_invalid_option() {
    let mut child = run_checksum(&["--foo"], &[]);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 1);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert!(lines.is_empty());

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("invalid"));
    assert!(lines[0].contains("--foo"));
}

#[test]
fn checksum_duplicate_digest() {
    let mut child = run_checksum(&["--md5", "--md5"], &[]);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 1);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert!(lines.is_empty());

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("duplicate"));
    assert!(lines[0].contains("--md5"));
}

#[test]
fn checksum_missing_file() {
    let mut child = run_checksum(&[], &["missing"]);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 1);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert!(lines.is_empty());

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("open"));
    assert!(lines[0].contains("missing"));
}

#[test]
fn checksum_missing_and_present_files() {
    let mut child = run_checksum(&["--rmd160", "--md5", "--crc32"],
                                 &["zero-0", "missing", "zero-400d"]);

    let status = child_run(&mut child)
        .expect("error running checksum subprocess");
    assert_eq!(status, 1);

    let lines = child_readlines(&mut child)
        .expect("error reading checksum stdout");
    assert_eq!(lines, [
        "RMD160 (tests/data/zero-0) = 9c1185a5c5e9fc54612808977ee8f548b2258d31",
        "MD5 (tests/data/zero-0) = d41d8cd98f00b204e9800998ecf8427e",
        "CRC32 (tests/data/zero-0) = 00000000",
        "RMD160 (tests/data/zero-400d) = 81e44bc5416e987e7cdba7c8cd2935ecf15bddcd",
        "MD5 (tests/data/zero-400d) = 96f64e179f777e6eda0caa2d879356c9",
        "CRC32 (tests/data/zero-400d) = 26a348bb",
    ]);

    let lines = child_errlines(&mut child)
        .expect("error reading checksum stderr");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("open"));
    assert!(lines[0].contains("missing"));
}

fn run_checksum(flags: &[&str], files: &[&str]) -> process::Child {
    use std::iter::FromIterator;
    let checksum_path =
        path::PathBuf::from_iter(&["target", "debug", "checksum"]);
    let mut cmd = process::Command::new(&checksum_path);
    cmd.args(flags);
    let paths = files.into_iter().map(|filename| {
        path::PathBuf::from_iter(&["tests", "data", filename])
    });
    cmd.args(paths);
    cmd.stdin(process::Stdio::piped());
    cmd.stdout(process::Stdio::piped());
    cmd.stderr(process::Stdio::piped());
    cmd.spawn().expect("Failed to spawn checksum")
}

fn child_write(child: &mut process::Child,
               data: &[u8]) -> io::Result<usize> {
    use io::Write;
    let stdin = match child.stdin.as_mut() {
        Some(stdin) => stdin,
        None => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
    };
    stdin.write(data)
}

fn child_run(child: &mut process::Child) -> io::Result<i32> {
    let status = child.wait()?;
    Ok(status.code().unwrap())
}

fn child_readlines(child: &mut process::Child) -> io::Result<Lines> {
    let stdout = match child.stdout.as_mut() {
        Some(stdout) => stdout,
        None => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
    };
    readlines(stdout)
}

fn child_errlines(child: &mut process::Child) -> io::Result<Lines> {
    let stderr = match child.stderr.as_mut() {
        Some(stderr) => stderr,
        None => return Err(io::Error::from(io::ErrorKind::BrokenPipe)),
    };
    readlines(stderr)
}

fn readlines<R: io::Read>(input: &mut R) -> io::Result<Lines> {
    let mut buffer = String::new();
    input.read_to_string(&mut buffer)?;
    let lines: Vec<String> = buffer.lines()
                                   .map(String::from)
                                   .collect();
    Ok(lines)
 }

