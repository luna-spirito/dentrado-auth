//! The CLI (the `auth` binary, the wg convention): root genkey → root
//! pubkey (phrase on stdin) → signer new --origin (phrase on stdin, a
//! SECRET bundle on stdout) → signer verify (bundle on stdin) → serve
//! negatives (a wide bundle mode / a garbage bundle / a pepper inside
//! the state dir / a non-32-byte pepper). `init` does not exist — the boot is declarative.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "auth-cli-{}-{}-{tag}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn set_mode(p: &PathBuf, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(p).unwrap().permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(p, perms).unwrap();
}

/// Run the binary feeding bytes to stdin (an empty slice just closes
/// stdin). stdout — RAW bytes (the bundle is binary); stderr — text.
fn run_raw(args: &[&str], stdin: &[u8]) -> (bool, Vec<u8>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_auth"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn auth binary");
    let mut child_stdin = child.stdin.take().expect("stdin");
    if !stdin.is_empty() {
        child_stdin.write_all(stdin).expect("feed stdin");
    }
    drop(child_stdin);
    let out = child.wait_with_output().expect("wait");
    (
        out.status.success(),
        out.stdout,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn serve_args(state: &Path, bundle: &Path, pepper: &Path) -> Vec<String> {
    vec![
        "serve".into(),
        "--dir".into(),
        state.to_string_lossy().into_owned(),
        "--bundle".into(),
        bundle.to_string_lossy().into_owned(),
        "--pepper".into(),
        pepper.to_string_lossy().into_owned(),
    ]
}

fn is_id_of(stderr: &str) -> String {
    stderr
        .lines()
        .find(|l| l.contains("is_id"))
        .expect("is_id hint on stderr")
        .split_whitespace()
        .last()
        .expect("hex tail")
        .to_string()
}

/// is_id from the serve boot line ("… (is_id <64 hex>) listening …").
fn is_id_of_serve_line(line: &str) -> String {
    let rest = line.split("is_id ").nth(1).expect("is_id in boot line");
    let hex: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    assert_eq!(hex.len(), 64, "boot line carries is_id: {line}");
    hex
}

#[test]
fn root_genkey_pubkey_signer_new_verify_and_tamper() {
    // root genkey: stdout — exactly 24 words (the phrase is the key),
    // no files; the is_id hint on stderr
    let (ok, stdout, stderr) = run_raw(&["root", "genkey"], b"");
    assert!(ok, "root genkey failed: {stderr}");
    let phrase = String::from_utf8(stdout).expect("the phrase is text");
    assert_eq!(
        phrase.split_whitespace().count(),
        24,
        "stdout is the phrase"
    );
    let is_id = is_id_of(&stderr);
    assert_eq!(is_id.len(), 64);

    // root pubkey: the phrase on stdin → the same is_id; a typo — refused
    let (ok, stdout, _) = run_raw(&["root", "pubkey"], phrase.trim().as_bytes());
    assert!(ok, "root pubkey failed");
    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        is_id,
        "pubkey is a pure function of the phrase"
    );
    let (ok, _, stderr) = run_raw(
        &["root", "pubkey"],
        format!("{}zoo", "abandon ".repeat(23)).as_bytes(),
    );
    assert!(!ok, "corrupt phrase must be rejected");
    assert!(stderr.contains("checksum"));

    // signer new WITHOUT --origin: no contract (usage, exit 2)
    let (ok, _, stderr) = run_raw(&["signer", "new"], phrase.trim().as_bytes());
    assert!(!ok, "signer new must require --origin");
    assert!(stderr.contains("--origin"), "got: {stderr}");

    // signer new --origin: the phrase on stdin; stdout — the SECRET
    // bundle (binary); the shell puts it on disk under umask 077
    let (ok, stdout, stderr) = run_raw(
        &["signer", "new", "--origin", "https://cli.test"],
        phrase.trim().as_bytes(),
    );
    assert!(ok, "signer new failed: {stderr}");
    assert!(
        stdout.len() > 32,
        "stdout is the bundle [signer seed + root-signed header]"
    );
    assert_eq!(is_id_of(&stderr), is_id, "is_id on stderr");
    assert!(stderr.contains("https://cli.test"), "origin on stderr");

    // verify: the bundle on stdin; the origin in the digest
    let (ok, _, stderr) = run_raw(&["signer", "verify"], &stdout);
    assert!(ok, "signer verify failed: {stderr}");
    assert!(stderr.contains("https://cli.test"), "got: {stderr}");

    // a tampered bundle (the last byte is the header's root signature)
    let mut tampered = stdout.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    let (ok, _, _) = run_raw(&["signer", "verify"], &tampered);
    assert!(!ok, "signer verify must fail on a tampered bundle");

    // a second bundle from the same phrase: shared is_id, a fresh key
    let (ok, stdout2, stderr2) = run_raw(
        &["signer", "new", "--origin", "https://cli2.test"],
        phrase.trim().as_bytes(),
    );
    assert!(ok, "second signer failed: {stderr2}");
    assert_eq!(is_id_of(&stderr2), is_id, "one root — one is_id");
    assert_ne!(stdout, stdout2, "fresh signer seed per bundle");
}

#[test]
fn boot_contract_is_serve_only() {
    // init does not exist — the boot is declarative: serve only
    let (ok, _, stderr) = run_raw(&["init"], b"");
    assert!(!ok, "init must be gone");
    assert!(stderr.contains("usage"), "got: {stderr}");
}

#[test]
fn serve_boot_negatives() {
    let (ok, phrase, stderr) = run_raw(&["root", "genkey"], b"");
    assert!(ok, "root genkey failed: {stderr}");
    let phrase = String::from_utf8(phrase).expect("text");
    let (ok, bundle_bytes, stderr) = run_raw(
        &["signer", "new", "--origin", "https://serve-cli.test"],
        phrase.trim().as_bytes(),
    );
    assert!(ok, "signer new failed: {stderr}");

    let state = tmpdir("state");
    let keys = tmpdir("keys");
    let pepper = keys.join("pepper.bin");
    let bundle = keys.join("signer.bin");

    // serve without --bundle: no contract (usage, exit 2)
    let mut args = serve_args(&state, &bundle, &pepper);
    let bundle_pos = args.iter().position(|a| a == "--bundle").unwrap();
    args.remove(bundle_pos);
    args.remove(bundle_pos);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, stderr) = run_raw(&arg_refs, b"");
    assert!(!ok, "serve must require --bundle");
    assert!(stderr.contains("--bundle"), "got: {stderr}");

    // a 0644 bundle (a shell without umask 077) — serve refuses at boot
    std::fs::write(&bundle, &bundle_bytes).unwrap();
    set_mode(&bundle, 0o644);
    let args = serve_args(&state, &bundle, &pepper);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, stderr) = run_raw(&arg_refs, b"");
    assert!(!ok, "serve must refuse a world-readable bundle");
    assert!(stderr.contains("0400/0600"), "got: {stderr}");

    // junk instead of the bundle (an honest 0400 mode) — parsing refuses;
    // write while the file is still writable, then narrow the mode
    std::fs::write(&bundle, [0xABu8; 100]).unwrap();
    set_mode(&bundle, 0o400);
    let args = serve_args(&state, &bundle, &pepper);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, stderr) = run_raw(&arg_refs, b"");
    assert!(!ok, "serve must refuse a garbage bundle");
    assert!(
        stderr.contains("bad header wire") || stderr.contains("not a bundle"),
        "got: {stderr}"
    );

    // an honest bundle + a pepper INSIDE the state dir — the contract is broken
    set_mode(&bundle, 0o600); // back to writable (after the 0400 negative)
    std::fs::write(&bundle, &bundle_bytes).unwrap();
    set_mode(&bundle, 0o400);
    let pepper_in = state.join("pepper.bin");
    let args = serve_args(&state, &bundle, &pepper_in);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, stderr) = run_raw(&arg_refs, b"");
    assert!(!ok, "serve must refuse a pepper inside the state dir");
    assert!(stderr.contains("outside the state dir"), "got: {stderr}");

    // an honest bundle + a broken pepper (not 32 bytes) — the vault load
    // refuses. (The pepper may have been auto-created by an earlier serve run —
    // 0400; restore write permission before writing.)
    if pepper.exists() {
        set_mode(&pepper, 0o600);
    }
    std::fs::write(&pepper, b"short").unwrap();
    set_mode(&pepper, 0o400);
    let args = serve_args(&state, &bundle, &pepper);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, stderr) = run_raw(&arg_refs, b"");
    assert!(!ok, "serve must refuse a wrong-size pepper");
    assert!(stderr.contains("32 bytes"), "got: {stderr}");

    // and a wide-mode pepper — refused too
    set_mode(&pepper, 0o600); // back to writable
    std::fs::write(&pepper, [7u8; 32]).unwrap();
    set_mode(&pepper, 0o644);
    let args = serve_args(&state, &bundle, &pepper);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let (ok, _, stderr) = run_raw(&arg_refs, b"");
    assert!(!ok, "serve must refuse a world-readable pepper");
    assert!(stderr.contains("0400/0600"), "got: {stderr}");

    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&keys);
}

#[test]
fn serve_boots_and_serves_keys_doc() {
    let (ok, phrase, stderr) = run_raw(&["root", "genkey"], b"");
    assert!(ok, "root genkey failed: {stderr}");
    let phrase = String::from_utf8(phrase).expect("text");
    let (ok, bundle_bytes, stderr) = run_raw(
        &["signer", "new", "--origin", "https://boot.test"],
        phrase.trim().as_bytes(),
    );
    assert!(ok, "signer new failed: {stderr}");

    let state = tmpdir("state2");
    let keys = tmpdir("keys2");
    let pepper = keys.join("pepper.bin");
    let bundle = keys.join("signer.bin");
    std::fs::write(&bundle, &bundle_bytes).unwrap();
    set_mode(&bundle, 0o400);
    std::fs::write(&pepper, [3u8; 32]).unwrap();
    set_mode(&pepper, 0o400);

    // serve boots (a port from the tmp range), /keys serves the is_id;
    // DENTRADO_PEPPER_FILE as an alternative to --pepper is exercised too
    let listen = format!("127.0.0.1:{}", 27000 + (std::process::id() % 2000) as u16);
    let mut child = Command::new(env!("CARGO_BIN_EXE_auth"))
        .args([
            "serve",
            "--dir",
            state.to_string_lossy().as_ref(),
            "--bundle",
            bundle.to_string_lossy().as_ref(),
            "--listen",
            &listen,
        ])
        .env("DENTRADO_PEPPER_FILE", &pepper)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");

    let stdout = child.stdout.take().unwrap();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();
    std::io::BufRead::read_line(&mut reader, &mut line).expect("boot line");
    let is_id = is_id_of_serve_line(&line);

    // GET /keys — the IS identity (the instances' trust line)
    let resp = std::net::TcpStream::connect(&listen)
        .map(|mut s| {
            use std::io::Read as _;
            s.write_all(b"GET /keys HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            buf
        })
        .expect("GET /keys");
    let text = String::from_utf8_lossy(&resp).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.contains(&is_id), "keys doc pins is_id: {text}");

    // GET / — statics: index.html is served
    let resp = std::net::TcpStream::connect(&listen)
        .map(|mut s| {
            use std::io::Read as _;
            s.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .unwrap();
            let mut buf = Vec::new();
            s.read_to_end(&mut buf).unwrap();
            buf
        })
        .expect("GET /");
    let text = String::from_utf8_lossy(&resp).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
    assert!(text.contains("Content-Type: text/html"), "{text}");

    child.kill().expect("kill serve");
    child.wait().expect("reap serve");
    let _ = std::fs::remove_dir_all(&state);
    let _ = std::fs::remove_dir_all(&keys);
}
