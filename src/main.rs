//! The `auth` binary: CLI over the `auth::` library.
//!
//! Roles:
//! - `auth root …`   — the offline root key (once per IS): seed-phrase,
//!   stored offline; NO "ceremony" wording, just a key;
//! - `auth signer …` — signer bundles under the root (any number);
//! - `auth serve`    — the identity service itself (WebAuthn login,
//!   certs, enroll codes, attestations); the bundle is fed at EVERY
//!   boot.
//!
//! The pepper lives OUTSIDE the state dir: --pepper or
//! DENTRADO_PEPPER_FILE, separate storage/volume.

#![forbid(unsafe_code)]

use auth::{
    crypto,
    keys::{mnemonic, root, signer},
    net::http,
    server::{Is, IsConfig},
    storage::Vault,
};
use std::path::PathBuf;

fn arg_value(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
    }
    None
}

fn need<'a>(args: &'a [String], name: &str) -> Result<&'a str, String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(|s| s.as_str())
        .ok_or(format!("missing required option {name}"))
}

fn usage() -> ! {
    eprintln!(
        "usage:
  auth root genkey
        (fresh offline root, ONCE per IS; wg genkey convention —
         stdout: the 24-word seed-phrase, the phrase IS the key;
         paper, safe; NO file is written; stderr: its is_id)
  auth root pubkey
        (stdin: the seed-phrase; stdout: root_pk = is_id — the
         instances' trust line; also the paper-vs-pinned cross-check)
  auth signer new --origin URL
        (stdin: the root seed-phrase; stdout: the SECRET bundle
         [signer seed + root-signed header] — redirect to a file under
         umask 077, no chmod window: (umask 077; … > signer.bin) — or
         pipe straight to the IS host; digest on stderr; is_id never
         changes while root lives. The signer key is ONE and forever:
         NO rotation, a re-issue is an incident procedure)
  auth signer verify
        (stdin: the bundle; cross-check)
  auth serve --dir DIR --bundle FILE --pepper FILE
        [--listen 127.0.0.1:7001] [--host HOST] [--web-origin URL]
        [--tls-cert PEM --tls-key PEM] [--bio-homeserver URL]
        [--cert-ttl SECS] [--att-ttl SECS]
        (the bundle is a PERMANENT server secret (0400/0600) fed at
         EVERY boot; state.redb is created automatically; the pepper
         path can also be set via DENTRADO_PEPPER_FILE; --tls-*
         enables in-process rustls HTTPS — without them plain HTTP
         for dev/localhost)"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        usage();
    }
    let rest = &args[1..];
    let code = match (args[0].as_str(), args[1].as_str()) {
        ("root", "genkey") => cmd_root_genkey(),
        ("root", "pubkey") => cmd_root_pubkey(),
        ("signer", "new") => cmd_signer_new(rest),
        ("signer", "verify") => cmd_signer_verify(),
        ("serve", _) => cmd_serve(rest),
        _ => usage(),
    };
    std::process::exit(code);
}

fn usage_err(e: &str) -> ! {
    eprintln!("error: {e}");
    usage();
}

fn opt_u64(args: &[String], name: &str, default: u64) -> Result<u64, String> {
    match arg_value(args, name) {
        Some(v) => v.parse().map_err(|_| format!("bad {name}: {v}")),
        None => Ok(default),
    }
}

// ------------------------------------------------------------- root / signer

/// The root seed phrase from stdin (not argv: shell history must not store secrets).
fn read_stdin_string(what: &str) -> Result<String, String> {
    use std::io::Read as _;
    let mut s = String::new();
    std::io::stdin()
        .read_to_string(&mut s)
        .map_err(|e| format!("reading {what}: {e}"))?;
    Ok(s)
}

/// Root generation (once per IS, `wg genkey` convention): stdout —
/// the seed phrase only (the phrase IS the secret); no files; is_id on
/// stderr. Rootkey compromise is a catastrophe, resolved by social
/// means (paper, safe; k-of-n later).
fn cmd_root_genkey() -> i32 {
    let sk = root::generate();
    eprintln!("root seed-phrase — THESE WORDS ARE THE ROOT KEY.");
    eprintln!("Nothing is written to disk: put the words on paper, store offline.");
    eprintln!(
        "is_id (pubkey, the instances' trust line): {}",
        crypto::hex(sk.public().bytes())
    );
    eprintln!(
        "NEXT: auth signer new --origin https://YOUR-IS > signer.bin  (paste the seed-phrase)"
    );
    println!("{}", mnemonic::encode(sk.bytes()));
    0
}

/// The pubkey as a pure function of the phrase (`wg pubkey` convention):
/// the paper-vs-pinned cross-check (the safe paper IS the root instances pin).
fn cmd_root_pubkey() -> i32 {
    let phrase = match read_stdin_string("seed-phrase") {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    match root::from_phrase(&phrase) {
        Ok(sk) => {
            println!("{}", crypto::hex(sk.public().bytes()));
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

/// Bundle issuance: the root secret comes only as the seed-phrase on
/// stdin; the signer key is always fresh. stdout — the SECRET bundle
/// ([signer seed + root-signed header]).
fn cmd_signer_new(args: &[String]) -> i32 {
    let origin = match arg_value(args, "--origin") {
        Some(o) => o,
        None => usage_err(
            "signer new needs --origin URL (the IS's HTTP(S) origin, e.g. https://auth.example)",
        ),
    };
    let root = match read_stdin_string("seed-phrase").and_then(|p| root::from_phrase(&p)) {
        Ok(sk) => sk,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let (signer_key, header) = match signer::issue(&root, crypto::now(), &origin) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    eprintln!("stdout: the signer bundle (binary, SECRET — signer seed + root-signed header)");
    eprintln!(
        "  is_id (root_pk, the trust line): {}",
        crypto::hex(header.is_id().bytes())
    );
    eprintln!("  signer key_id: {}", crypto::hex(&header.key_id()));
    eprintln!("  origin:  {}", header.origin);
    eprintln!();
    eprintln!("NEXT:");
    eprintln!("  1. (umask 077; auth signer new --origin URL > signer.bin) — the file is");
    eprintln!(
        "     born 0600, there is no window before chmod; then auth signer verify < signer.bin"
    );
    eprintln!("  2. get signer.bin to the IS host (scp, or a pipe without touching the disk:");
    eprintln!("     auth signer new --origin URL | ssh IS-HOST 'umask 077; cat > signer.bin').");
    eprintln!("     The bundle is a PERMANENT server secret (0400/0600):");
    eprintln!("     auth serve --dir DIR --bundle signer.bin --pepper FILE");
    eprintln!("     (serve refuses a bundle with a mode wider than 0400/0600)");
    eprintln!("  3. the instances' trust line never changes: auth root pubkey (same seed-phrase)");
    use std::io::Write as _;
    let mut out = std::io::stdout();
    if let Err(e) = out
        .write_all(&signer::bundle(&signer_key, &header))
        .and_then(|_| out.flush())
    {
        eprintln!("error: writing the bundle: {e}");
        return 1;
    }
    0
}

fn cmd_signer_verify() -> i32 {
    use std::io::Read as _;
    let mut b = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut b) {
        eprintln!("error: reading the bundle: {e}");
        return 1;
    }
    match signer::verify_bundle(&b) {
        Ok(info) => {
            eprintln!("signer bundle OK");
            eprintln!("  is_id (root_pk): {}", crypto::hex(info.is_id.bytes()));
            eprintln!("  signer key_id: {}", crypto::hex(&info.key_id));
            eprintln!("  origin:  {}", info.origin);
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    }
}

// ------------------------------------------------------------- serve

fn cmd_serve(args: &[String]) -> i32 {
    let dir = need(args, "--dir")
        .unwrap_or_else(|e| usage_err(&e))
        .to_string();
    let bundle = need(args, "--bundle")
        .unwrap_or_else(|e| usage_err(&e))
        .to_string();
    let pepper_path = arg_value(args, "--pepper")
        .or_else(|| std::env::var("DENTRADO_PEPPER_FILE").ok())
        .unwrap_or_else(|| usage_err("missing --pepper FILE (or DENTRADO_PEPPER_FILE)"));
    let pepper_path = PathBuf::from(&pepper_path);
    if pepper_path.starts_with(&dir) {
        eprintln!("error: the pepper must live outside the state dir (no pepper on the IS disk)");
        return 1;
    }
    // declarative boot: a missing pepper is created (first start);
    // the rest of the state files are created by Storage::open
    if !pepper_path.exists() {
        match crypto::write_secret_0400(&pepper_path, &crypto::random_arr::<32>()) {
            Ok(()) => eprintln!(
                "pepper: created {} (NEW — if this is NOT a first boot, the real pepper \
                 is missing: STOP the server and restore it, or every account becomes unlinkable)",
                pepper_path.display()
            ),
            Err(e) => {
                eprintln!("error: {}: {e}", pepper_path.display());
                return 1;
            }
        }
    }
    let vault = match Vault::load(&pepper_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let tls = match (arg_value(args, "--tls-cert"), arg_value(args, "--tls-key")) {
        (None, None) => None,
        (Some(c), Some(k)) => {
            // the TLS private key is a server secret, like the bundle:
            // the mode must say so before it is read
            if !crypto::is_private_mode(std::path::Path::new(&k)) {
                eprintln!(
                    "error: {k} must have mode 0400/0600 (the TLS private key is a server secret)"
                );
                return 1;
            }
            let cert_pem = match std::fs::read(&c) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {c}: {e}");
                    return 1;
                }
            };
            let key_pem = match std::fs::read(&k) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: {k}: {e}");
                    return 1;
                }
            };
            match http::tls_config(&cert_pem, &key_pem) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 1;
                }
            }
        }
        _ => usage_err("--tls-cert and --tls-key go together"),
    };
    let cfg = IsConfig {
        host: arg_value(args, "--host").unwrap_or_default(),
        web_origin: arg_value(args, "--web-origin").unwrap_or_default(),
        cert_ttl: opt_u64(args, "--cert-ttl", 7 * 86400).unwrap_or_else(|e| usage_err(&e)),
        att_ttl: opt_u64(args, "--att-ttl", 300).unwrap_or_else(|e| usage_err(&e)),
        bio_default: arg_value(args, "--bio-homeserver"),
        ..Default::default()
    };
    let is = match Is::open(&PathBuf::from(&dir), &PathBuf::from(&bundle), cfg, vault) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: {e}");
            return 1;
        }
    };
    let listen = arg_value(args, "--listen").unwrap_or_else(|| "127.0.0.1:7001".into());
    let listener = match std::net::TcpListener::bind(&listen) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind {listen}: {e}");
            return 1;
        }
    };
    println!(
        "is {} (is_id {}) listening on {}://{}",
        is.cfg.host,
        crypto::hex(is.keys.is_id().bytes()),
        if tls.is_some() { "https" } else { "http" },
        listen
    );
    let h: std::sync::Arc<dyn Fn(&http::Req) -> http::Resp + Send + Sync> = {
        let is = is.clone();
        std::sync::Arc::new(move |req| auth::server::route::route(&is, req))
    };
    http::serve(listener, tls, h)
}
