//! Edge: net (TCP, optionally TLS via rustls); parsing Req/Resp itself
//! — pure.
//!
//! Minimal HTTP/1.1 on std::net — thread per connection,
//! Connection: close, Content-Length only (no chunked), size limits.
//! TLS — in-process rustls (`--tls-cert/--tls-key`) so that no reverse
//! proxy stands in front of the service (its compromise = traffic
//! compromise); without the flags — plain HTTP for dev/localhost
//! (WebAuthn works on localhost without TLS too).
//!
//! Cookies/forms/urlencode are cut: the v7 API is JSON-only; sessions
//! are PoP headers (x-jti/x-ts/x-sig), not cookies.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 256 * 1024;
/// Cap on concurrently served connections: each is a thread; without a
/// cap a burst of accepts can exhaust threads and fds.
const MAX_CONNS: usize = 256;
/// Socket-level idle read/write timeout: a stuck peer must not pin a
/// thread forever.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Whole-request deadline (headers + body): a peer dribbling bytes
/// under the socket timeout is cut here.
const MAX_REQ_TIME: Duration = Duration::from_secs(30);

pub struct Req {
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// Headers, keys lowercased.
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Req {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(|s| s.as_str())
    }

    /// JSON body (browser WebAuthn responses, API calls).
    pub fn json(&self) -> Result<crate::codec::json::Json, String> {
        crate::codec::json::parse(&self.body)
    }
}

pub struct Resp {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
    /// Extra headers (Location, Cache-Control...).
    pub headers: Vec<(String, String)>,
}

impl Resp {
    pub fn text(body: String) -> Resp {
        Resp {
            status: 200,
            content_type: "text/plain; charset=utf-8".into(),
            body: body.into_bytes(),
            headers: Vec::new(),
        }
    }
    pub fn html(body: String) -> Resp {
        Resp {
            status: 200,
            content_type: "text/html; charset=utf-8".into(),
            body: body.into_bytes(),
            headers: Vec::new(),
        }
    }
    pub fn json(body: String) -> Resp {
        Resp {
            status: 200,
            content_type: "application/json".into(),
            body: body.into_bytes(),
            headers: Vec::new(),
        }
    }
    /// 303 See Other: redirect (authorize callback).
    pub fn redirect(location: &str) -> Resp {
        Resp {
            status: 303,
            content_type: "text/plain; charset=utf-8".into(),
            body: Vec::new(),
            headers: vec![("Location".into(), location.into())],
        }
    }
    pub fn err(status: u16, msg: String) -> Resp {
        Resp {
            status,
            content_type: "text/plain; charset=utf-8".into(),
            body: msg.into_bytes(),
            headers: Vec::new(),
        }
    }
    pub fn with_header(mut self, k: &str, v: impl Into<String>) -> Resp {
        self.headers.push((k.into(), v.into()));
        self
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        303 => "See Other",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "Error",
    }
}

fn write_resp<S: Write>(stream: &mut S, resp: &Resp) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        resp.status,
        reason(resp.status),
        resp.content_type,
        resp.body.len()
    );
    for (k, v) in &resp.headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

fn read_request<S: Read>(stream: &mut S) -> Result<Req, String> {
    let deadline = Instant::now() + MAX_REQ_TIME;
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 4096];
    // read until \r\n\r\n
    loop {
        if Instant::now() > deadline {
            return Err("request deadline".into());
        }
        if buf.len() > MAX_HEAD {
            return Err("headers too large".into());
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        let n = stream.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("eof before headers end".into());
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let head = String::from_utf8_lossy(&buf[..split]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err("bad request line".into());
    }
    let mut content_length = 0usize;
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().map_err(|_| "bad content-length")?;
            }
        }
    }
    if content_length > MAX_BODY {
        return Err("body too large".into());
    }
    // body: what's already read + fetch the rest
    let mut body = buf[split + 4..].to_vec();
    while body.len() < content_length {
        if Instant::now() > deadline {
            return Err("request deadline".into());
        }
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            return Err("eof in body".into());
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(content_length);
    let path = match target.split_once('?') {
        Some((p, _)) => p.to_string(),
        None => target,
    };
    Ok(Req {
        method,
        path,
        headers,
        body,
    })
}

// ---------------------------------------------------------------- TLS

/// PEM (cert chain + private key) → rustls server config. The crypto
/// provider is ring — as in kolorinko (the only non-pure-Rust piece
/// the policy allows); everything else stays pure Rust.
pub fn tls_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};
    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("tls cert pem: {e}"))?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|e| format!("tls key pem: {e}"))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("tls versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls cert/key mismatch: {e}"))?;
    Ok(Arc::new(cfg))
}

// ---------------------------------------------------------------- limits

/// A counting semaphore (std-only): caps concurrently served
/// connections. Acquire blocks until a slot frees; [`Permit`] releases
/// on drop (RAII — panic- and early-return-safe). A poisoned lock is
/// tolerated: the counter is monotone bookkeeping, not a security
/// boundary, so it survives a panicking handler thread.
struct Permits {
    free: Mutex<usize>,
    cv: Condvar,
}

struct Permit {
    permits: Arc<Permits>,
}

impl Permits {
    fn new(n: usize) -> Arc<Permits> {
        Arc::new(Permits {
            free: Mutex::new(n),
            cv: Condvar::new(),
        })
    }

    fn acquire(self: &Arc<Self>) -> Permit {
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        while *free == 0 {
            free = self.cv.wait(free).unwrap_or_else(|e| e.into_inner());
        }
        *free -= 1;
        Permit {
            permits: self.clone(),
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut free = self.permits.free.lock().unwrap_or_else(|e| e.into_inner());
        *free += 1;
        self.permits.cv.notify_one();
    }
}

/// Simple blocking server: a thread per connection, Connection: close.
/// `tls = Some` — HTTPS (rustls in-process), None — plain HTTP.
pub fn serve(
    listener: TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    handler: Arc<dyn Fn(&Req) -> Resp + Send + Sync>,
) -> ! {
    let permits = Permits::new(MAX_CONNS);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                // a stuck peer must not pin a thread (best effort)
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                // backpressure at accept: no slot — no thread
                let permit = permits.acquire();
                let handler = handler.clone();
                let tls = tls.clone();
                std::thread::spawn(move || {
                    let _permit = permit;
                    let resp = match tls {
                        None => serve_one(stream, &handler),
                        Some(cfg) => match rustls::ServerConnection::new(cfg) {
                            Ok(conn) => serve_one(rustls::StreamOwned::new(conn, stream), &handler),
                            Err(e) => Resp::err(500, format!("tls: {e}")),
                        },
                    };
                    let _ = resp;
                });
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn serve_one<S: Read + Write>(
    mut stream: S,
    handler: &Arc<dyn Fn(&Req) -> Resp + Send + Sync>,
) -> Resp {
    let resp = match read_request(&mut stream) {
        Ok(req) => handler(&req),
        Err(e) => Resp::err(400, e),
    };
    let _ = write_resp(&mut stream, &resp);
    resp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_parse_and_resp_write() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let body = br#"{"a":1}"#;
        let raw = format!(
            "POST /webauthn/login/finish?x=1 HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\nX-Jti: abc\r\n\r\n",
            body.len()
        );
        let t = std::thread::spawn(move || {
            use std::io::Write as _;
            a.write_all(raw.as_bytes()).unwrap();
            a.write_all(body).unwrap();
        });
        let req = read_request(&mut b).unwrap();
        t.join().unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/webauthn/login/finish");
        assert_eq!(req.header("x-jti"), Some("abc"));
        assert_eq!(req.header("X-JTI"), Some("abc"), "lowercased keys");
        assert_eq!(req.body, body.as_slice());
        assert!(req.json().is_ok());

        // truncated headers
        let (mut c, mut d) = std::os::unix::net::UnixStream::pair().unwrap();
        c.write_all(b"GET / HTTP/1.1\r\n").unwrap();
        drop(c);
        assert!(read_request(&mut d).is_err());

        // resp serialization
        let resp = Resp::json("{\"ok\":true}".into()).with_header("Cache-Control", "no-store");
        let bytes = {
            let mut w = Vec::new();
            write_resp(&mut w, &resp).unwrap();
            w
        };
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("Content-Type: application/json\r\n"));
        assert!(s.contains("Cache-Control: no-store\r\n"));
        assert!(s.ends_with("{\"ok\":true}"));
    }

    #[test]
    fn permits_cap_concurrency() {
        let p = Permits::new(1);
        let g1 = p.acquire(); // the only slot
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let _g = p.acquire(); // must block until g1 drops
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_err(),
            "second acquire must block while the slot is held"
        );
        drop(g1);
        t.join().unwrap();
        assert!(
            rx.try_recv().is_ok(),
            "acquire proceeds once a permit drops"
        );
    }

    #[test]
    fn body_limit() {
        let (mut a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let raw = format!(
            "POST /x HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let t = std::thread::spawn(move || {
            use std::io::Write as _;
            a.write_all(raw.as_bytes()).unwrap();
        });
        let err = match read_request(&mut b) {
            Err(e) => e,
            Ok(_) => panic!("oversized body must be rejected"),
        };
        t.join().unwrap();
        assert!(err.contains("too large"), "{err}");
    }
}
