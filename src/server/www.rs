//! Static frontend (embedded at compile time): the shell lives in
//! `src/www/`. The frontend "lives its own life": the service worker
//! precaches the shell — the app opens offline; API requests
//! always hit the network. Cache strategy: the shell gets a no-cache header
//! (the SW cache tracks freshness by version); few statics, so no
//! hashed names are needed.

use super::Is;
use crate::net::http::{Req, Resp};

const INDEX: &[u8] = include_bytes!("../www/index.html");
const APP: &[u8] = include_bytes!("../www/app.js");
const SW: &[u8] = include_bytes!("../www/sw.js");
const STYLE: &[u8] = include_bytes!("../www/style.css");
const ICONS: &[u8] = include_bytes!("../www/icons.svg");
const LOGO: &[u8] = include_bytes!("../www/logo.svg");

pub fn route(_is: &Is, req: &Req) -> Resp {
    if req.method != "GET" {
        return Resp::err(405, "method not allowed".into());
    }
    match req.path.as_str() {
        "/" | "/index.html" => file(INDEX, "text/html; charset=utf-8"),
        "/app.js" => file(APP, "text/javascript; charset=utf-8"),
        "/sw.js" => file(SW, "text/javascript; charset=utf-8"),
        "/style.css" => file(STYLE, "text/css; charset=utf-8"),
        "/icons.svg" => file(ICONS, "image/svg+xml"),
        "/logo.svg" => file(LOGO, "image/svg+xml"),
        _ => Resp::err(404, "not found".into()),
    }
}

fn file(b: &'static [u8], ct: &str) -> Resp {
    Resp {
        status: 200,
        content_type: ct.into(),
        body: b.to_vec(),
        headers: vec![
            ("Cache-Control".into(), "no-cache".into()),
            // The consent screen must never be framed (clickjacking),
            // and URLs (nonce/aud/callback) must not leak via Referer.
            (
                "Content-Security-Policy".into(),
                "frame-ancestors 'none'; base-uri 'none'".into(),
            ),
            ("X-Frame-Options".into(), "DENY".into()),
            ("Referrer-Policy".into(), "no-referrer".into()),
        ],
    }
}
