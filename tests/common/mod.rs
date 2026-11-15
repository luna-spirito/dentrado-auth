//! Shared by the integration tests:
//! - [`SynthAuth`] — a synthetic authenticator (a port of
//!   `legacy-tests/common`): honest ceremony responses with genuine
//!   signatures — the checks work at full strength. Lives in the tests
//!   so the `webauthn` module stays pure.
//! - [`SessionKey`] — a P-256 session key "as in the browser": WebCrypto
//!   ECDSA yields raw r‖s over SHA-256; the pubkey is 64B x‖y.
//! - [`TestEnv`] — boots an IS on a tempdir (bundle 0400 + pepper outside the state dir).

// each test crate includes the module whole, using its own subset
#![allow(dead_code)]

use auth::codec::cbor;
use auth::codec::json;
use auth::codec::json::Json;
use auth::crypto;
use auth::crypto::{PublicKey, SecretKey as EdSecret, Signature as EdSignature};
use auth::keys::{mnemonic, root, signer};
use auth::net::http::{Req, Resp};
use auth::server::route;
use auth::server::{Is, IsConfig};
use auth::storage::Vault;
use auth::wire::{self, Cert, Jti, Oneshot};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey as EsKey, VerifyingKey};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

pub const ORIGIN: &str = "https://auth.test";
/// RP ID — the host part of the origin (IsConfig derives it by default).
pub const RP: &str = "auth.test";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_AT: u8 = 0x40;

// ---------------------------------------------------------------- synth

/// A mini-authenticator: answers ceremonies honestly.
#[derive(Clone)]
pub struct SynthAuth {
    cred_id: Vec<u8>,
    cose: Vec<u8>,
    ed: Option<EdSecret>,
    es: Option<p256::ecdsa::SigningKey>,
}

impl SynthAuth {
    pub fn new_ed() -> SynthAuth {
        let sk = EdSecret::generate();
        // COSE OKP: {1:1, 3:-8, -1:6, -2:x}
        let mut cose = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
        cose.extend_from_slice(sk.public().bytes());
        SynthAuth {
            cred_id: crypto::random(16),
            cose,
            ed: Some(sk),
            es: None,
        }
    }

    pub fn new_es() -> SynthAuth {
        let mut seed;
        let sk = loop {
            seed = crypto::random_arr::<32>();
            if let Ok(k) = EsKey::from_bytes(&seed.into()) {
                break k;
            }
        };
        let xy = VerifyingKey::from(&sk)
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(); // 0x04 ‖ x ‖ y
        // COSE EC2: {1:2, 3:-7, -1:1, -2:x, -3:y}
        let mut cose = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
        cose.extend_from_slice(&xy[1..33]);
        cose.extend_from_slice(&[0x22, 0x58, 0x20]);
        cose.extend_from_slice(&xy[33..65]);
        SynthAuth {
            cred_id: crypto::random(16),
            cose,
            ed: None,
            es: Some(sk),
        }
    }

    pub fn cred_id(&self) -> &[u8] {
        &self.cred_id
    }

    pub fn cred_id_b64u(&self) -> String {
        crypto::b64u_encode(&self.cred_id)
    }

    fn client_data(
        &self,
        type_: &str,
        origin: &str,
        challenge: &str,
        cross_origin: bool,
    ) -> Vec<u8> {
        format!(
            concat!(
                "{{\"type\":{t},\"challenge\":{c},\"origin\":{o},",
                "\"crossOrigin\":{co}}}"
            ),
            t = json::quote(type_),
            c = json::quote(challenge),
            o = json::quote(origin),
            co = cross_origin,
        )
        .into_bytes()
    }

    fn auth_data(&self, rp_id: &str, flags: u8) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&crypto::sha256(rp_id.as_bytes()));
        ad.push(flags);
        ad.extend_from_slice(&7u32.to_be_bytes());
        ad
    }

    fn sign(&self, m: &[u8]) -> Vec<u8> {
        match (&self.ed, &self.es) {
            (Some(sk), _) => crypto::sign(sk, m).bytes().to_vec(),
            (_, Some(sk)) => {
                let sig: Signature = sk.sign(m);
                sig.to_der().as_bytes().to_vec()
            }
            _ => unreachable!(),
        }
    }

    /// navigator.credentials.create() response: {id, rawId, response:{…}}.
    pub fn attestation_json(&self, rp_id: &str, origin: &str, challenge: &str) -> String {
        let cd = self.client_data("webauthn.create", origin, challenge, false);
        let mut ad = self.auth_data(rp_id, FLAG_UP | FLAG_UV | FLAG_AT);
        ad.extend_from_slice(&[0u8; 16]); // aaguid
        ad.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&self.cred_id);
        ad.extend_from_slice(&self.cose);
        // attestationObject = CBOR {"fmt":"none","attStmt":{},"authData":ad}
        let mut ao = vec![0xa3];
        ao.extend_from_slice(&[0x63, b'f', b'm', b't', 0x64, b'n', b'o', b'n', b'e']);
        ao.extend_from_slice(&[0x67]);
        ao.extend_from_slice(b"attStmt");
        ao.push(0xa0);
        ao.extend_from_slice(&[0x68]);
        ao.extend_from_slice(b"authData");
        ao.extend(cbor::bytes(&ad));
        format!(
            concat!(
                "{{\"id\":\"{id}\",\"rawId\":\"{id}\",\"type\":\"public-key\",",
                "\"response\":{{\"clientDataJSON\":\"{cd}\",\"attestationObject\":\"{ao}\"}},",
                "\"clientExtensionResults\":{{}},\"authenticatorAttachment\":\"platform\"}}"
            ),
            id = self.cred_id_b64u(),
            cd = crypto::b64u_encode(&cd),
            ao = crypto::b64u_encode(&ao),
        )
    }

    /// navigator.credentials.get() response: {id, rawId, response:{…}}.
    pub fn assertion_json(&self, rp_id: &str, origin: &str, challenge: &str) -> String {
        self.assertion_json_with(rp_id, origin, challenge, FLAG_UP | FLAG_UV)
    }

    /// The same with explicit flags (the "no UV" negative).
    pub fn assertion_json_with(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &str,
        flags: u8,
    ) -> String {
        self.assertion_json_co(rp_id, origin, challenge, flags, false)
    }

    /// The cross-origin negative: `crossOrigin:true` (an iframe
    /// ceremony) — the server must refuse it even with a matching
    /// origin string.
    pub fn assertion_json_cross_origin(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &str,
    ) -> String {
        self.assertion_json_co(rp_id, origin, challenge, FLAG_UP | FLAG_UV, true)
    }

    fn assertion_json_co(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &str,
        flags: u8,
        cross_origin: bool,
    ) -> String {
        let cd = self.client_data("webauthn.get", origin, challenge, cross_origin);
        let ad = self.auth_data(rp_id, flags);
        let mut m = ad.clone();
        m.extend_from_slice(&crypto::sha256(&cd));
        format!(
            concat!(
                "{{\"id\":\"{id}\",\"rawId\":\"{id}\",\"type\":\"public-key\",",
                "\"response\":{{\"clientDataJSON\":\"{cd}\",\"authenticatorData\":\"{ad}\",",
                "\"signature\":\"{sig}\",\"userHandle\":\"{id}\"}},",
                "\"clientExtensionResults\":{{}},\"authenticatorAttachment\":\"platform\"}}"
            ),
            id = self.cred_id_b64u(),
            cd = crypto::b64u_encode(&cd),
            ad = crypto::b64u_encode(&ad),
            sig = crypto::b64u_encode(&self.sign(&m)),
        )
    }
}

// ---------------------------------------------------------------- session key

/// A client P-256 session key: raw r‖s over SHA-256 (like WebCrypto),
/// pubkey 64B x‖y — exactly what `crypto::verify_p256` expects.
pub struct SessionKey {
    sk: EsKey,
    pub pk: [u8; 64],
}

impl SessionKey {
    pub fn new() -> SessionKey {
        let mut seed;
        let sk = loop {
            seed = crypto::random_arr::<32>();
            if let Ok(k) = EsKey::from_bytes(&seed.into()) {
                break k;
            }
        };
        let xy = VerifyingKey::from(&sk)
            .to_sec1_point(false)
            .as_bytes()
            .to_vec();
        let mut pk = [0u8; 64];
        pk.copy_from_slice(&xy[1..65]);
        SessionKey { sk, pk }
    }

    /// Raw r‖s (64B).
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        let sig: Signature = self.sk.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.to_bytes().as_slice());
        out
    }

    /// b64u of a raw signature (the pop field format).
    pub fn sign(&self, msg: &[u8]) -> String {
        crypto::b64u_encode(&self.sign_raw(msg))
    }
}

impl Default for SessionKey {
    fn default() -> Self {
        SessionKey::new()
    }
}

// ---------------------------------------------------------------- env

/// Boots an IS on a tempdir: the bundle (root [root_seed] → signer
/// [signer_seed]) is 0400, the pepper sits nearby but outside the state dir. State in `dir`.
/// The handle is wrapped in an `Option`: redb holds an exclusive lock,
/// so a restart is `reboot()` (the old `Arc<Is>` dies BEFORE the new `Is::open`).
pub struct TestEnv {
    is: Option<Arc<Is>>,
    pub base: PathBuf,
    pub dir: PathBuf,
    pub bundle: PathBuf,
    pub pepper: PathBuf,
    pub root_seed: [u8; 32],
}

pub fn boot_cfg() -> IsConfig {
    // empty host/web_origin → derived from the bundle origin
    IsConfig {
        host: String::new(),
        web_origin: String::new(),
        ..Default::default()
    }
}

impl TestEnv {
    pub fn new(tag: &str) -> TestEnv {
        Self::with_cfg(tag, boot_cfg())
    }

    pub fn with_cfg(tag: &str, cfg: IsConfig) -> TestEnv {
        let base = std::env::temp_dir().join(format!(
            "auth-it-{}-{}-{tag}",
            std::process::id(),
            crypto::now()
        ));
        let dir = base.join("state");
        let keys = base.join("keys");
        std::fs::create_dir_all(&keys).unwrap();
        // public API only: the root is born inside keys::root, the
        // authorizer seed inside signer::issue (no test-side seeds)
        let root = root::generate();
        let root_seed = *root.bytes();
        let (signing, header) = signer::issue(&root, crypto::now(), ORIGIN).expect("signer issue");
        let bundle = keys.join("signer.bin");
        crypto::write_secret_0400(&bundle, &signer::bundle(&signing, &header)).unwrap();
        let pepper = keys.join("pepper.bin");
        crypto::write_secret_0400(&pepper, &crypto::random_arr::<32>()).unwrap();
        let vault = Vault::load(&pepper).unwrap();
        let is = Is::open(&dir, &bundle, cfg, vault).expect("Is::open");
        TestEnv {
            is: Some(is),
            base,
            dir,
            bundle,
            pepper,
            root_seed,
        }
    }

    /// The IS handle (an Arc clone).
    pub fn is(&self) -> Arc<Is> {
        self.is.as_ref().expect("IS is open").clone()
    }

    /// Restart: same state, bundle and pepper; the old handle closes
    /// before the new open (the redb lock).
    pub fn reboot(&mut self) {
        self.is = None;
        let vault = Vault::load(&self.pepper).unwrap();
        self.is = Some(Is::open(&self.dir, &self.bundle, boot_cfg(), vault).expect("Is::open"));
    }

    /// Open the state with ANOTHER pepper (the "pepper lost/foreign"
    /// negative): accounts become unlinkable.
    pub fn reboot_with_pepper(&mut self, pepper_bytes: &[u8; 32]) {
        self.is = None;
        let p2 = self.base.join("pepper-other.bin");
        crypto::write_secret_0400(&p2, pepper_bytes).unwrap();
        let vault = Vault::load(&p2).unwrap();
        self.is = Some(Is::open(&self.dir, &self.bundle, boot_cfg(), vault).expect("Is::open"));
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

// ---------------------------------------------------------------- http

pub fn req(method: &str, path: &str, body: &str) -> Req {
    Req {
        method: method.into(),
        path: path.into(),
        headers: HashMap::new(),
        body: body.as_bytes().to_vec(),
    }
}

pub fn get(path: &str) -> Req {
    req("GET", path, "")
}

pub fn resp_json(r: &Resp) -> Json {
    json::parse(&r.body).unwrap_or_else(|e| {
        panic!(
            "response is not json ({}): {} ({e})",
            r.status,
            String::from_utf8_lossy(&r.body)
        )
    })
}

pub fn jstr(j: &Json, k: &str) -> String {
    j.get(k)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("no string {k} in {j:?}"))
        .to_string()
}

pub fn jnum(j: &Json, k: &str) -> f64 {
    j.get(k)
        .and_then(Json::as_f64)
        .unwrap_or_else(|| panic!("no number {k}"))
}

/// Check an API error in full: the status and the {"error":…} text.
pub fn expect_err(r: &Resp, status: u16, needle: &str) {
    let body = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, status, "want {needle:?}, got: {body}");
    assert!(body.contains(needle), "want {needle:?}, got: {body}");
}

// ---------------------------------------------------------------- flows

/// A device: authenticator + session key + an issued cert.
pub struct Device {
    pub synth: SynthAuth,
    pub skey: SessionKey,
    pub cert: Cert,
    pub jti: Jti,
}

impl Device {
    pub fn account_pk(&self) -> PublicKey {
        self.cert.account_pk
    }
    pub fn identity(&self) -> String {
        self.cert.identity()
    }
}

/// Merge {challenge, session_pk, pop} with the authenticator response —
/// the finish request body.
pub fn with_finish(kind: &str, ch: &str, skey: &SessionKey, auth_json: &str) -> String {
    let pop = skey.sign(&wire::msg_pop(kind, ch, &skey.pk));
    format!(
        "{{\"challenge\":{},\"session_pk\":{},\"pop\":{},{}",
        json::quote(ch),
        json::quote(&crypto::b64u_encode(&skey.pk)),
        json::quote(&pop),
        &auth_json[1..]
    )
}

/// A finish body for ceremonies without an authenticator response
/// (connect enrollment): just the PoP over the challenge.
pub fn with_pop(kind: &str, ch: &str, skey: &SessionKey) -> String {
    let pop = skey.sign(&wire::msg_pop(kind, ch, &skey.pk));
    format!(
        "{{\"challenge\":{},\"session_pk\":{},\"pop\":{}}}",
        json::quote(ch),
        json::quote(&crypto::b64u_encode(&skey.pk)),
        json::quote(&pop)
    )
}

fn device_of(synth: SynthAuth, skey: SessionKey, r: &Resp) -> Device {
    let j = resp_json(r);
    let cert = Cert::decode(&crypto::b64u_decode(&jstr(&j, "cert")).unwrap()).unwrap();
    let jti = Jti::from_bytes(
        crypto::b64u_decode(&jstr(&j, "jti"))
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap(),
    );
    Device {
        synth,
        skey,
        cert,
        jti,
    }
}

/// Register a new account (through the HTTP layer).
pub fn register(env: &TestEnv, synth: SynthAuth, skey: SessionKey) -> Device {
    register_on(&env.is(), synth, skey)
}

pub fn register_on(is: &Arc<Is>, synth: SynthAuth, skey: SessionKey) -> Device {
    let r = route::route(is, &req("POST", "/webauthn/register/begin", "{}"));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json(RP, ORIGIN, &ch),
    );
    let r = route::route(is, &req("POST", "/webauthn/register/finish", &body));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    device_of(synth, skey, &r)
}

/// Login with an existing authenticator (a new session key).
pub fn login(env: &TestEnv, synth: &SynthAuth, skey: SessionKey) -> Device {
    login_on(&env.is(), synth, skey)
}

pub fn login_on(is: &Arc<Is>, synth: &SynthAuth, skey: SessionKey) -> Device {
    let r = route::route(is, &req("POST", "/webauthn/login/begin", "{}"));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &synth.assertion_json(RP, ORIGIN, &ch),
    );
    let r = route::route(is, &req("POST", "/webauthn/login/finish", &body));
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    device_of(synth.clone(), skey, &r)
}

/// A PoP request from a device (x-jti/x-ts/x-sig over path+ts+body).
pub fn authed_req(env: &TestEnv, dev: &Device, path: &str, body: &str) -> Resp {
    authed_req_on(&env.is(), dev, path, body)
}

pub fn authed_req_on(is: &Arc<Is>, dev: &Device, path: &str, body: &str) -> Resp {
    let ts = crypto::now();
    let sig = dev
        .skey
        .sign(&wire::msg_request("POST", path, ts, body.as_bytes()));
    let mut r = req("POST", path, body);
    r.headers
        .insert("x-jti".into(), crypto::b64u_encode(dev.jti.bytes()));
    r.headers.insert("x-ts".into(), ts.to_string());
    r.headers.insert("x-sig".into(), sig);
    route::route(is, &r)
}

/// Cred ids from a cert-flow response's account doc.
pub fn cred_ids(doc: &Json) -> Vec<String> {
    doc.get("creds")
        .and_then(Json::as_arr)
        .map(|a| a.iter().map(|c| jstr(c, "id")).collect::<Vec<_>>())
        .unwrap_or_default()
}

/// An Oneshot the way the frontend assembles it: the server attestation
/// + the instance nonce + the session key's signature.
pub fn oneshot_of(dev: &Device, att_b: &[u8], nonce: &[u8; 32]) -> Oneshot {
    Oneshot {
        attestation: wire::Attestation::decode(att_b).unwrap(),
        nonce: *nonce,
        session_sig: EdSignature::from_bytes(&dev.skey.sign_raw(&Oneshot::msg(att_b, nonce))),
    }
}

/// A random instance nonce.
pub fn nonce() -> [u8; 32] {
    crypto::random_arr::<32>()
}

/// The 12-word code from a /connect/finish response — valid as a mnemonic.
pub fn words_of(r: &Resp) -> String {
    let j = resp_json(r);
    let w = jstr(&j, "words");
    assert_eq!(w.split_whitespace().count(), 12, "12-word code: {w}");
    mnemonic::decode128(&w).expect("code decodes");
    w
}
