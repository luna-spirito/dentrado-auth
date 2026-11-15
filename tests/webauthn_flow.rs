//! The v7 WebAuthn flow on a synthetic authenticator: registration →
//! cert (PoP), login, cred management, bio homeserver, logout —
//! and negatives: foreign origin, replayed challenge, a swapped session
//! key, bad pop, login by an unknown cred, no UV, a broken signature.

mod common;

use auth::crypto;
use auth::server::IsConfig;
use common::*;
use std::thread::sleep;
use std::time::Duration;

#[test]
fn register_login_roundtrip() {
    let env = TestEnv::new("wa-roundtrip");
    let skey = SessionKey::new();
    let dev = register(&env, SynthAuth::new_es(), skey);

    // the cert: the bundle origin, 7 days, identity = @hex@origin
    assert_eq!(dev.cert.origin(), ORIGIN);
    assert_eq!(dev.cert.exp - dev.cert.iat, 7 * 86400);
    assert_eq!(dev.jti, dev.cert.jti);
    assert_eq!(dev.identity(), dev.cert.identity());
    assert!(dev.identity().starts_with('@'));

    // the PoP session works: an account read
    let r = authed_req(&env, &dev, "/account", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let doc = resp_json(&r);
    assert_eq!(cred_ids(&doc).len(), 1);

    // a second login — a new session key, the same account
    let dev2 = login(&env, &dev.synth, SessionKey::new());
    assert_eq!(dev2.account_pk(), dev.account_pk(), "same account");
    assert_ne!(dev2.jti, dev.jti, "fresh session per login");
    let r = authed_req(&env, &dev2, "/account", "{}");
    assert_eq!(r.status, 200);
}

#[test]
fn profile_handle_and_label_are_stable_across_passkeys() {
    let env = TestEnv::new("wa-profile-id");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();

    // Capture the options of the account-creating ceremony.
    let r = post(&env, "/webauthn/register/begin", "{\"name\":\"  Alice  \"}");
    let doc = resp_json(&r);
    let opts = doc.get("options").unwrap();
    let user = opts.get("user").unwrap();
    let uid = jstr(user, "id");
    let name = jstr(user, "name");
    assert_eq!(name, "Alice", "the chosen profile name is used verbatim");
    assert_eq!(
        jstr(opts.get("authenticatorSelection").unwrap(), "residentKey"),
        "required",
        "discoverable credential"
    );

    let ch = jstr(&doc, "challenge");
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let doc = resp_json(&r);
    let account = doc.get("account").unwrap();
    assert_eq!(jstr(account, "name"), "Alice");

    // A second passkey for the same account must keep the same user handle
    // and label, so the discoverable picker groups it with the first one.
    let dev = login(&env, &synth, SessionKey::new());
    let r = authed_req(&env, &dev, "/cred/add/begin", "{}");
    let doc = resp_json(&r);
    let user = doc.get("options").unwrap().get("user").unwrap();
    assert_eq!(jstr(user, "id"), uid);
    assert_eq!(jstr(user, "name"), name);
}

#[test]
fn profile_name_falls_back_and_is_validated() {
    let env = TestEnv::new("wa-profile-name");

    // No name → the stable readable fallback.
    let r = route_begin(&env, "/webauthn/register/begin");
    let doc = resp_json(&r);
    let name = jstr(doc.get("options").unwrap().get("user").unwrap(), "name");
    assert!(name.starts_with("Profile "), "fallback label: {name}");

    // Empty/whitespace also means the fallback.
    let r = post(&env, "/webauthn/register/begin", "{\"name\":\"   \"}");
    let doc = resp_json(&r);
    let name = jstr(doc.get("options").unwrap().get("user").unwrap(), "name");
    assert!(name.starts_with("Profile "), "fallback label: {name}");

    // Control characters and over-long names are refused.
    let r = post(&env, "/webauthn/register/begin", "{\"name\":\"a\\nb\"}");
    expect_err(&r, 400, "control characters");
    let long = "x".repeat(65);
    let r = post(
        &env,
        "/webauthn/register/begin",
        &format!("{{\"name\":\"{long}\"}}"),
    );
    expect_err(&r, 400, "at most 64 characters");
    let r = post(&env, "/webauthn/register/begin", "{\"name\":42}");
    expect_err(&r, 400, "string expected");
}

#[test]
fn restart_survives_accounts_and_sessions() {
    let mut env = TestEnv::new("wa-restart");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());

    // restart: same bundle + pepper — the state (accounts, sessions) lives
    env.reboot();
    let r = authed_req(&env, &dev, "/account", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // and a login by the same authenticator after the restart
    let dev2 = login(&env, &dev.synth, SessionKey::new());
    assert_eq!(dev2.account_pk(), dev.account_pk());
}

#[test]
fn wrong_pepper_makes_accounts_unlinkable() {
    let mut env = TestEnv::new("wa-pepper");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());

    // a foreign/lost pepper: the auth row is not found (a different HMAC) —
    // the account seems not to exist, NEW registrations live on
    env.reboot_with_pepper(&crypto::random_arr::<32>());
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &dev.synth.assertion_json(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/login/finish", &body);
    expect_err(&r, 400, "unknown credential");

    // a fresh registration under the new pepper works
    let dev2 = register(&env, SynthAuth::new_es(), SessionKey::new());
    let r = authed_req(&env, &dev2, "/account", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

#[test]
fn register_twice_same_cred_rejected() {
    let env = TestEnv::new("wa-dup");
    let synth = SynthAuth::new_es();
    let _ = register(&env, synth.clone(), SessionKey::new());

    // the same authenticator (the same cred_id) — refused
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r, 400, "credential already linked");
}

#[test]
fn register_foreign_origin_rejected() {
    let env = TestEnv::new("wa-origin");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json(RP, "https://evil.example", &ch),
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r, 400, "origin mismatch");
}

#[test]
fn register_foreign_rp_rejected() {
    let env = TestEnv::new("wa-rp");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json("other.example", ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r, 400, "rp");
}

#[test]
fn register_bad_pop_rejected() {
    let env = TestEnv::new("wa-badpop");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");

    // the pop is signed with a foreign kind — no binding to "register"
    let wrong_kind_pop = skey.sign(&auth::wire::msg_pop("login-pop", &ch, &skey.pk));
    let body = format!(
        "{{\"challenge\":{},\"session_pk\":{},\"pop\":{},{}",
        auth::codec::json::quote(&ch),
        auth::codec::json::quote(&crypto::b64u_encode(&skey.pk)),
        auth::codec::json::quote(&wrong_kind_pop),
        &synth.attestation_json(RP, ORIGIN, &ch)[1..]
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r, 400, "pop: signature mismatch");
}

#[test]
fn register_key_swap_rejected() {
    let env = TestEnv::new("wa-swap");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();
    let other = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");

    // session_pk swapped after begin: the pop is genuine but signed over
    // a DIFFERENT pk — the server verifies it against the body's pk and refuses
    let pop = skey.sign(&auth::wire::msg_pop("register-pop", &ch, &skey.pk));
    let body = format!(
        "{{\"challenge\":{},\"session_pk\":{},\"pop\":{},{}",
        auth::codec::json::quote(&ch),
        auth::codec::json::quote(&crypto::b64u_encode(&other.pk)),
        auth::codec::json::quote(&pop),
        &synth.attestation_json(RP, ORIGIN, &ch)[1..]
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r, 400, "pop: signature mismatch");
}

#[test]
fn register_replayed_challenge_rejected() {
    let env = TestEnv::new("wa-replay");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json(RP, ORIGIN, &ch),
    );
    // the pending is single-use: consumed by the first finish, a repeat is refused
    let _ = post(&env, "/webauthn/register/finish", &body);
    let r2 = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r2, 400, "unknown or expired challenge");
}

#[test]
fn register_unknown_challenge_rejected() {
    let env = TestEnv::new("wa-unknown-ch");
    let synth = SynthAuth::new_es();
    let skey = SessionKey::new();
    let ch = crypto::b64u_encode(&crypto::random_arr::<32>()); // never issued
    let body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &synth.attestation_json(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/register/finish", &body);
    expect_err(&r, 400, "unknown or expired challenge");
}

#[test]
fn login_unknown_cred_rejected() {
    let env = TestEnv::new("wa-unknown-cred");
    let rogue = SynthAuth::new_ed(); // never registered
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &rogue.assertion_json(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/login/finish", &body);
    expect_err(&r, 400, "unknown credential");
}

#[test]
fn login_without_uv_rejected() {
    let env = TestEnv::new("wa-nouv");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    // UP present, UV absent — v7 requires UV always
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &dev.synth.assertion_json_with(RP, ORIGIN, &ch, 0x01),
    );
    let r = post(&env, "/webauthn/login/finish", &body);
    expect_err(&r, 400, "user verification required");
}

#[test]
fn login_tampered_signature_rejected() {
    let env = TestEnv::new("wa-tamsig");
    let dev = register(&env, SynthAuth::new_ed(), SessionKey::new());
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &dev.synth.assertion_json(RP, ORIGIN, &ch),
    );
    // break the assertion signature (the last character of the b64u signature)
    let pos = body.rfind("\"signature\":\"").unwrap();
    let start = pos + "\"signature\":\"".len();
    let mut chars = body.as_bytes().to_vec();
    chars[start] = if chars[start] == b'A' { b'B' } else { b'A' };
    let body = String::from_utf8(chars).unwrap();
    let r = post(&env, "/webauthn/login/finish", &body);
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert_eq!(r.status, 400, "{text}");
    assert!(text.contains("signature"), "{text}");
}

#[test]
fn login_challenge_mismatch_rejected() {
    let env = TestEnv::new("wa-chmismatch");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    // an assertion over a DIFFERENT challenge: one in clientData, another in the finish body
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &dev.synth.assertion_json(
            RP,
            ORIGIN,
            &crypto::b64u_encode(&crypto::random_arr::<32>()),
        ),
    );
    let r = post(&env, "/webauthn/login/finish", &body);
    expect_err(&r, 400, "challenge mismatch");
}

#[test]
fn login_cross_origin_ceremony_rejected() {
    let env = TestEnv::new("wa-crossorigin");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    // crossOrigin:true (an iframe ceremony) — refused even though the
    // origin string matches (W3C: a top-level ceremony only)
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &dev.synth.assertion_json_cross_origin(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/login/finish", &body);
    expect_err(&r, 400, "crossOrigin ceremony refused");
}

// ---------------------------------------------------------------- creds

/// Add a credential to an existing account (PoP session + register
/// ceremony), optionally recording a User Agent. Returns the account doc.
fn add_cred(
    env: &TestEnv,
    dev: &Device,
    synth: &SynthAuth,
    ua: Option<&str>,
) -> auth::codec::json::Json {
    let r = authed_req(env, dev, "/cred/add/begin", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let ch = jstr(&resp_json(&r), "challenge");
    let mut body = with_finish(
        "register-pop",
        &ch,
        &dev.skey,
        &synth.attestation_json(RP, ORIGIN, &ch),
    );
    if let Some(ua) = ua {
        body.pop(); // trailing }
        body.push_str(&format!(",\"ua\":{}}}", auth::codec::json::quote(ua)));
    }
    let r = authed_req(env, dev, "/cred/add/finish", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    resp_json(&r)
}

/// Start an ordered step-up for unlinking `id`. Returns the challenge
/// and the options document (`allowCredentials` = older creds).
fn drop_begin(env: &TestEnv, dev: &Device, id: &str) -> (String, auth::codec::json::Json) {
    let body = format!("{{\"id\":{}}}", auth::codec::json::quote(id));
    let r = authed_req(env, dev, "/cred/drop/begin", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let j = resp_json(&r);
    (jstr(&j, "challenge"), j)
}

/// Finish an unlink step-up with a specific authenticator.
fn drop_finish(env: &TestEnv, dev: &Device, ch: &str, synth: &SynthAuth) -> auth::net::http::Resp {
    let body = format!(
        "{{\"challenge\":{},\"response\":{}}}",
        auth::codec::json::quote(ch),
        synth.assertion_json(RP, ORIGIN, ch)
    );
    authed_req(env, dev, "/cred/drop/finish", &body)
}

#[test]
fn cred_add_and_drop() {
    let env = TestEnv::new("wa-creds");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let first = dev.synth.cred_id_b64u();

    // add a second cred (PoP + the register ceremony)
    let synth2 = SynthAuth::new_ed();
    let doc = add_cred(&env, &dev, &synth2, None);
    let ids = cred_ids(&doc);
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&synth2.cred_id_b64u()));

    // an unknown id — an error
    let body = "{\"id\":\"nope\"}".to_string();
    let r = authed_req(&env, &dev, "/cred/drop/begin", &body);
    expect_err(&r, 400, "unknown credential");

    // drop that very cred: the step-up is made by the OLDER first cred
    let (ch, _opts) = drop_begin(&env, &dev, &synth2.cred_id_b64u());
    let r = drop_finish(&env, &dev, &ch, &dev.synth);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(cred_ids(&resp_json(&r)).len(), 1);

    // the dropped cred no longer logs in
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/login/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let body = with_finish(
        "login-pop",
        &ch,
        &skey,
        &synth2.assertion_json(RP, ORIGIN, &ch),
    );
    let r = post(&env, "/webauthn/login/finish", &body);
    expect_err(&r, 400, "unknown credential");

    // the first credential can never be unlinked (nobody gets a step-up)
    let body = format!("{{\"id\":{}}}", auth::codec::json::quote(&first));
    let r = authed_req(&env, &dev, "/cred/drop/begin", &body);
    expect_err(&r, 400, "cannot unlink the first credential");
}

#[test]
fn unlink_requires_an_older_credential() {
    let env = TestEnv::new("wa-creds-order");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let x = dev.synth.clone();
    let y = SynthAuth::new_ed();
    let z = SynthAuth::new_es();
    let w = SynthAuth::new_ed();
    for (i, s) in [&y, &z, &w].into_iter().enumerate() {
        let doc = add_cred(&env, &dev, s, None);
        assert_eq!(cred_ids(&doc).len(), i + 2);
    }
    let doc = resp_json(&authed_req(&env, &dev, "/account", "{}"));
    let order = cred_ids(&doc);
    assert_eq!(
        order,
        vec![
            x.cred_id_b64u(),
            y.cred_id_b64u(),
            z.cred_id_b64u(),
            w.cred_id_b64u()
        ],
        "credentials keep insertion order"
    );

    // begin for Z offers ONLY the older creds (X, Y)
    let (ch, opts) = drop_begin(&env, &dev, &z.cred_id_b64u());
    let allow: Vec<String> = opts
        .get("options")
        .and_then(|o| o.get("allowCredentials"))
        .and_then(auth::codec::json::Json::as_arr)
        .map(|a| a.iter().map(|c| jstr(c, "id")).collect())
        .unwrap_or_default();
    assert_eq!(allow, vec![x.cred_id_b64u(), y.cred_id_b64u()]);

    // but the server does not trust the client's picker: W (newer) is refused
    let r = drop_finish(&env, &dev, &ch, &w);
    expect_err(&r, 400, "step-up credential must be older");

    // the challenge is single-use: replaying it (even with an older cred) fails
    let r = drop_finish(&env, &dev, &ch, &y);
    expect_err(&r, 400, "unknown or expired challenge");

    // a fresh begin + an older Y succeeds
    let (ch, _opts) = drop_begin(&env, &dev, &z.cred_id_b64u());
    let r = drop_finish(&env, &dev, &ch, &y);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(
        cred_ids(&resp_json(&r)),
        vec![x.cred_id_b64u(), y.cred_id_b64u(), w.cred_id_b64u()]
    );

    // X remains permanent even with other creds present
    let body = format!("{{\"id\":{}}}", auth::codec::json::quote(&x.cred_id_b64u()));
    let r = authed_req(&env, &dev, "/cred/drop/begin", &body);
    expect_err(&r, 400, "cannot unlink the first credential");
}

#[test]
fn credential_user_agent_is_stored() {
    let env = TestEnv::new("wa-creds-ua");
    // registration: send a UA in the finish body
    let st = SynthAuth::new_es();
    let skey = SessionKey::new();
    let r = route_begin(&env, "/webauthn/register/begin");
    let ch = jstr(&resp_json(&r), "challenge");
    let mut body = with_finish(
        "register-pop",
        &ch,
        &skey,
        &st.attestation_json(RP, ORIGIN, &ch),
    );
    body.pop();
    body.push_str(",\"ua\":\"TestAgent/1.0\"}");
    let r = post(&env, "/webauthn/register/finish", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let doc = resp_json(&r);
    let account = doc.get("account").expect("account doc");
    let creds = account
        .get("creds")
        .and_then(auth::codec::json::Json::as_arr)
        .unwrap();
    assert_eq!(
        creds[0].get("ua").and_then(auth::codec::json::Json::as_str),
        Some("TestAgent/1.0")
    );

    // a later cred without a UA reports null
    let dev = Device {
        synth: st,
        skey,
        cert: auth::wire::Cert::decode(&crypto::b64u_decode(&jstr(&doc, "cert")).unwrap()).unwrap(),
        jti: auth::wire::Jti::from_bytes(
            crypto::b64u_decode(&jstr(&doc, "jti"))
                .unwrap()
                .as_slice()
                .try_into()
                .unwrap(),
        ),
    };
    let doc = add_cred(&env, &dev, &SynthAuth::new_ed(), Some("OtherAgent/2.0"));
    let creds = doc
        .get("creds")
        .and_then(auth::codec::json::Json::as_arr)
        .unwrap();
    assert_eq!(
        creds[0].get("ua").and_then(auth::codec::json::Json::as_str),
        Some("TestAgent/1.0")
    );
    assert_eq!(
        creds[1].get("ua").and_then(auth::codec::json::Json::as_str),
        Some("OtherAgent/2.0")
    );

    let doc = add_cred(&env, &dev, &SynthAuth::new_ed(), None);
    let creds = doc
        .get("creds")
        .and_then(auth::codec::json::Json::as_arr)
        .unwrap();
    assert_eq!(creds[2].get("ua"), Some(&auth::codec::json::Json::Null));
}

// ---------------------------------------------------------------- account

#[test]
fn account_bio_default_override_reset() {
    let env = TestEnv::with_cfg(
        "wa-bio",
        IsConfig {
            bio_default: Some("https://home.default.example".into()),
            ..boot_cfg()
        },
    );
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());

    // The config default is copied into the account at creation.
    let r = authed_req(&env, &dev, "/account", "{}");
    let doc = resp_json(&r);
    assert_eq!(jstr(&doc, "bio_homeserver"), "https://home.default.example");

    // an override
    let r = authed_req(
        &env,
        &dev,
        "/account",
        "{\"bio_homeserver\":\"https://my.home.example\"}",
    );
    let doc = resp_json(&r);
    assert_eq!(jstr(&doc, "bio_homeserver"), "https://my.home.example");

    // null clears it; no implicit fallback to the config afterwards
    let r = authed_req(&env, &dev, "/account", "{\"bio_homeserver\":null}");
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert!(text.contains("\"bio_homeserver\":null"), "{text}");

    // not http(s) — refused
    let r = authed_req(&env, &dev, "/account", "{\"bio_homeserver\":\"ftp://x\"}");
    expect_err(&r, 400, "http(s) URL expected");

    // no default and no override — the field is empty
    let env2 = TestEnv::new("wa-bio-nodefault");
    let dev2 = register(&env2, SynthAuth::new_es(), SessionKey::new());
    let r = authed_req(&env2, &dev2, "/account", "{}");
    let text = String::from_utf8_lossy(&r.body).into_owned();
    assert!(text.contains("\"bio_homeserver\":null"), "{text}");
}

// ---------------------------------------------------------------- logout / PoP

#[test]
fn logout_kills_the_session() {
    let env = TestEnv::new("wa-logout");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());

    let r = authed_req(&env, &dev, "/logout", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // the session row is gone: signed requests no longer pass
    let r = authed_req(&env, &dev, "/account", "{}");
    expect_err(&r, 401, "unknown session");

    // a second logout too
    let r = authed_req(&env, &dev, "/logout", "{}");
    expect_err(&r, 401, "unknown session");
}

#[test]
fn pop_request_negatives() {
    let env = TestEnv::new("wa-pop");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let path = "/account";
    let body = "{}";

    // no headers at all
    let r = auth::server::route::route(&env.is(), &req("POST", path, body));
    expect_err(&r, 401, "no x-jti");

    // a stale ts (the 300s window)
    let ts = crypto::now() - 10_000;
    let r = pop_req_raw(&env, &dev.skey, dev.jti.bytes(), path, body, ts, None);
    expect_err(&r, 401, "stale timestamp");

    // a broken signature
    let ts = crypto::now();
    let sig = dev.skey.sign(&auth::wire::msg_request(
        "POST",
        "/other",
        ts,
        body.as_bytes(),
    ));
    let r = pop_req_raw(&env, &dev.skey, dev.jti.bytes(), path, body, ts, Some(sig));
    expect_err(&r, 401, "bad request signature");

    // an unknown jti
    let fake_jti = [7u8; 16];
    let ts = crypto::now();
    let r = pop_req_raw(&env, &dev.skey, &fake_jti, path, body, ts, None);
    expect_err(&r, 401, "unknown session");

    // a GET on an API path — misses the API routing (falls through to www)
    let r = auth::server::route::route(&env.is(), &get(path));
    assert_ne!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
}

// ---------------------------------------------------------------- expiry

#[test]
fn session_expires_with_the_cert() {
    let env = TestEnv::with_cfg(
        "wa-expiry",
        IsConfig {
            cert_ttl: 1,
            ..boot_cfg()
        },
    );
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let r = authed_req(&env, &dev, "/account", "{}");
    assert_eq!(r.status, 200);
    sleep(Duration::from_millis(1600));
    let r = authed_req(&env, &dev, "/account", "{}");
    expect_err(&r, 401, "session expired");
}

// ---------------------------------------------------------------- helpers

use auth::net::http::Resp;

fn post(env: &TestEnv, path: &str, body: &str) -> Resp {
    auth::server::route::route(&env.is(), &req("POST", path, body))
}

fn route_begin(env: &TestEnv, path: &str) -> Resp {
    post(env, path, "{}")
}

/// A PoP request with an explicit ts and an optional signature override (for negatives).
fn pop_req_raw(
    env: &TestEnv,
    skey: &SessionKey,
    jti: &[u8; 16],
    path: &str,
    body: &str,
    ts: u64,
    force_sig: Option<String>,
) -> Resp {
    let sig = force_sig
        .unwrap_or_else(|| skey.sign(&auth::wire::msg_request("POST", path, ts, body.as_bytes())));
    let mut r = req("POST", path, body);
    r.headers.insert("x-jti".into(), crypto::b64u_encode(jti));
    r.headers.insert("x-ts".into(), ts.to_string());
    r.headers.insert("x-sig".into(), sig);
    auth::server::route::route(&env.is(), &r)
}
