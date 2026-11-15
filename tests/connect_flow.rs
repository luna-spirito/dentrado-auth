//! The v7 connect flow: issuing a 12-word code (always via a step-up —
//! a fresh assertion by this account's cred), redeeming the code on a
//! new device (its own session key + a cert; no passkey ceremony),
//! single-use (burn on a SUCCESSFUL finish), foreign-session protection.

mod common;

use auth::crypto;
use common::*;

/// /connect/start (PoP) → a step-up challenge + options (allowList = the account's creds).
fn connect_start(env: &TestEnv, dev: &Device) -> String {
    let r = authed_req(env, dev, "/connect/start", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    jstr(&resp_json(&r), "challenge")
}

/// /connect/finish: a step-up assertion → 12 words.
fn connect_finish(
    env: &TestEnv,
    dev: &Device,
    ch: &str,
) -> std::result::Result<String, (u16, String)> {
    let body = format!(
        "{{\"challenge\":{},\"response\":{}}}",
        auth::codec::json::quote(ch),
        dev.synth.assertion_json(RP, ORIGIN, ch)
    );
    let r = authed_req(env, dev, "/connect/finish", &body);
    if r.status == 200 {
        Ok(words_of(&r))
    } else {
        Err((r.status, String::from_utf8_lossy(&r.body).into_owned()))
    }
}

#[test]
fn code_issue_via_stepup_and_enroll_new_device() {
    let mut env = TestEnv::new("cn-flow");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());

    // step-up: the allowList in options names THIS account's creds
    let r = authed_req(&env, &dev, "/connect/start", "{}");
    let j = resp_json(&r);
    let allow = j
        .get("options")
        .and_then(|o| o.get("allowCredentials"))
        .and_then(auth::codec::json::Json::as_arr)
        .unwrap_or_else(|| panic!("allowCredentials in options"));
    let ids: Vec<String> = allow.iter().map(|c| jstr(c, "id")).collect();
    assert!(
        ids.contains(&dev.synth.cred_id_b64u()),
        "allowList holds the account's creds: {ids:?}"
    );

    let ch = connect_start(&env, &dev);
    let words = connect_finish(&env, &dev, &ch).expect("code issued");

    // the new device: the code → a session, no authenticator ceremony
    let r = post(
        &env,
        "/connect/enroll/begin",
        &format!("{{\"words\":{}}}", auth::codec::json::quote(&words)),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let begin = resp_json(&r);
    assert!(
        begin.get("options").is_none(),
        "connect enrollment must not request a passkey: {begin:?}"
    );
    let ech = jstr(&begin, "challenge");
    let skey2 = SessionKey::new();
    let body = with_pop("enroll-pop", &ech, &skey2);
    let r = post(&env, "/connect/enroll/finish", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let dev2 = device_of(SynthAuth::new_ed(), skey2, &r);
    assert_eq!(dev2.account_pk(), dev.account_pk(), "same account");

    // no passkey was added: the account still has only the original cred
    let r = authed_req(&env, &dev2, "/account", "{}");
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    assert_eq!(cred_ids(&resp_json(&r)).len(), 1);

    // and after a restart everything lives
    env.reboot();
    let r = authed_req(&env, &dev2, "/account", "{}");
    assert_eq!(r.status, 200);
}

#[test]
fn code_is_single_use() {
    let env = TestEnv::new("cn-single");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let ch = connect_start(&env, &dev);
    let words = connect_finish(&env, &dev, &ch).expect("code issued");

    // the first redemption begins the ceremony; finish it honestly
    let r = post(
        &env,
        "/connect/enroll/begin",
        &format!("{{\"words\":{}}}", auth::codec::json::quote(&words)),
    );
    assert_eq!(r.status, 200);
    let ech = jstr(&resp_json(&r), "challenge");
    let body = with_pop("enroll-pop", &ech, &SessionKey::new());
    let r = post(&env, "/connect/enroll/finish", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // reusing the code — refused
    let r = post(
        &env,
        "/connect/enroll/begin",
        &format!("{{\"words\":{}}}", auth::codec::json::quote(&words)),
    );
    expect_err(&r, 400, "unknown or expired connect code");
}

#[test]
fn parallel_begins_cannot_outrun_the_burn() {
    let env = TestEnv::new("cn-parallel");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let ch = connect_start(&env, &dev);
    let words = connect_finish(&env, &dev, &ch).expect("code issued");
    let words_body = format!("{{\"words\":{}}}", auth::codec::json::quote(&words));

    // two devices (or tabs) begin before either finishes
    let r = post(&env, "/connect/enroll/begin", &words_body);
    assert_eq!(r.status, 200);
    let first = jstr(&resp_json(&r), "challenge");
    let r = post(&env, "/connect/enroll/begin", &words_body);
    assert_eq!(r.status, 200);
    let second = jstr(&resp_json(&r), "challenge");

    let r = post(
        &env,
        "/connect/enroll/finish",
        &with_pop("enroll-pop", &first, &SessionKey::new()),
    );
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // the code is claimed/burned: the second challenge cannot race it
    let r = post(
        &env,
        "/connect/enroll/finish",
        &with_pop("enroll-pop", &second, &SessionKey::new()),
    );
    expect_err(&r, 400, "unknown or expired connect code");
}

#[test]
fn code_burns_only_on_successful_finish() {
    let env = TestEnv::new("cn-burn");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let ch = connect_start(&env, &dev);
    let words = connect_finish(&env, &dev, &ch).expect("code issued");
    let words_body = format!("{{\"words\":{}}}", auth::codec::json::quote(&words));

    // a failed enrollment attempt (a bad PoP) does NOT eat the code
    let r = post(&env, "/connect/enroll/begin", &words_body);
    assert_eq!(r.status, 200);
    let ech = jstr(&resp_json(&r), "challenge");
    let skey_bad = SessionKey::new();
    let bad = format!(
        "{{\"challenge\":{},\"session_pk\":{},\"pop\":\"AAAA\"}}",
        auth::codec::json::quote(&ech),
        auth::codec::json::quote(&crypto::b64u_encode(&skey_bad.pk)),
    );
    let r = post(&env, "/connect/enroll/finish", &bad);
    assert_ne!(r.status, 200, "bad pop must fail");

    // the code is still alive — an honest attempt passes
    let r = post(&env, "/connect/enroll/begin", &words_body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    let ech = jstr(&resp_json(&r), "challenge");
    let skey3 = SessionKey::new();
    let body = with_pop("enroll-pop", &ech, &skey3);
    let r = post(&env, "/connect/enroll/finish", &body);
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));

    // and only success consumes the code
    let r = post(&env, "/connect/enroll/begin", &words_body);
    expect_err(&r, 400, "unknown or expired connect code");
}

#[test]
fn unknown_words_rejected() {
    let env = TestEnv::new("cn-unknown");
    let words = auth::keys::mnemonic::encode128(&crypto::random_arr::<16>()); // valid words, never issued
    let r = post(
        &env,
        "/connect/enroll/begin",
        &format!("{{\"words\":{}}}", auth::codec::json::quote(&words)),
    );
    expect_err(&r, 400, "unknown or expired connect code");

    // broken words (not 12, a bad checksum) — refused too
    let r = post(&env, "/connect/enroll/begin", "{\"words\":\"abandon\"}");
    assert_eq!(r.status, 400);
    let r = post(&env, "/connect/enroll/begin", "{\"words\":123}");
    assert_eq!(r.status, 400);
}

#[test]
fn stepup_foreign_authenticator_rejected() {
    let env = TestEnv::new("cn-foreign");
    let alice = register(&env, SynthAuth::new_es(), SessionKey::new());
    let mallory = register(&env, SynthAuth::new_ed(), SessionKey::new());

    // a step-up by a foreign authenticator: the cred is not of the account
    let ch = connect_start(&env, &alice);
    let body = format!(
        "{{\"challenge\":{},\"response\":{}}}",
        auth::codec::json::quote(&ch),
        mallory.synth.assertion_json(RP, ORIGIN, &ch)
    );
    let r = authed_req(&env, &alice, "/connect/finish", &body);
    expect_err(&r, 400, "credential not linked");

    // and a foreign PoP session cannot finish someone else's step-up challenge
    let ch = connect_start(&env, &alice);
    let body = format!(
        "{{\"challenge\":{},\"response\":{}}}",
        auth::codec::json::quote(&ch),
        mallory.synth.assertion_json(RP, ORIGIN, &ch)
    );
    let r = authed_req(&env, &mallory, "/connect/finish", &body);
    expect_err(&r, 400, "challenge belongs to another account");
}

#[test]
fn stepup_challenge_single_use() {
    let env = TestEnv::new("cn-step-single");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let ch = connect_start(&env, &dev);
    let _words = connect_finish(&env, &dev, &ch).expect("first finish");
    // a repeated finish with the same challenge — the pending is gone
    match connect_finish(&env, &dev, &ch) {
        Err((400, m)) => assert!(m.contains("unknown or expired"), "{m}"),
        other => panic!("replayed step-up must fail, got {other:?}"),
    }
}

#[test]
fn stepup_without_uv_rejected() {
    let env = TestEnv::new("cn-step-nouv");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let ch = connect_start(&env, &dev);
    let body = format!(
        "{{\"challenge\":{},\"response\":{}}}",
        auth::codec::json::quote(&ch),
        dev.synth.assertion_json_with(RP, ORIGIN, &ch, 0x01)
    );
    let r = authed_req(&env, &dev, "/connect/finish", &body);
    expect_err(&r, 400, "user verification required");
}

#[test]
fn connect_requires_an_authed_session() {
    let env = TestEnv::new("cn-noauth");
    // without PoP headers
    let r = auth::server::route::route(&env.is(), &req("POST", "/connect/start", "{}"));
    expect_err(&r, 401, "no x-jti");
}

/// A local device_of helper.
fn device_of(synth: SynthAuth, skey: SessionKey, r: &auth::net::http::Resp) -> Device {
    let j = resp_json(r);
    let cert = auth::wire::Cert::decode(&crypto::b64u_decode(&jstr(&j, "cert")).unwrap()).unwrap();
    let jti = auth::wire::Jti::from_bytes(
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

fn post(env: &TestEnv, path: &str, body: &str) -> auth::net::http::Resp {
    auth::server::route::route(&env.is(), &req("POST", path, body))
}
