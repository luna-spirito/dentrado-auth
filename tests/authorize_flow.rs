//! /authorize → Attestation → Oneshot: the full authorization path of
//! a third-party instance. The positive: an honest oneshot passes
//! `Oneshot::verify` (pin → root → signer → account → session, the
//! pin first, then four signatures + exp). Negatives: an unpinned
//! root, broken signatures of every level, a foreign session key, a
//! foreign nonce, a non-bare `aud`, expiry.

mod common;

use auth::crypto;
use auth::wire::{Attestation, Oneshot};
use common::*;

/// /authorize (PoP) → (attestation bytes, expires).
fn authorize(env: &TestEnv, dev: &Device, aud: &str, nonce: &[u8; 32]) -> auth::net::http::Resp {
    let body = format!(
        "{{\"aud\":{},\"nonce\":\"{}\"}}",
        auth::codec::json::quote(aud),
        crypto::b64u_encode(nonce)
    );
    authed_req(env, dev, "/authorize", &body)
}

fn att_bytes_of(r: &auth::net::http::Resp) -> Vec<u8> {
    assert_eq!(r.status, 200, "{}", String::from_utf8_lossy(&r.body));
    crypto::b64u_decode(&jstr(&resp_json(r), "attestation")).unwrap()
}

/// The pin an instance holds: phrase → root pubkey (the public API
/// derivation — the phrase IS the root).
fn pin_of(env: &TestEnv) -> auth::crypto::PublicKey {
    auth::keys::root::from_phrase(&auth::keys::mnemonic::encode(&env.root_seed))
        .expect("phrase decodes")
        .public()
}

#[test]
fn honest_oneshot_verifies() {
    let env = TestEnv::new("au-honest");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let aud = "https://wiki.example";
    let n = nonce();

    let r = authorize(&env, &dev, aud, &n);
    let att_b = att_bytes_of(&r);
    let att = Attestation::decode(&att_b).unwrap();

    // the attestation binds the session key to the account and the audience
    assert_eq!(att.session_pk.bytes(), &dev.skey.pk);
    assert_eq!(att.account_pk, dev.account_pk());
    assert_eq!(att.aud, aud);
    assert_eq!(att.header.origin, ORIGIN);
    assert_eq!(att.exp - att.iat, 300); // the default att_ttl

    // the frontend assembles the oneshot; verify is exactly what the instance does
    let os = oneshot_of(&dev, &att_b, &n);
    let pin = pin_of(&env);
    os.verify(crypto::now(), &pin, aud, &n)
        .expect("honest oneshot verifies");

    // the response's expires agrees with the attestation
    let expires = jnum(&resp_json(&authorize(&env, &dev, aud, &n)), "expires");
    assert_eq!(expires as u64, att.exp);
}

#[test]
fn aud_must_be_a_bare_origin() {
    let env = TestEnv::new("au-bare");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let n = nonce();

    // A path/query/fragment would let the caller choose WHICH PAGE on
    // the audience origin receives the token (a wiki page or an open
    // redirect could forward it); userinfo and bad ports are refused
    // for the same "one canonical origin" reason.
    for bad in [
        "https://wiki.example/wiki/Page",
        "https://wiki.example/?a=b",
        "https://wiki.example/#frag",
        "https://user@wiki.example",
        "https://wiki.example:0",
        "https://wiki.example:99999",
        "ftp://wiki.example",
        "wiki.example",
    ] {
        let r = authorize(&env, &dev, bad, &n);
        assert_eq!(
            r.status,
            400,
            "{bad} must be refused: {}",
            String::from_utf8_lossy(&r.body)
        );
    }

    // a non-default port is still a bare origin
    assert_eq!(
        authorize(&env, &dev, "https://wiki.example:8443", &n).status,
        200
    );
}

#[test]
fn oneshot_tampered_signatures_rejected() {
    let env = TestEnv::new("au-tamper");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let n = nonce();
    let att_b = att_bytes_of(&authorize(&env, &dev, "https://wiki.example", &n));

    // break the signatures one by one: root_sig / authorizer_sig / account_sig
    let att = Attestation::decode(&att_b).unwrap();
    let mut m = att.clone();
    m.header.root_sig.bytes_mut()[0] ^= 1;
    let os = oneshot_of(&dev, &m.encode(), &n);
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "bad root signature"
    );

    let mut m = att.clone();
    m.authorizer_sig.bytes_mut()[0] ^= 1;
    let os = oneshot_of(&dev, &m.encode(), &n);
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "bad authorizer signature"
    );

    let mut m = att.clone();
    m.account_sig.bytes_mut()[0] ^= 1;
    let os = oneshot_of(&dev, &m.encode(), &n);
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "bad account signature"
    );

    // a swapped binding: a foreign session key inside the attestation —
    // the authorizer would never sign that; we exercise the verifier: the
    // session_pk ↔ session_sig skew is caught at the last step
    let mut m = att.clone();
    m.session_pk = auth::wire::SessionPk::from_bytes(&SessionKey::new().pk);
    let os = oneshot_of(&dev, &m.encode(), &n);
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "bad authorizer signature"
    );
}

#[test]
fn oneshot_wrong_nonce_and_wrong_session_key_rejected() {
    let env = TestEnv::new("au-nonce");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let n = nonce();
    let att_b = att_bytes_of(&authorize(&env, &dev, "https://wiki.example", &n));
    let honest_sig = dev.skey.sign_raw(&Oneshot::msg(&att_b, &n));

    // the nonce swapped under the old signature: the relying party
    // compares against the nonce IT issued and rejects it
    let os = Oneshot {
        attestation: Attestation::decode(&att_b).unwrap(),
        nonce: nonce(),
        session_sig: auth::crypto::Signature::from_bytes(&honest_sig),
    };
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "wrong nonce"
    );

    // a signature by another key (another device)
    let impostor = SessionKey::new();
    let os = Oneshot {
        attestation: Attestation::decode(&att_b).unwrap(),
        nonce: n,
        session_sig: auth::crypto::Signature::from_bytes(
            &impostor.sign_raw(&Oneshot::msg(&att_b, &n)),
        ),
    };
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "bad session signature"
    );
}

#[test]
fn oneshot_expires() {
    let env = TestEnv::new("au-exp");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let n = nonce();
    let att_b = att_bytes_of(&authorize(&env, &dev, "https://wiki.example", &n));
    let os = oneshot_of(&dev, &att_b, &n);

    let exp = Attestation::decode(&att_b).unwrap().exp;
    let pin = pin_of(&env);
    os.verify(exp - 1, &pin, "https://wiki.example", &n)
        .expect("alive right before exp");
    assert_eq!(
        os.verify(exp, &pin, "https://wiki.example", &n)
            .unwrap_err(),
        "attestation expired"
    );
    assert_eq!(
        os.verify(exp + 60, &pin, "https://wiki.example", &n)
            .unwrap_err(),
        "attestation expired"
    );
}

#[test]
fn aud_is_bound_per_instance() {
    let env = TestEnv::new("au-aud");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());

    // an attestation for one aud is no good for another: aud is part of
    // the signed part — each instance checks att.aud against its own origin
    let a = Attestation::decode(&att_bytes_of(&authorize(
        &env,
        &dev,
        "https://wiki.example",
        &nonce(),
    )))
    .unwrap();
    let b = Attestation::decode(&att_bytes_of(&authorize(
        &env,
        &dev,
        "https://other.example",
        &nonce(),
    )))
    .unwrap();
    assert_eq!(a.aud, "https://wiki.example");
    assert_eq!(b.aud, "https://other.example");
    assert_ne!(a.encode(), b.encode());
    // each honest oneshot verifies on its own; a token minted for
    // another audience is rejected by the verifier
    let n = nonce();
    let os = oneshot_of(&dev, &b.encode(), &n);
    let pin = pin_of(&env);
    os.verify(crypto::now(), &pin, "https://other.example", &n)
        .unwrap();
    assert_eq!(
        os.verify(crypto::now(), &pin_of(&env), "https://wiki.example", &n)
            .unwrap_err(),
        "wrong audience"
    );
    assert_ne!(os.attestation.aud, "https://wiki.example");
}

#[test]
fn foreign_is_attestation_is_pinned_out() {
    let env_a = TestEnv::new("au-pin-a");
    let env_b = TestEnv::new("au-pin-b"); // another root
    let dev_a = register(&env_a, SynthAuth::new_es(), SessionKey::new());
    let n = nonce();
    let att_b = att_bytes_of(&authorize(&env_a, &dev_a, "https://wiki.example", &n));

    let dev_b = register(&env_b, SynthAuth::new_es(), SessionKey::new());
    let att_foreign = att_bytes_of(&authorize(&env_b, &dev_b, "https://wiki.example", &n));

    // the phrase IS the root (public API): phrase → pubkey = the pin
    let phrase = auth::keys::mnemonic::encode(&env_a.root_seed);
    let pinned_pk = auth::keys::root::from_phrase(&phrase)
        .expect("phrase decodes")
        .public();
    let foreign_is_id = *Attestation::decode(&att_foreign).unwrap().header.is_id();
    let honest_is_id = *Attestation::decode(&att_b).unwrap().header.is_id();
    assert_ne!(honest_is_id, foreign_is_id, "one root — one is_id");
    // an instance pins its own root's pubkey
    assert_eq!(pinned_pk, honest_is_id);
    assert_ne!(pinned_pk, foreign_is_id);

    // verify() enforces the pin itself, BEFORE any signature check: a
    // GENUINE foreign-IS attestation (self-consistent signatures an
    // attacker can mint for their own root) is refused outright
    let os = oneshot_of(&dev_b, &att_foreign, &n);
    assert_eq!(
        os.verify(crypto::now(), &pinned_pk, "https://wiki.example", &n)
            .unwrap_err(),
        "unpinned root (not our IS)"
    );
    // pinned to the foreign root it was born under, the same oneshot
    // is self-consistent (what a foreign instance would accept)
    let pin_b = pin_of(&env_b);
    os.verify(crypto::now(), &pin_b, "https://wiki.example", &n)
        .expect("pinned to the issuing root: self-consistent");
}

#[test]
fn authorize_negatives() {
    let env = TestEnv::new("au-neg");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let n = nonce();

    // a non-http(s) aud
    let body = format!(
        "{{\"aud\":\"wiki.example\",\"nonce\":\"{}\"}}",
        crypto::b64u_encode(&n)
    );
    let r = authed_req(&env, &dev, "/authorize", &body);
    expect_err(&r, 400, "bare http(s) origin");

    // a nonce that is not 32 bytes
    let body = format!(
        "{{\"aud\":\"https://wiki.example\",\"nonce\":\"{}\"}}",
        crypto::b64u_encode(&[1u8; 16])
    );
    let r = authed_req(&env, &dev, "/authorize", &body);
    expect_err(&r, 400, "32 bytes expected");

    // broken b64u
    let r = authed_req(
        &env,
        &dev,
        "/authorize",
        "{\"aud\":\"https://w.example\",\"nonce\":\"!!\"}",
    );
    expect_err(&r, 400, "bad nonce encoding");

    // missing fields
    let r = authed_req(&env, &dev, "/authorize", "{}");
    expect_err(&r, 400, "missing aud");
    let r = authed_req(&env, &dev, "/authorize", "{\"aud\":\"https://w.example\"}");
    expect_err(&r, 400, "missing nonce");

    // without a PoP session
    let r = auth::server::route::route(
        &env.is(),
        &req("POST", "/authorize", "{\"aud\":\"https://w.example\"}"),
    );
    expect_err(&r, 401, "no x-jti");
}

#[test]
fn cert_header_travels_in_every_document() {
    // the cert and the attestation carry the same root header — one pin
    // is enough for an instance
    let env = TestEnv::new("au-header");
    let dev = register(&env, SynthAuth::new_es(), SessionKey::new());
    let att = Attestation::decode(&att_bytes_of(&authorize(
        &env,
        &dev,
        "https://wiki.example",
        &nonce(),
    )))
    .unwrap();
    assert_eq!(&dev.cert.header, &att.header);
    assert_eq!(dev.cert.key_id(), att.header.key_id());
}
