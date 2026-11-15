//! Dentrado identity service library (v7 minimal — see README.md).
//!
//! Architecture: a deterministic pure core, with all effects (clock,
//! randomness, disk, network) named and pushed to the edges.
//! Functional style on plain Rust — no effect monads, no async: a
//! decision is a pure function of its inputs (`now` and seeds come in
//! as parameters), effects live in explicitly marked places.
//!
//! # The module tower
//!
//! Modules are STRICTLY ordered: every module uses only modules
//! ABOVE it in this list (lower layer number), never below — new
//! modules are built on top of the old ones, there are no up-down
//! dependency zigzags:
//!
//! | Layer | Module | Contents |
//! |-------|--------|----------|
//! | L0 | [`crypto`] | primitives + the named key types (`SecretKey`, `PublicKey`, `Signature`) |
//! | L1 | [`codec`] | generic formats: [`codec::bin`] (versioned documents), [`codec::json`], [`codec::cbor`] |
//! | L2 | [`keys`] | the key hierarchy: [`keys::mnemonic`], [`keys::root`], [`keys::signer`], [`keys::header`] |
//! | L3 | [`wire`] | the v7 documents: `Cert`, `Attestation`, `Oneshot`, `SessionPk`, `Jti` |
//! | L4 | [`storage`] | fs/redb: THE state.redb schema — tables, vault, ALL record types |
//! | L5 | [`net`] | TCP/TLS: HTTP/1.1 codec + the serve loop |
//! | L6 | [`server`] | the IS flows (WebAuthn login, certs, enroll codes, attestations) |
//! | L7 | main.rs | the CLI (composition of effects for a human) |
//!
//! **Pure core** (deterministic — the audit lives here): L0–L3,
//! plus [`server::webauthn`] (COSE keys, assertion/attestation
//! checks — pure checks over parsed bytes).
//!
//! **Edges** (all effects live here):
//! - clock & randomness: `crypto::{now, random, random_arr}` (and the
//!   `generate` constructors built on them) only;
//! - files: `crypto::write_secret_0400`, [`storage`] (redb, pepper),
//!   `server::Is::open` (the boot bundle), the CLI;
//! - network: [`net::http`] (TCP/TLS server), tests' HTTP client.
//!
//! **Runtime** ([`server`]): the IS host — boot from the signer
//! bundle, WebAuthn-only login, session certificates, device
//! enrollment codes, attestations, the static frontend; entry point
//! [`server::route`]. No schema or transport knowledge: rows go
//! through [`storage`], bytes through [`net`].
//!
//! Everything outside the effect list is deterministic. `unsafe` is
//! forbidden crate-wide.

#![forbid(unsafe_code)]

pub mod codec;
pub mod crypto;
pub mod keys;
pub mod net;
pub mod server;
pub mod storage;
pub mod wire;
