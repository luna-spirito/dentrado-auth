//! The IS offline key hierarchy (layer 2 in the lib.rs tower: builds
//! on `crypto` and `codec`, no higher module is used). CLI-only:
//! [`root`], [`signer`], [`mnemonic`] are used only by the `auth`
//! binary (the `root …` / `signer …` commands); the server runtime
//! never touches them — hence `server/`. The one exception is
//! [`header`] — the root-signed signer header embeds itself into
//! every wire document.
//!
//! Generation ownership: fresh keys are born INSIDE this module
//! (`root::generate`, the authorizer seed inside `signer::issue`) —
//! production code cannot hand in a chosen (e.g. constant) seed;
//! seed-taking constructors are private/`cfg(test)`. Everything else
//! is deterministic (time and inputs arrive as parameters). Effects
//! (reading the phrase from stdin, writing the bundle to stdout, disk)
//! live in `main.rs` — the wg (genkey/pubkey).
//!
//! Hierarchy: a seed phrase (24 BIP39 words, [`mnemonic`]) = the root key;
//! `is_id = pubkey(root)` — the service identity; `signer` issues the
//! bundle `[signer key seed][root-signed Header]`.

pub mod header;
pub mod mnemonic;
pub mod root;
pub mod signer;
