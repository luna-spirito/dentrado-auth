//! Pure. Layer 1 of the lib.rs tower (builds on nothing but std).
//! Generic serialization codecs — dependency-free parsers with
//! no domain knowledge: [`bin`] (the length-prefixed binary format of
//! versioned documents), [`json`] (API bodies, options documents) and
//! [`cbor`] (WebAuthn COSE structures). The domain codecs built on
//! them live elsewhere: wire documents in [`crate::wire`], the signer
//! header in [`crate::keys::header`], stored records in
//! [`crate::storage::records`].

pub mod bin;
pub mod cbor;
pub mod json;
