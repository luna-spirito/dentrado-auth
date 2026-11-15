//! Edge: net. Layer 5 of the lib.rs tower. The transport layer —
//! HTTP/1.1 and TLS, thread per connection. The protocol codec and
//! the serve loop live in [`http`]; nothing in this module knows the
//! IS or its routes.

pub mod http;
