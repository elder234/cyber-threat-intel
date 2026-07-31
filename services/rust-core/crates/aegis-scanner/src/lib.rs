//! Aegis vulnerability scanner library.
//!
//! ⚠️ RUNTIME VERIFICATION REQUIRED: network scanning paths not executed
//! (workspace VM unavailable during authoring). Pure parsing/analysis logic is
//! unit-tested.
//!
//! AUTHORIZATION: the binary refuses to scan a registered asset unless
//! `aegis.assets.is_authorized = true`. Ad-hoc targets are the operator's
//! responsibility — scan only systems you are permitted to test.

pub mod http_headers;
pub mod ports;
pub mod portspec;
pub mod service;
pub mod tls;

pub use portspec::parse_ports;
