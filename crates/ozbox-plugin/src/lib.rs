//! The Oz Box plugin protocol, version 1 (ADR 0031; the contract is written out in `docs/plugins.md`).
//!
//! A plugin is an executable. For each call the host starts it, writes one [`Request`] as JSON on its standard input, and
//! reads one [`Response`] as JSON from its standard output. This crate holds the shared types ([`protocol`]), the helper a
//! plugin written in Rust uses to answer ([`sdk`]), and, behind the `host` feature, the code that runs plugins ([`host`]).
//! A plugin written in another language needs only the JSON shapes.

pub mod protocol;
pub mod sdk;

#[cfg(feature = "host")]
pub mod host;

pub use protocol::{Failure, Kind, Manifest, Request, Response, API_VERSION};
