//! Strict, model-neutral JOSE byte operations.
//!
//! This crate does not validate claims, issuers, audiences, key lifecycle, or
//! tenant policy. Callers supply already-authorized key material and apply
//! those application decisions around the primitives here.

mod compact_jws;
mod error;
mod header;
mod key_material;

pub use compact_jws::{CompactJws, PreparedJwsInput, finish_compact_jws};
pub use error::JoseError;
pub use header::{JwsAlgorithm, ProtectedHeader};
pub use key_material::{PreparedVerifier, PublicJwk, PublicJwks, PublicKeyComponents};

#[cfg(test)]
mod tests;
