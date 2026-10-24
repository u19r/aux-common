//! Strict, model-neutral JOSE signature and encryption operations.
//!
//! This crate does not validate claims, issuers, audiences, key lifecycle, or
//! tenant policy. Callers supply already-authorized key material and apply
//! those application decisions around the primitives here.

#[cfg(feature = "native")]
mod compact_jwe;
#[cfg(feature = "native")]
mod compact_jws;
mod constants;
mod error;
#[cfg(feature = "native")]
mod header;
#[cfg(feature = "native")]
mod key_material;

#[cfg(feature = "native")]
pub use compact_jwe::JweRecipient;
#[cfg(feature = "native")]
pub use compact_jws::{CompactJws, PreparedJwsInput, finish_compact_jws};
pub use error::JoseError;
#[cfg(feature = "native")]
pub use header::{JwsAlgorithm, ProtectedHeader};
#[cfg(feature = "native")]
pub use key_material::{PreparedVerifier, PublicJwk, PublicJwks, PublicKeyComponents};

mod bounded_json;
mod embedded_jwk;
mod lossless_jws;
mod thumbprint;

pub use bounded_json::BoundedJson;
pub use embedded_jwk::EmbeddedEs256Key;
pub use lossless_jws::LosslessJws;
pub use thumbprint::JwkThumbprint;
