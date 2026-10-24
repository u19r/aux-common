//! Explicit, model-neutral hashing primitives.
//!
//! Canonical paths are `crypto_hash::digest`, `crypto_hash::hmac_sha256`, and
//! the password and API-key helpers below. The `sha256` module re-exports the
//! same functions for namespaced callers; prefer the top-level names in new
//! code.
//!
//! This crate deliberately does not own password reset, rate limiting, audit,
//! persistence, or scheduling policy. Callers choose those policies around the
//! synchronous operations exposed here.

mod api_key;
mod constants;
mod error;
mod password;
pub mod sha256;

pub use api_key::{
    ApiKeySecretHash, hash_api_key_secret, try_derive_api_key_public_id, verify_api_key_secret,
};
pub use constants::{
    API_KEY_HASH_ALGO, ARGON2_HASH_OUTPUT_BYTES, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
    ARGON2_SALT_BYTES, ARGON2_VERSION,
};
pub use error::HashError;
pub use password::{Argon2Policy, hash_password, verify_password, verify_password_with_policy};
pub use sha256::{content_digest_header_value, digest, digest_base64, hmac_sha256};
