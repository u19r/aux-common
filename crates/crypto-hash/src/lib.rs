//! Explicit, model-neutral hashing primitives.
//!
//! This crate deliberately does not own password reset, rate limiting, audit,
//! persistence, or scheduling policy. Callers choose those policies around the
//! synchronous operations exposed here.

mod api_key;
mod error;
mod password;
pub mod sha256;

pub use api_key::{
    API_KEY_HASH_ALGO, ApiKeySecretHash, hash_api_key_secret, try_derive_api_key_public_id,
    verify_api_key_secret,
};
pub use error::HashError;
pub use password::{
    ARGON2_HASH_OUTPUT_BYTES, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, ARGON2_SALT_BYTES,
    ARGON2_VERSION, Argon2Policy, hash_password, verify_password, verify_password_with_policy,
};

#[cfg(test)]
mod tests;
