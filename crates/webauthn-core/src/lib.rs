//! Strict WebAuthn Level 3 ceremony primitives.
//!
//! The caller supplies expected challenge/origin/RP policy and owns stateful
//! challenge consumption, credential binding, counters, tenants, and audit.

mod assertion;
mod attestation;
mod cbor;
mod client_data;
mod error;
mod types;

pub use assertion::verify_assertion;
pub use attestation::verify_none_attestation;
pub use cbor::{CoseKey, parse_cose_key};
pub use client_data::{ClientData, parse_client_data};
pub use error::WebAuthnError;
pub use types::{
    AssertionInput, AssertionResult, AttestationInput, CrossOriginPolicy, RegistrationResult,
    RpPolicy, SignCountStatus, UserVerification,
};

#[cfg(test)]
mod webauthn_tests;
