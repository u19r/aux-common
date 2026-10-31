//! Stateless DPoP validation. Callers verify token authority before presenter
//! validation. There is no accepted-jti store: a proof can replay within its
//! freshness window.
mod algorithm;
mod constants;
mod error;
mod numeric_date;
mod presenter;
mod proof;
mod target_uri;

pub use algorithm::DpopAlgorithm;
pub use constants::{MAX_ACCESS_TOKEN_BYTES, MAX_ACCESS_TOKEN_EXPIRY_LEEWAY_SECONDS};
pub use error::DpopError;
pub use jose_core::JwkThumbprint;
pub use presenter::{
    AccessTokenConfirmation, PresenterValidationInput, ResourceProofValidationInput,
};
pub use proof::{DpopValidationInput, ValidatedDpopProof};
pub use target_uri::DpopTargetUri;

mod challenge;
pub use challenge::ResourceChallenge;

#[cfg(test)]
mod presenter_tests;
#[cfg(test)]
mod proof_tests;
#[cfg(test)]
#[cfg(test)]
mod target_uri_tests;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

#[cfg(test)]
mod bounded_inputs_tests;

#[cfg(test)]
mod corpus_tests;
