mod algorithm;
mod claims;
mod claims_policy;
mod clock;
mod error;
mod json;
mod jwks;
mod key_policy;
mod policy;
mod unverified;
mod verifier;

pub use algorithm::{AllowedAlgorithms, SignatureAlgorithm};
pub use claims::{Audience, RegisteredClaims, TokenKind, VerifiedJwt};
pub use clock::{Clock, SystemClock};
pub use error::{ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, PolicyErrorKind};
pub use jwks::{
    JwksCachePolicy, JwksDocument, JwksSource, JwksUrl, LocalSymmetricKey, RemoteJwksSource,
};
pub use policy::{VerificationPolicy, VerificationPolicyBuilder};
pub use unverified::{DangerousUnverifiedClaims, dangerous_unverified_claims};
pub use verifier::{JwtVerifier, JwtVerifierBuilder};

pub(crate) type Result<T> = std::result::Result<T, JwtDecodeError>;

#[cfg(test)]
mod claim_validation_tests;
#[cfg(test)]
mod lib_tests;
#[cfg(test)]
mod performance_tests;
#[cfg(test)]
mod security_tests;
#[cfg(test)]
mod test_support;
