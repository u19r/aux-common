mod algorithm;
mod claims;
mod claims_policy;
mod clock;
mod constants;
mod error;
mod json;
pub(crate) mod jwks;
mod key_policy;
mod policy;
mod unverified;
mod verifier;
#[cfg(any(test, target_arch = "wasm32"))]
mod wasm_signature;

pub use algorithm::{AllowedAlgorithms, SignatureAlgorithm};
pub use claims::{Audience, RegisteredClaims, TokenKind, VerifiedJwt};
pub use clock::{Clock, SystemClock};
pub use error::{ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, PolicyErrorKind};
pub use jwks::{JwksCachePolicy, JwksDocument, JwksSource, LocalSymmetricKey};
#[cfg(not(target_arch = "wasm32"))]
pub use jwks::{JwksUrl, RemoteJwksSource};
pub use policy::{VerificationPolicy, VerificationPolicyBuilder};
pub use unverified::{DangerousUnverifiedClaims, dangerous_unverified_claims};
pub use verifier::{JwtVerifier, JwtVerifierBuilder};

#[cfg(test)]
mod dpop_leeway_tests;

#[cfg(test)]
mod policy_tests;
