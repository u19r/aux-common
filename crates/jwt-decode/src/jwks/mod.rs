mod source;

#[cfg(test)]
mod test_support;

pub use source::{JwksCachePolicy, JwksDocument, JwksSource, LocalSymmetricKey};
#[cfg(not(target_arch = "wasm32"))]
pub use source::{JwksUrl, RemoteJwksSource};
#[cfg(test)]
pub(crate) use test_support::{
    Claims, CountingTransport, FixedClock, HMAC_SECRET, PRIVATE_KEY, build_hmac_verifier,
    build_remote_verifier, build_remote_verifier_with_policy, build_verifier, hmac_token,
    id_header, jwk, jwks, jwks_without_test_key, mock_response, policy, registered_claims,
    signed_raw_token, signed_token, signed_value_token, token, token_without_iat, valid_claims,
};

#[cfg(test)]
pub(crate) use crate::constants::{
    MAX_INVALIDATION_GENERATIONS, MAX_JWKS_DOCUMENT_BYTES, MAX_JWKS_KEYS,
    MAX_UNKNOWN_KID_REFRESH_COOLDOWNS,
};

#[cfg(test)]
mod source_tests;
