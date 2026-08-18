use thiserror::Error;

/// Stable categories for malformed or unsupported JOSE material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum JoseError {
    #[error("compact JWS shape is invalid")]
    InvalidCompactShape,
    #[error("base64url encoding is invalid")]
    InvalidBase64,
    #[error("protected header is invalid")]
    InvalidProtectedHeader,
    #[error("unsupported JWS algorithm")]
    UnsupportedAlgorithm,
    #[error("key identifier is empty")]
    EmptyKeyId,
    #[error("public key material is invalid for the selected algorithm")]
    InvalidPublicKey,
    #[error("signature is invalid")]
    InvalidSignature,
    #[error("JWK public-key components are invalid")]
    InvalidJwk,
}
