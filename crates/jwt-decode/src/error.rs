use thiserror::Error;

use crate::SignatureAlgorithm;

#[derive(Debug, Clone, Error)]
#[error("{kind}")]
pub struct JwtDecodeError {
    kind: JwtDecodeErrorKind,
}

impl JwtDecodeError {
    #[must_use]
    pub fn kind(&self) -> &JwtDecodeErrorKind {
        &self.kind
    }

    pub(crate) fn new(kind: JwtDecodeErrorKind) -> Self {
        Self { kind }
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum JwtDecodeErrorKind {
    #[error("malformed token")]
    MalformedToken,
    #[error("unsupported JOSE header")]
    UnsupportedHeader,
    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(SignatureAlgorithm),
    #[error("missing key id")]
    MissingKeyId,
    #[error("key not found")]
    KeyNotFound,
    #[error("ambiguous key id")]
    AmbiguousKeyId,
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    SignatureInvalid,
    #[error("claims invalid: {0}")]
    ClaimsInvalid(ClaimErrorKind),
    #[error("token expired")]
    Expired,
    #[error("token not yet valid")]
    NotYetValid,
    #[error("issued-at invalid")]
    IssuedAtInvalid,
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("token type mismatch")]
    TokenTypeMismatch,
    #[error("client mismatch")]
    ClientMismatch,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("JWKS parse failed")]
    JwksParse,
    #[error("JWKS fetch failed")]
    JwksFetch,
    #[error("JWKS cache failed")]
    JwksCache,
    #[error("policy invalid: {0}")]
    PolicyInvalid(PolicyErrorKind),
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ClaimErrorKind {
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("duplicate JSON member")]
    DuplicateJsonMember,
    #[error("deserialization failed")]
    Deserialize,
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PolicyErrorKind {
    #[error("missing issuer")]
    MissingIssuer,
    #[error("missing audience")]
    MissingAudience,
    #[error("empty algorithm allowlist")]
    EmptyAlgorithmAllowlist,
    #[error("empty value for {0}")]
    EmptyValue(&'static str),
    #[error("mixed symmetric and asymmetric algorithms")]
    MixedAlgorithmFamilies,
}
