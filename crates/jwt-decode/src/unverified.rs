use serde::de::DeserializeOwned;

use crate::{
    ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, error::Result, json::CompactToken,
};

/// Unauthenticated claims decoded without signature, time, issuer, or audience
/// checks.
///
/// Never use this value for authorization. It exists only for diagnostics such
/// as logging the `kid` of a rejected token. Prefer [`crate::JwtVerifier`] for
/// every trust decision.
pub struct DangerousUnverifiedClaims<T> {
    /// Unauthenticated claims for diagnostic or pre-verification routing only.
    pub claims: T,
}

/// Decode claims without verifying the token signature or policy.
///
/// The token shape is still bounded by [`CompactToken`], but the returned
/// claims are unauthenticated and must not inform authorization decisions.
pub fn dangerous_unverified_claims<T>(token: &str) -> Result<DangerousUnverifiedClaims<T>>
where T: DeserializeOwned {
    CompactToken::try_from(token)?;
    let data = jsonwebtoken::dangerous::insecure_decode::<T>(token).map_err(map_backend_error)?;
    Ok(DangerousUnverifiedClaims {
        claims: data.claims,
    })
}

fn map_backend_error(error: jsonwebtoken::errors::Error) -> JwtDecodeError {
    use jsonwebtoken::errors::ErrorKind;
    let kind = match error.kind() {
        ErrorKind::InvalidToken => JwtDecodeErrorKind::MalformedToken,
        _ => JwtDecodeErrorKind::ClaimsInvalid(ClaimErrorKind::Deserialize),
    };
    JwtDecodeError::new(kind)
}
