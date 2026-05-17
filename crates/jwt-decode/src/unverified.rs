use serde::de::DeserializeOwned;

use crate::{ClaimErrorKind, JwtDecodeError, JwtDecodeErrorKind, Result, json::CompactToken};

pub struct DangerousUnverifiedClaims<T> {
    pub claims: T,
}

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
