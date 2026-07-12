use std::fmt;

use aws_credential_types::provider;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("AWS credential resolution failed: {0}")]
    Credentials(CredentialErrorKind),
    #[error("invalid header value for signing")]
    InvalidHeaderValue,
    #[error("invalid header name for signing")]
    InvalidHeaderName,
    #[error("failed to prepare signable request: {0}")]
    PrepareRequest(String),
    #[error("SigV4 signing failed: {0}")]
    Signing(String),
    #[error("invalid URI for signing: {0}")]
    InvalidUri(String),
    #[error("invalid URL for signing: {0}")]
    InvalidUrl(String),
    #[error("signed HTTP request failed: {0}")]
    HttpRequest(String),
    #[error("signed HTTP requests require a no-redirect HTTP client")]
    RedirectPolicyRequired,
}

impl From<provider::error::CredentialsError> for SigningError {
    fn from(error: provider::error::CredentialsError) -> Self {
        Self::Credentials(CredentialErrorKind::Provider(error.to_string()))
    }
}

#[derive(Debug)]
pub enum CredentialErrorKind {
    HttpClientInit(String),
    Provider(String),
}

impl fmt::Display for CredentialErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpClientInit(error) => {
                write!(f, "failed to initialize credentials HTTP client: {error}")
            }
            Self::Provider(error) => f.write_str(error),
        }
    }
}
