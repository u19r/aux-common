use std::fmt;

use aws_credentials::CredentialSource;
use aws_sigv4_signing::{AwsRequestSigner, SignableBody, SigningError};
use bg_jobs_http::{
    AuthorizationErrorKind, AuthorizationFuture, AuthorizationRequest, RequestAuthorizer,
};
use http::Uri;

/// Configuration or execution failures from the AWS adapter. No credential
/// values or signer diagnostics are retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigV4AuthorizerError {
    InvalidConfiguration,
    CredentialUnavailable,
    SigningFailed,
    InvalidUri,
}

impl fmt::Display for SigV4AuthorizerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidConfiguration => "invalid SigV4 authorizer configuration",
            Self::CredentialUnavailable => "AWS credentials unavailable",
            Self::SigningFailed => "SigV4 signing failed",
            Self::InvalidUri => "request URI could not be prepared for SigV4",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SigV4AuthorizerError {}

/// Execution-time AWS SigV4 authorizer backed by the shared signer and
/// credential provider chain.
pub struct SigV4Authorizer {
    signer: AwsRequestSigner,
}

impl fmt::Debug for SigV4Authorizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SigV4Authorizer([REDACTED])")
    }
}

impl SigV4Authorizer {
    #[cfg(test)]
    pub(crate) fn from_signer(signer: AwsRequestSigner) -> Self {
        Self { signer }
    }

    pub fn try_new(
        region: impl AsRef<str>,
        service: impl AsRef<str>,
        credentials: CredentialSource,
    ) -> Result<Self, SigV4AuthorizerError> {
        let region = region.as_ref();
        let service = service.as_ref();
        if region.is_empty()
            || service.is_empty()
            || region.chars().any(char::is_control)
            || service.chars().any(char::is_control)
        {
            return Err(SigV4AuthorizerError::InvalidConfiguration);
        }
        let signer =
            AwsRequestSigner::new(region, credentials, service).map_err(map_signing_error)?;
        Ok(Self { signer })
    }

    async fn sign(
        &self,
        request: AuthorizationRequest<'_>,
    ) -> Result<http::HeaderMap, SigV4AuthorizerError> {
        if request.url().scheme() != "https" {
            return Err(SigV4AuthorizerError::InvalidUri);
        }
        let uri = request
            .url()
            .as_str()
            .parse::<Uri>()
            .map_err(|_| SigV4AuthorizerError::InvalidUri)?;
        self.signer
            .sign_request(
                request.method().as_str(),
                &uri,
                request.headers(),
                SignableBody::Bytes(request.body()),
            )
            .await
            .map_err(map_signing_error)
    }
}

impl RequestAuthorizer for SigV4Authorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            self.sign(request).await.map_err(|error| match error {
                SigV4AuthorizerError::InvalidUri => AuthorizationErrorKind::InvalidRequest,
                SigV4AuthorizerError::CredentialUnavailable => {
                    AuthorizationErrorKind::CredentialUnavailable
                }
                SigV4AuthorizerError::InvalidConfiguration
                | SigV4AuthorizerError::SigningFailed => AuthorizationErrorKind::SigningFailed,
            })
        })
    }
}

fn map_signing_error(error: SigningError) -> SigV4AuthorizerError {
    match error {
        SigningError::Credentials(_) => SigV4AuthorizerError::CredentialUnavailable,
        SigningError::InsecureTransport | SigningError::InvalidUri | SigningError::InvalidUrl => {
            SigV4AuthorizerError::InvalidUri
        }
        _ => SigV4AuthorizerError::SigningFailed,
    }
}
