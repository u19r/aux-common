use std::time::{Duration, SystemTime};

use aws_credentials::{
    CredentialSource, DefaultChainCredentialsProvider, ProvideCredentials,
    SharedCredentialsProvider, static_credentials,
};
use http::{HeaderMap, Uri};

use crate::{
    SignableBody, SigningError,
    constants::MAX_PRESIGN_EXPIRY,
    signing::{SigningContext, SigningRequest},
};

#[derive(Debug, Clone)]
pub struct AwsRequestSigner {
    region: String,
    credentials: SharedCredentialsProvider,
    service_name: String,
}

impl AwsRequestSigner {
    pub fn new(
        region: &str,
        credentials: CredentialSource,
        service_name: &str,
    ) -> Result<Self, SigningError> {
        let provider = match credentials {
            CredentialSource::DefaultChain => {
                let provider = DefaultChainCredentialsProvider::new()?;
                SharedCredentialsProvider::new(provider)
            }
            CredentialSource::Static(creds) => {
                SharedCredentialsProvider::new(static_credentials(&creds))
            }
        };

        Ok(Self::new_with_provider(region, provider, service_name))
    }

    /// Creates a signer backed by the supplied credentials provider.
    ///
    /// The provider is the sole credential source for this signer. This is
    /// useful when the caller owns credential loading, and it avoids silently
    /// consulting an ambient default chain.
    #[must_use]
    pub fn new_with_provider(
        region: &str,
        credentials: SharedCredentialsProvider,
        service_name: &str,
    ) -> Self {
        Self {
            region: region.to_owned(),
            credentials,
            service_name: service_name.to_string(),
        }
    }

    pub async fn sign(
        &self,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: &[u8],
    ) -> Result<HeaderMap, SigningError> {
        self.sign_request("POST", uri, base_headers, SignableBody::Bytes(body))
            .await
    }

    pub async fn sign_request(
        &self,
        method: &str,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: SignableBody<'_>,
    ) -> Result<HeaderMap, SigningError> {
        self.sign_request_at(method, uri, base_headers, body, SystemTime::now())
            .await
    }

    pub(crate) async fn sign_request_at(
        &self,
        method: &str,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: SignableBody<'_>,
        signing_time: SystemTime,
    ) -> Result<HeaderMap, SigningError> {
        require_https(uri)?;
        let credentials = self.credentials.provide_credentials().await?;
        let context =
            SigningContext::try_new(&self.region, &self.service_name, credentials, signing_time)?;
        context.sign_headers(&SigningRequest {
            method,
            uri,
            headers: base_headers,
            body,
        })
    }

    pub async fn presign_request(
        &self,
        method: &str,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: SignableBody<'_>,
        expires_in: Duration,
    ) -> Result<Uri, SigningError> {
        self.presign_request_at(
            method,
            uri,
            base_headers,
            body,
            expires_in,
            SystemTime::now(),
        )
        .await
    }

    pub(crate) async fn presign_request_at(
        &self,
        method: &str,
        uri: &Uri,
        base_headers: &HeaderMap,
        body: SignableBody<'_>,
        expires_in: Duration,
        signing_time: SystemTime,
    ) -> Result<Uri, SigningError> {
        require_https(uri)?;
        validate_presign_expiry(expires_in)?;
        let credentials = self.credentials.provide_credentials().await?;
        let context =
            SigningContext::try_new(&self.region, &self.service_name, credentials, signing_time)?;
        context.presign(
            &SigningRequest {
                method,
                uri,
                headers: base_headers,
                body,
            },
            expires_in,
        )
    }
}

fn require_https(uri: &Uri) -> Result<(), SigningError> {
    if uri.scheme_str() == Some("https") {
        Ok(())
    } else {
        Err(SigningError::InsecureTransport)
    }
}

fn validate_presign_expiry(expires_in: Duration) -> Result<(), SigningError> {
    if expires_in.as_secs() == 0 || expires_in > MAX_PRESIGN_EXPIRY {
        return Err(SigningError::InvalidPresignExpiry);
    }
    Ok(())
}
