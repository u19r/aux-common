use std::time::{Duration, SystemTime};

use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use aws_credentials::{CredentialSource, DefaultChainCredentialsProvider, static_credentials};
use aws_sigv4::{
    http_request::{
        PayloadChecksumKind, SignableRequest, SignatureLocation, SigningParams, SigningSettings,
        sign,
    },
    sign::v4,
};
use aws_smithy_runtime_api::client::identity::Identity;
use http::{HeaderMap, HeaderName, HeaderValue, Uri, header::AUTHORIZATION};
use url::Url;

use crate::{SignableBody, SigningError};

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

        Ok(Self {
            region: region.to_owned(),
            credentials: provider,
            service_name: service_name.to_string(),
        })
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
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(SigningError::from)?;

        let mut headers = base_headers.clone();
        if !headers.contains_key(http::header::HOST)
            && let Some(authority) = uri.authority()
        {
            let host_value = HeaderValue::from_str(authority.as_str())
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            headers.insert(http::header::HOST, host_value);
        }

        let mut header_pairs = Vec::with_capacity(headers.len());
        for (name, value) in &headers {
            let value_str = value
                .to_str()
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            header_pairs.push((name.as_str().to_owned(), value_str.to_owned()));
        }

        let signable = SignableRequest::new(
            method,
            uri.to_string(),
            header_pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
        )
        .map_err(|err| SigningError::PrepareRequest(err.to_string()))?;

        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;

        let identity = Identity::new(credentials.clone(), credentials.expiry());
        let signing_params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service_name)
            .time(signing_time)
            .settings(settings)
            .build()
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into();

        let (instructions, _) = sign(signable, &signing_params)
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into_parts();

        for (name, value) in instructions.headers() {
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| SigningError::InvalidHeaderName)?;
            let header_value =
                HeaderValue::from_str(value).map_err(|_| SigningError::InvalidHeaderValue)?;
            headers.insert(header_name, header_value);
        }
        for sensitive_name in [AUTHORIZATION.as_str(), "x-amz-security-token"] {
            if let Some(value) = headers.get_mut(sensitive_name) {
                value.set_sensitive(true);
            }
        }

        Ok(headers)
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
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(SigningError::from)?;

        let mut headers = base_headers.clone();
        if !headers.contains_key(http::header::HOST)
            && let Some(authority) = uri.authority()
        {
            let host_value = HeaderValue::from_str(authority.as_str())
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            headers.insert(http::header::HOST, host_value);
        }

        let mut header_pairs = Vec::with_capacity(headers.len());
        for (name, value) in &headers {
            let value_str = value
                .to_str()
                .map_err(|_| SigningError::InvalidHeaderValue)?;
            header_pairs.push((name.as_str().to_owned(), value_str.to_owned()));
        }

        let signable = SignableRequest::new(
            method,
            uri.to_string(),
            header_pairs
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
            body,
        )
        .map_err(|err| SigningError::PrepareRequest(err.to_string()))?;

        let mut settings = SigningSettings::default();
        settings.payload_checksum_kind = PayloadChecksumKind::NoHeader;
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(expires_in);

        let identity = Identity::new(credentials.clone(), credentials.expiry());
        let signing_params: SigningParams = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(&self.service_name)
            .time(signing_time)
            .settings(settings)
            .build()
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into();

        let (instructions, _) = sign(signable, &signing_params)
            .map_err(|err| SigningError::Signing(err.to_string()))?
            .into_parts();

        let mut url = Url::parse(&uri.to_string())
            .map_err(|err| SigningError::InvalidUrl(err.to_string()))?;
        if !instructions.params().is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (name, value) in instructions.params() {
                pairs.append_pair(name, value.as_ref());
            }
        }

        url.as_str()
            .parse::<Uri>()
            .map_err(|err| SigningError::InvalidUri(err.to_string()))
    }
}
