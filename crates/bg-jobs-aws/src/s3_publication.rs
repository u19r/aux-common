use aws_sigv4_signing::{AwsRequestSigner, SignableBody};
use http::{
    HeaderMap, HeaderValue, Uri,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, IF_NONE_MATCH},
};
use http_request::{
    HttpClient, HttpResponse, Url,
    reqwest::{Body, Request, StatusCode},
};

use crate::constants::S3_SOURCE_IDENTITY_HEADER;

/// Caller-owned destination and immutable source description. No job policy or
/// application persistence enters the AWS adapter.
pub struct S3ObjectInput {
    pub url: Url,
    pub source_identity: String,
    pub content_length: u64,
    pub content_type: String,
    pub content_encoding: Option<String>,
}

pub struct S3ObjectPublication {
    url: Url,
    headers: HeaderMap,
    content_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3PublicationError {
    InvalidObject,
    SigningFailed,
    RequestFailed,
    IdentityMismatch,
    Conflict,
}

impl std::fmt::Display for S3PublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidObject => "invalid S3 publication",
            Self::SigningFailed => "S3 publication signing failed",
            Self::RequestFailed => "S3 publication request failed",
            Self::IdentityMismatch => "S3 publication identity mismatch",
            Self::Conflict => "S3 publication conflict",
        })
    }
}

impl std::error::Error for S3PublicationError {}

impl TryFrom<S3ObjectInput> for S3ObjectPublication {
    type Error = S3PublicationError;

    fn try_from(input: S3ObjectInput) -> Result<Self, Self::Error> {
        if !matches!(input.url.scheme(), "http" | "https")
            || !input.url.username().is_empty()
            || input.url.password().is_some()
            || input.url.fragment().is_some()
            || input.source_identity.is_empty()
        {
            return Err(S3PublicationError::InvalidObject);
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            S3_SOURCE_IDENTITY_HEADER,
            HeaderValue::from_str(&input.source_identity)
                .map_err(|_| S3PublicationError::InvalidObject)?,
        );
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(&input.content_type)
                .map_err(|_| S3PublicationError::InvalidObject)?,
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from(input.content_length));
        headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        if let Some(encoding) = input.content_encoding {
            headers.insert(
                CONTENT_ENCODING,
                HeaderValue::from_str(&encoding).map_err(|_| S3PublicationError::InvalidObject)?,
            );
        }
        Ok(Self {
            url: input.url,
            headers,
            content_length: input.content_length,
        })
    }
}

/// One conditional streaming PUT, preceded by reconciliation. Retries and
/// cancellation remain with the common job runtime and bounded HTTP client.
pub struct S3ObjectPublisher<'a> {
    client: &'a HttpClient,
    signer: &'a AwsRequestSigner,
}

impl<'a> S3ObjectPublisher<'a> {
    pub fn new(client: &'a HttpClient, signer: &'a AwsRequestSigner) -> Self {
        Self { client, signer }
    }

    /// A subsequent call reconciles a lost PUT response before resubmission.
    /// Conditional creation also prevents a stale worker from replacing bytes.
    /// https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
    pub async fn publish(
        &self,
        object: &S3ObjectPublication,
        body: Body,
    ) -> Result<(), S3PublicationError> {
        if self.has_matching_object(object).await? {
            return Ok(());
        }
        let request = self
            .client
            .put(object.url.clone())
            .headers(object.headers.clone())
            .body(body)
            .build()
            .map_err(|_| S3PublicationError::InvalidObject)?;
        let response = self.submit_request(request).await?;
        if response.status().is_success() {
            return Ok(());
        }
        if matches!(
            response.status(),
            StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT
        ) {
            return if self.has_matching_object(object).await? {
                Ok(())
            } else {
                Err(S3PublicationError::Conflict)
            };
        }
        Err(S3PublicationError::RequestFailed)
    }

    async fn has_matching_object(
        &self,
        object: &S3ObjectPublication,
    ) -> Result<bool, S3PublicationError> {
        let request = self
            .client
            .head(object.url.clone())
            .build()
            .map_err(|_| S3PublicationError::InvalidObject)?;
        let response = self.submit_request(request).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(false);
        }
        if !response.status().is_success() {
            return Err(S3PublicationError::RequestFailed);
        }
        let bytes = response
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if bytes != Some(object.content_length)
            || response.headers().get(S3_SOURCE_IDENTITY_HEADER)
                != object.headers.get(S3_SOURCE_IDENTITY_HEADER)
        {
            return Err(S3PublicationError::IdentityMismatch);
        }
        Ok(true)
    }

    async fn submit_request(
        &self,
        mut request: Request,
    ) -> Result<HttpResponse, S3PublicationError> {
        let uri = request
            .url()
            .as_str()
            .parse::<Uri>()
            .map_err(|_| S3PublicationError::InvalidObject)?;
        let headers = self
            .signer
            .sign_request(
                request.method().as_str(),
                &uri,
                request.headers(),
                SignableBody::UnsignedPayload,
            )
            .await
            .map_err(|_| S3PublicationError::SigningFailed)?;
        *request.headers_mut() = headers;
        self.client
            .execute(request)
            .await
            .map_err(|_| S3PublicationError::RequestFailed)
    }
}
