use std::{fmt, future::Future, pin::Pin};

use http::{HeaderMap, Method};
use http_request::method_telemetry_label;
use url::Url;

/// Closed authorisation failure categories. Secret material and provider
/// error text never cross the HTTP job boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorizationErrorKind {
    InsecureEndpoint,
    CredentialUnavailable,
    SigningFailed,
    InvalidRequest,
}

impl fmt::Display for AuthorizationErrorKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InsecureEndpoint => "authorisation requires HTTPS",
            Self::CredentialUnavailable => "authorisation credentials unavailable",
            Self::SigningFailed => "request authorisation failed",
            Self::InvalidRequest => "request could not be authorised",
        };
        formatter.write_str(message)
    }
}

/// The safe input presented to a registration-owned request authorizer.
pub struct AuthorizationRequest<'a> {
    method: &'a Method,
    url: &'a Url,
    /// Request headers, bounded by [`crate::MAX_HTTP_HEADER_COUNT`] and
    /// [`crate::MAX_HTTP_HEADER_BYTES`] before and after authorization.
    headers: HeaderMap,
    body: &'a [u8],
}

impl<'a> AuthorizationRequest<'a> {
    pub(crate) fn new(
        method: &'a Method,
        url: &'a Url,
        headers: HeaderMap,
        body: &'a [u8],
    ) -> Self {
        Self {
            method,
            url,
            headers,
            body,
        }
    }

    pub fn method(&self) -> &Method {
        self.method
    }

    pub fn url(&self) -> &Url {
        self.url
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        &mut self.headers
    }

    pub fn body(&self) -> &[u8] {
        self.body
    }

    pub fn into_headers(self) -> HeaderMap {
        self.headers
    }
}

impl fmt::Debug for AuthorizationRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequest")
            .field("method", &method_telemetry_label(self.method))
            .field("url", &"[REDACTED]")
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

pub type AuthorizationResult = Result<HeaderMap, AuthorizationErrorKind>;
pub type AuthorizationFuture<'a> = Pin<Box<dyn Future<Output = AuthorizationResult> + Send + 'a>>;

/// Narrow execution-time authorisation boundary used by `HttpExecutor`.
pub trait RequestAuthorizer: Send + Sync + 'static {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a>;
}

/// Authorizer for endpoints that do not require an additional protocol.
#[derive(Debug, Default)]
pub struct NoopAuthorizer;

impl RequestAuthorizer for NoopAuthorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        Box::pin(async move { Ok(request.into_headers()) })
    }
}
