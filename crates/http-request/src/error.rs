use std::fmt;

use http::StatusCode;
use thiserror::Error;

#[derive(Error)]
pub enum HttpRequestError {
    #[error("request build failed")]
    Build,
    #[error("request failed: {kind:?}")]
    Transport { kind: HttpRequestErrorKind },
    #[error("request body too large: {size} > {max}")]
    RequestTooLarge { size: usize, max: usize },
    #[error("request body size unknown (max {max})")]
    RequestSizeUnknown { max: usize },
    #[error("request body not cloneable for retry or redirect")]
    RequestNotCloneable,
    #[error("response body could not be read")]
    ResponseBody,
    #[error("response body too large: {size} > {max}")]
    ResponseTooLarge { size: usize, max: usize },
    #[error("response cache lifetime is too large: {seconds} seconds")]
    CacheTtlOverflow { seconds: u64 },
    #[error("http status {status}")]
    HttpStatus {
        status: StatusCode,
        body: Option<String>,
    },
    #[error("redirect blocked: {reason}")]
    RedirectBlocked { reason: &'static str },
    #[error("ssrf blocked: {reason}")]
    SsrfBlocked { reason: &'static str },
    #[error("invalid URL")]
    InvalidUrl,
    #[error("response body could not be decoded")]
    Decode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestErrorKind {
    Build,
    Timeout,
    Connect,
    Request,
    Body,
    ResponseBody,
    ResponseTooLarge,
    Status,
    Redirect,
    Ssrf,
    InvalidUrl,
    Decode,
    InvalidCacheTtl,
    Unknown,
}

/// Whether an HTTP failure proves that no request reached the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestDispatchStatus {
    /// Request bytes are known not to have reached the destination.
    NotDispatched,
    /// Request bytes may have reached the destination before the failure.
    PossiblyDispatched,
}

impl fmt::Debug for HttpRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build => formatter.write_str("Build"),
            Self::Transport { kind } => formatter
                .debug_struct("Transport")
                .field("kind", kind)
                .finish(),
            Self::HttpStatus { status, body } => formatter
                .debug_struct("HttpStatus")
                .field("status", status)
                .field("body", &body.as_ref().map(|_| "[REDACTED]"))
                .finish(),
            other => write!(formatter, "{other}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, HttpRequestError>;

impl HttpRequestError {
    #[must_use]
    pub fn kind(&self) -> HttpRequestErrorKind {
        match self {
            HttpRequestError::Build => HttpRequestErrorKind::Build,
            HttpRequestError::Transport { kind } => *kind,
            HttpRequestError::RequestTooLarge { .. }
            | HttpRequestError::RequestSizeUnknown { .. }
            | HttpRequestError::RequestNotCloneable => HttpRequestErrorKind::Body,
            HttpRequestError::ResponseBody => HttpRequestErrorKind::ResponseBody,
            HttpRequestError::ResponseTooLarge { .. } => HttpRequestErrorKind::ResponseTooLarge,
            HttpRequestError::CacheTtlOverflow { .. } => HttpRequestErrorKind::InvalidCacheTtl,
            HttpRequestError::HttpStatus { .. } => HttpRequestErrorKind::Status,
            HttpRequestError::RedirectBlocked { .. } => HttpRequestErrorKind::Redirect,
            HttpRequestError::SsrfBlocked { .. } => HttpRequestErrorKind::Ssrf,
            HttpRequestError::InvalidUrl => HttpRequestErrorKind::InvalidUrl,
            HttpRequestError::Decode => HttpRequestErrorKind::Decode,
        }
    }

    /// Classifies whether a caller may safely treat the operation as not
    /// applied.
    #[must_use]
    pub const fn dispatch_status(&self) -> HttpRequestDispatchStatus {
        match self {
            Self::Build
            | Self::RequestTooLarge { .. }
            | Self::RequestSizeUnknown { .. }
            | Self::SsrfBlocked { .. }
            | Self::InvalidUrl
            | Self::Transport {
                kind:
                    HttpRequestErrorKind::Build
                    | HttpRequestErrorKind::Connect
                    | HttpRequestErrorKind::Ssrf
                    | HttpRequestErrorKind::InvalidUrl,
            } => HttpRequestDispatchStatus::NotDispatched,
            Self::Transport { .. }
            | Self::RequestNotCloneable
            | Self::ResponseBody
            | Self::ResponseTooLarge { .. }
            | Self::CacheTtlOverflow { .. }
            | Self::HttpStatus { .. }
            | Self::RedirectBlocked { .. }
            | Self::Decode => HttpRequestDispatchStatus::PossiblyDispatched,
        }
    }
}

impl From<reqwest::Error> for HttpRequestError {
    fn from(error: reqwest::Error) -> Self {
        let kind = if error.is_connect() {
            HttpRequestErrorKind::Connect
        } else if error.is_timeout() {
            HttpRequestErrorKind::Timeout
        } else if error.is_body() {
            HttpRequestErrorKind::Body
        } else if error.is_request() {
            HttpRequestErrorKind::Request
        } else if error.status().is_some() {
            HttpRequestErrorKind::Status
        } else {
            HttpRequestErrorKind::Unknown
        };
        let _ = error;
        HttpRequestError::Transport { kind }
    }
}
