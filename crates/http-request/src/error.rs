use http::StatusCode;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpRequestError {
    #[error("request build failed: {source}")]
    Build {
        #[source]
        source: reqwest::Error,
    },
    #[error("request failed: {source}")]
    Transport {
        kind: HttpRequestErrorKind,
        #[source]
        source: reqwest::Error,
    },
    #[error("request body too large: {size} > {max}")]
    RequestTooLarge { size: usize, max: usize },
    #[error("request body size unknown (max {max})")]
    RequestSizeUnknown { max: usize },
    #[error("request body not cloneable for retry or redirect")]
    RequestNotCloneable,
    #[error("response body too large: {size} > {max}")]
    ResponseTooLarge { size: usize, max: usize },
    #[error("http status {status}")]
    HttpStatus {
        status: StatusCode,
        body: Option<String>,
    },
    #[error("redirect blocked: {reason}")]
    RedirectBlocked { reason: &'static str },
    #[error("ssrf blocked: {reason}")]
    SsrfBlocked { reason: &'static str },
    #[error("invalid url: {message}")]
    InvalidUrl { message: String },
    #[error("response decode failed: {message}")]
    Decode { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpRequestErrorKind {
    Build,
    Timeout,
    Connect,
    Request,
    Body,
    Status,
    Redirect,
    Ssrf,
    InvalidUrl,
    Decode,
    Unknown,
}

pub type Result<T> = std::result::Result<T, HttpRequestError>;

impl HttpRequestError {
    #[must_use]
    pub fn kind(&self) -> HttpRequestErrorKind {
        match self {
            HttpRequestError::Build { .. } => HttpRequestErrorKind::Build,
            HttpRequestError::Transport { kind, .. } => *kind,
            HttpRequestError::RequestTooLarge { .. }
            | HttpRequestError::RequestSizeUnknown { .. }
            | HttpRequestError::RequestNotCloneable
            | HttpRequestError::ResponseTooLarge { .. } => HttpRequestErrorKind::Body,
            HttpRequestError::HttpStatus { .. } => HttpRequestErrorKind::Status,
            HttpRequestError::RedirectBlocked { .. } => HttpRequestErrorKind::Redirect,
            HttpRequestError::SsrfBlocked { .. } => HttpRequestErrorKind::Ssrf,
            HttpRequestError::InvalidUrl { .. } => HttpRequestErrorKind::InvalidUrl,
            HttpRequestError::Decode { .. } => HttpRequestErrorKind::Decode,
        }
    }
}

impl From<reqwest::Error> for HttpRequestError {
    fn from(error: reqwest::Error) -> Self {
        let kind = if error.is_timeout() {
            HttpRequestErrorKind::Timeout
        } else if error.is_connect() {
            HttpRequestErrorKind::Connect
        } else if error.is_body() {
            HttpRequestErrorKind::Body
        } else if error.is_request() {
            HttpRequestErrorKind::Request
        } else if error.status().is_some() {
            HttpRequestErrorKind::Status
        } else {
            HttpRequestErrorKind::Unknown
        };
        HttpRequestError::Transport {
            kind,
            source: error,
        }
    }
}
