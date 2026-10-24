use std::fmt;

use bg_jobs::ValidationError;

use crate::authorizer::AuthorizationErrorKind;

/// Construction or execution failures that are safe to expose to a caller.
///
/// The error deliberately contains no URL, body, header, credential, or raw
/// transport text. HTTP transport failures that are retryable are represented
/// by [`crate::HttpClassification`] instead of this boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpJobError {
    Validation(ValidationError),
    UnknownPolicy,
    NoPolicies,
    DuplicatePolicy,
    EndpointNotApproved,
    InsecureEndpoint,
    RequestBodyTooLarge,
    ResponseBodyTooLarge,
    HeaderCountTooLarge,
    HeaderBytesTooLarge,
    SensitiveHeader,
    SensitiveProjection,
    BatchInvariant,
    InvalidDeadline,
    RequestBuild,
    Authorization(AuthorizationErrorKind),
}

impl fmt::Display for HttpJobError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Validation(error) => return error.fmt(formatter),
            Self::UnknownPolicy => "HTTP policy is not registered",
            Self::NoPolicies => "at least one HTTP policy is required",
            Self::DuplicatePolicy => "HTTP policy ID is already registered",
            Self::EndpointNotApproved => "HTTP endpoint is not approved",
            Self::InsecureEndpoint => "HTTP endpoint must use HTTPS",
            Self::RequestBodyTooLarge => "HTTP request body exceeds its bound",
            Self::ResponseBodyTooLarge => "HTTP response body exceeds its bound",
            Self::HeaderCountTooLarge => "HTTP request contains too many headers",
            Self::HeaderBytesTooLarge => "HTTP request headers exceed their aggregate bound",
            Self::SensitiveHeader => "HTTP request contains a forbidden sensitive header",
            Self::SensitiveProjection => {
                "HTTP diagnostic projection cannot include secret material"
            }
            Self::BatchInvariant => "HTTP batch response violated its item contract",
            Self::InvalidDeadline => "HTTP request deadline is outside its policy bound",
            Self::RequestBuild => "HTTP request could not be built",
            Self::Authorization(kind) => return kind.fmt(formatter),
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for HttpJobError {}

impl From<ValidationError> for HttpJobError {
    fn from(error: ValidationError) -> Self {
        Self::Validation(error)
    }
}
