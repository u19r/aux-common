use std::time::{Duration, SystemTime};

use bg_jobs::{JobOutcome, OutcomeCode, RetryClass, Timestamp, ValidationError};
use http::{HeaderMap, StatusCode, header::RETRY_AFTER};
use http_request::{HttpRequestErrorKind, HttpResponse};

/// The one durable result class produced by an HTTP attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpResultClass {
    Complete,
    Retry,
    DeadLetter,
}

/// Source and bounded value of a `Retry-After` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryAfterSource {
    Missing,
    Delta,
    Date,
    Malformed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryAfterDecision {
    source: RetryAfterSource,
    delay: Option<Duration>,
}

impl RetryAfterDecision {
    pub const fn missing() -> Self {
        Self {
            source: RetryAfterSource::Missing,
            delay: None,
        }
    }

    pub const fn source(self) -> RetryAfterSource {
        self.source
    }

    pub const fn delay(self) -> Option<Duration> {
        self.delay
    }

    pub const fn is_malformed(self) -> bool {
        matches!(self.source, RetryAfterSource::Malformed)
    }
}

/// A body-free, bounded classification suitable for conversion to a job
/// outcome. No response body, URL, header value, or raw transport error is
/// retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpClassification {
    class: HttpResultClass,
    status: Option<StatusCode>,
    retry_class: Option<RetryClass>,
    retry_after: RetryAfterDecision,
    code: &'static str,
}

impl HttpClassification {
    pub(crate) const fn retry_invariant() -> Self {
        Self {
            class: HttpResultClass::Retry,
            status: None,
            retry_class: Some(RetryClass::Transient),
            retry_after: RetryAfterDecision::missing(),
            code: "batch_invariant_retry",
        }
    }

    pub const fn class(self) -> HttpResultClass {
        self.class
    }

    pub const fn status(self) -> Option<StatusCode> {
        self.status
    }

    pub const fn retry_class(self) -> Option<RetryClass> {
        self.retry_class
    }

    pub const fn retry_after(self) -> RetryAfterDecision {
        self.retry_after
    }

    pub const fn code(self) -> &'static str {
        self.code
    }

    pub fn to_job_outcome(self, now: Timestamp) -> Result<JobOutcome, ValidationError> {
        let code = OutcomeCode::try_new(self.code)?;
        match self.class {
            HttpResultClass::Complete => Ok(JobOutcome::Complete(code)),
            HttpResultClass::DeadLetter => Ok(JobOutcome::DeadLetter { code }),
            HttpResultClass::Retry => {
                let not_before = self
                    .retry_after
                    .delay
                    .map(|delay| now.checked_add(delay))
                    .transpose()?;
                Ok(JobOutcome::Retry {
                    class: match self.retry_class {
                        Some(class) => class,
                        None => RetryClass::Transient,
                    },
                    not_before,
                    code,
                })
            }
        }
    }
}

/// Classifies one bounded response without consuming its body.
pub fn classify_response(
    response: &HttpResponse,
    max_response_bytes: usize,
    retry_after_max: Duration,
    retry_after_fallback: Duration,
    now: SystemTime,
) -> HttpClassification {
    if response
        .headers()
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > max_response_bytes)
    {
        return dead_letter(
            Some(response.status()),
            RetryAfterDecision::missing(),
            "http_response_too_large",
        );
    }
    classify_status(
        response.status(),
        response.headers(),
        retry_after_max,
        retry_after_fallback,
        now,
    )
}

/// Classifies a status and bounded retry hint without retaining response data.
pub fn classify_status(
    status: StatusCode,
    headers: &HeaderMap,
    retry_after_max: Duration,
    retry_after_fallback: Duration,
    now: SystemTime,
) -> HttpClassification {
    let retry_after = parse_retry_after(headers, now, retry_after_max, retry_after_fallback);
    if status.is_success() {
        return complete(status, retry_after);
    }
    if is_retryable_status(status) {
        return retry(Some(status), retry_after, "http_retry");
    }
    dead_letter(Some(status), retry_after, "http_rejected")
}

/// Converts a transport error into the same single-owner result model.
pub fn classify_transport(
    kind: HttpRequestErrorKind,
    retry_after_fallback: Duration,
) -> HttpClassification {
    let retry_after = RetryAfterDecision {
        source: RetryAfterSource::Missing,
        delay: Some(retry_after_fallback),
    };
    match kind {
        HttpRequestErrorKind::Timeout
        | HttpRequestErrorKind::Connect
        | HttpRequestErrorKind::ResponseBody => retry(
            StatusCode::from_u16(599).ok(),
            retry_after,
            "http_transport_retry",
        ),
        _ => dead_letter(
            None,
            RetryAfterDecision::missing(),
            "http_transport_rejected",
        ),
    }
}

pub(crate) fn classify_response_body_error(
    status: StatusCode,
    kind: HttpRequestErrorKind,
    retry_after_fallback: Duration,
) -> HttpClassification {
    match kind {
        HttpRequestErrorKind::Timeout | HttpRequestErrorKind::Connect => {
            classify_transport(kind, retry_after_fallback)
        }
        HttpRequestErrorKind::ResponseBody => retry(
            Some(status),
            RetryAfterDecision {
                source: RetryAfterSource::Missing,
                delay: Some(retry_after_fallback),
            },
            "http_response_retry",
        ),
        HttpRequestErrorKind::ResponseTooLarge => dead_letter(
            Some(status),
            RetryAfterDecision::missing(),
            "http_response_too_large",
        ),
        _ => dead_letter(
            Some(status),
            RetryAfterDecision::missing(),
            "http_response_rejected",
        ),
    }
}

/// Parses `Retry-After` as a bounded delta-seconds or HTTP date.
pub fn parse_retry_after(
    headers: &HeaderMap,
    now: SystemTime,
    maximum: Duration,
    fallback: Duration,
) -> RetryAfterDecision {
    let Some(value) = headers.get(RETRY_AFTER) else {
        return RetryAfterDecision::missing();
    };
    let Ok(value) = value.to_str() else {
        return malformed_retry_after(fallback.min(maximum));
    };
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return bounded_retry_after(
            RetryAfterSource::Delta,
            Duration::from_secs(seconds),
            maximum,
        );
    }
    let Ok(date) = httpdate::parse_http_date(value) else {
        return malformed_retry_after(fallback.min(maximum));
    };
    let delay = match date.duration_since(now) {
        Ok(delay) => delay,
        Err(_) => Duration::ZERO,
    };
    bounded_retry_after(RetryAfterSource::Date, delay, maximum)
}

fn bounded_retry_after(
    source: RetryAfterSource,
    delay: Duration,
    maximum: Duration,
) -> RetryAfterDecision {
    RetryAfterDecision {
        source,
        delay: Some(delay.min(maximum)),
    }
}

fn malformed_retry_after(fallback: Duration) -> RetryAfterDecision {
    RetryAfterDecision {
        source: RetryAfterSource::Malformed,
        delay: Some(fallback),
    }
}

fn complete(status: StatusCode, retry_after: RetryAfterDecision) -> HttpClassification {
    HttpClassification {
        class: HttpResultClass::Complete,
        status: Some(status),
        retry_class: None,
        retry_after,
        code: "http_complete",
    }
}

fn retry(
    status: Option<StatusCode>,
    retry_after: RetryAfterDecision,
    code: &'static str,
) -> HttpClassification {
    let retry_class = if status == Some(StatusCode::TOO_MANY_REQUESTS) {
        RetryClass::Throttled
    } else {
        RetryClass::Transient
    };
    HttpClassification {
        class: HttpResultClass::Retry,
        status,
        retry_class: Some(retry_class),
        retry_after,
        code,
    }
}

fn dead_letter(
    status: Option<StatusCode>,
    retry_after: RetryAfterDecision,
    code: &'static str,
) -> HttpClassification {
    HttpClassification {
        class: HttpResultClass::DeadLetter,
        status,
        retry_class: None,
        retry_after,
        code,
    }
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}
