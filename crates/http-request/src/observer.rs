use std::{
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};

use reqwest::StatusCode;

use crate::constants::{
    OUTCOME_ERROR, OUTCOME_RETRY, OUTCOME_SUCCESS, STATUS_CLASS_2XX, STATUS_CLASS_3XX,
    STATUS_CLASS_4XX, STATUS_CLASS_5XX, STATUS_CLASS_ERROR,
};

/// Closed outcome categories for a single HTTP request attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpRequestAttemptOutcome {
    Success,
    Retry,
    Error,
}

impl HttpRequestAttemptOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => OUTCOME_SUCCESS,
            Self::Retry => OUTCOME_RETRY,
            Self::Error => OUTCOME_ERROR,
        }
    }
}

/// Closed HTTP status class categories for telemetry and diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HttpRequestStatusClass {
    Status2xx,
    Status3xx,
    Status4xx,
    Status5xx,
    Error,
}

impl HttpRequestStatusClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Status2xx => STATUS_CLASS_2XX,
            Self::Status3xx => STATUS_CLASS_3XX,
            Self::Status4xx => STATUS_CLASS_4XX,
            Self::Status5xx => STATUS_CLASS_5XX,
            Self::Error => STATUS_CLASS_ERROR,
        }
    }
}

impl From<StatusCode> for HttpRequestStatusClass {
    fn from(status: StatusCode) -> Self {
        if status.is_success() {
            Self::Status2xx
        } else if status.is_redirection() {
            Self::Status3xx
        } else if status.is_client_error() {
            Self::Status4xx
        } else if status.is_server_error() {
            Self::Status5xx
        } else {
            Self::Error
        }
    }
}

impl From<Option<StatusCode>> for HttpRequestStatusClass {
    fn from(status: Option<StatusCode>) -> Self {
        status.map_or(Self::Error, Self::from)
    }
}

/// Safe, bounded facts for a single completed HTTP transport attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpRequestAttempt {
    method: &'static str,
    status: Option<StatusCode>,
    status_class: HttpRequestStatusClass,
    outcome: HttpRequestAttemptOutcome,
    attempt: u32,
    retrying: bool,
    elapsed: Duration,
}

impl HttpRequestAttempt {
    #[must_use]
    pub(crate) fn new(
        method: &'static str,
        status: Option<StatusCode>,
        attempt: u32,
        retrying: bool,
        elapsed: Duration,
    ) -> Self {
        let outcome = if retrying {
            HttpRequestAttemptOutcome::Retry
        } else if status.is_some() {
            HttpRequestAttemptOutcome::Success
        } else {
            HttpRequestAttemptOutcome::Error
        };
        let status_class = HttpRequestStatusClass::from(status);
        Self {
            method,
            status,
            status_class,
            outcome,
            attempt,
            retrying,
            elapsed,
        }
    }

    #[must_use]
    pub const fn method(&self) -> &'static str {
        self.method
    }

    #[must_use]
    pub const fn status(&self) -> Option<StatusCode> {
        self.status
    }

    #[must_use]
    pub const fn status_class(&self) -> HttpRequestStatusClass {
        self.status_class
    }

    #[must_use]
    pub const fn outcome(&self) -> HttpRequestAttemptOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn attempt(&self) -> u32 {
        self.attempt
    }

    #[must_use]
    pub const fn is_retrying(&self) -> bool {
        self.retrying
    }

    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }

    #[must_use]
    pub fn latency_ms(&self) -> f64 {
        self.elapsed.as_secs_f64() * 1000.0
    }
}

/// Observer for HTTP request attempt, retry, error, and latency facts.
pub trait HttpRequestObserver: Send + Sync + 'static {
    fn observe_attempt(&self, attempt: HttpRequestAttempt);
}

impl<F> HttpRequestObserver for F
where F: Fn(HttpRequestAttempt) + Send + Sync + 'static
{
    fn observe_attempt(&self, attempt: HttpRequestAttempt) {
        self(attempt);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopHttpRequestObserver;

impl HttpRequestObserver for NoopHttpRequestObserver {
    fn observe_attempt(&self, _attempt: HttpRequestAttempt) {}
}

static DEFAULT_OBSERVER: OnceLock<RwLock<Arc<dyn HttpRequestObserver>>> = OnceLock::new();

fn default_observer_cell() -> &'static RwLock<Arc<dyn HttpRequestObserver>> {
    DEFAULT_OBSERVER.get_or_init(|| RwLock::new(Arc::new(NoopHttpRequestObserver)))
}

#[must_use]
pub fn active_http_request_observer() -> Arc<dyn HttpRequestObserver> {
    match default_observer_cell().read() {
        Ok(guard) => Arc::clone(&guard),
        Err(poisoned) => Arc::clone(&poisoned.into_inner()),
    }
}

pub fn set_default_http_request_observer(
    observer: Arc<dyn HttpRequestObserver>,
) -> Arc<dyn HttpRequestObserver> {
    match default_observer_cell().write() {
        Ok(mut guard) => std::mem::replace(&mut *guard, observer),
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            std::mem::replace(&mut *guard, observer)
        }
    }
}

#[must_use]
pub fn reset_default_http_request_observer() -> Arc<dyn HttpRequestObserver> {
    set_default_http_request_observer(Arc::new(NoopHttpRequestObserver))
}
