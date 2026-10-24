use std::sync::{Arc, OnceLock};

use http_request::{HttpRequestAttempt, HttpRequestAttemptOutcome, HttpRequestObserver};

use crate::{
    CounterMetric, HistogramMetric,
    constants::{LABEL_HTTP_METHOD, LABEL_HTTP_OUTCOME, LABEL_HTTP_STATUS_CLASS},
    counter, histogram,
};

/// Projects [`HttpRequestAttempt`] observations into [`CounterMetric`] and
/// [`HistogramMetric`] handles without introducing a `http-request ->
/// metrics-facade` dependency edge.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpRequestMetricsObserver;

impl HttpRequestMetricsObserver {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn observe(&self, attempt: HttpRequestAttempt) {
        let method = attempt.method();
        let outcome = attempt.outcome().as_str();
        let status_label = attempt.status_class().as_str();

        if attempt.outcome() == HttpRequestAttemptOutcome::Error {
            counter!(
                CounterMetric::MetricHttpRequestErrors,
                LABEL_HTTP_METHOD => method
            )
            .increment(1);
        }

        counter!(
            CounterMetric::MetricHttpRequestAttempts,
            LABEL_HTTP_METHOD => method,
            LABEL_HTTP_OUTCOME => outcome,
            LABEL_HTTP_STATUS_CLASS => status_label
        )
        .increment(1);

        histogram!(
            HistogramMetric::MetricHttpRequestLatencyMs,
            LABEL_HTTP_METHOD => method,
            LABEL_HTTP_OUTCOME => outcome,
            LABEL_HTTP_STATUS_CLASS => status_label
        )
        .record(attempt.latency_ms());

        if attempt.is_retrying() {
            counter!(
                CounterMetric::MetricHttpRequestRetries,
                LABEL_HTTP_METHOD => method
            )
            .increment(1);
        }
    }
}

impl HttpRequestObserver for HttpRequestMetricsObserver {
    fn observe_attempt(&self, attempt: HttpRequestAttempt) {
        self.observe(attempt);
    }
}

#[must_use]
pub const fn http_request_observer() -> HttpRequestMetricsObserver {
    HttpRequestMetricsObserver::new()
}

pub fn install_http_request_observer() -> Arc<dyn HttpRequestObserver> {
    http_request::set_default_http_request_observer(Arc::new(HttpRequestMetricsObserver))
}

pub(crate) fn ensure_default_http_request_observer_installed() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = install_http_request_observer();
    });
}
