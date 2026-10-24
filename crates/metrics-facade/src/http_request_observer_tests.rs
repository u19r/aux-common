use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::HeaderMap;
use http_request::{
    HttpClientBuilder, HttpRequestError, HttpRequestErrorKind, HttpResponse, RetryConfig,
    StatusCode, Transport, TransportFuture, Url,
    reqwest::{Method, Request},
};

use crate::{
    CounterMetric, GaugeMetric, HistogramMetric, MetricLabel, MetricsFacade, http_request_observer,
    recorder_tests::METRICS_FACADE_TEST_LOCK, set_metrics_facade,
};

#[derive(Clone, Debug, Default)]
struct RecordingHttpMetricsFacade {
    events: Arc<Mutex<Vec<String>>>,
}

impl RecordingHttpMetricsFacade {
    fn events(&self) -> Vec<String> {
        self.events.lock().expect("events lock").clone()
    }
}

impl MetricsFacade for RecordingHttpMetricsFacade {
    fn increment_counter(&self, metric: CounterMetric, labels: &[MetricLabel], value: u64) {
        let formatted = labels
            .iter()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect::<Vec<_>>()
            .join("|");
        self.events
            .lock()
            .expect("events lock")
            .push(format!("counter:{}:{formatted}:{value}", metric.name()));
    }

    fn absolute_counter(&self, _metric: CounterMetric, _labels: &[MetricLabel], _value: u64) {}

    fn increment_gauge(&self, _metric: GaugeMetric, _labels: &[MetricLabel], _value: f64) {}

    fn decrement_gauge(&self, _metric: GaugeMetric, _labels: &[MetricLabel], _value: f64) {}

    fn set_gauge(&self, _metric: GaugeMetric, _labels: &[MetricLabel], _value: f64) {}

    fn record_histogram(&self, metric: HistogramMetric, labels: &[MetricLabel], _value: f64) {
        let formatted = labels
            .iter()
            .map(|label| format!("{}={}", label.key(), label.value()))
            .collect::<Vec<_>>()
            .join("|");
        self.events
            .lock()
            .expect("events lock")
            .push(format!("histogram:{}:{formatted}", metric.name()));
    }
}

struct SequenceTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl std::fmt::Debug for SequenceTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SequenceTransport")
    }
}

impl SequenceTransport {
    fn new(responses: Vec<Result<HttpResponse, HttpRequestError>>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl Transport for SequenceTransport {
    fn send(&self, _request: Request) -> TransportFuture {
        let next = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("queued response");
        Box::pin(async move { next })
    }
}

#[test]
fn given_http_client_with_metrics_observer_when_request_retries_once_and_succeeds_then_observations_preserve_contract()
 {
    // Scenario B25: Preserve HTTP metric observations without a dependency
    // cycle
    let url = Url::parse("https://example.test/resource").expect("url");
    let transport = SequenceTransport::new(vec![
        Ok(HttpResponse::from_mock(
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            Vec::new(),
            url.clone(),
        )),
        Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            b"ok".to_vec(),
            url,
        )),
    ]);
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .with_observer(http_request_observer())
        .build()
        .expect("build client");

    let events = {
        let _guard = METRICS_FACADE_TEST_LOCK.lock().expect("test lock");
        let facade = RecordingHttpMetricsFacade::default();
        let previous = set_metrics_facade(Arc::new(facade.clone()));
        let response = observer_test_runtime()
            .block_on(
                client
                    .request(Method::GET, "https://example.test/resource")
                    .send(),
            )
            .expect("retried response");
        assert_eq!(response.status(), StatusCode::OK);
        let recorded = facade.events();
        set_metrics_facade(previous);
        recorded
    };

    assert_eq!(
        events,
        vec![
            "counter:http.request.attempts:method=GET|outcome=retry|status_class=5xx:1",
            "histogram:http.request.latency.ms:method=GET|outcome=retry|status_class=5xx",
            "counter:http.request.retries:method=GET:1",
            "counter:http.request.attempts:method=GET|outcome=success|status_class=2xx:1",
            "histogram:http.request.latency.ms:method=GET|outcome=success|status_class=2xx",
        ]
    );
}

#[test]
fn given_http_client_with_metrics_observer_when_transport_fails_then_error_counter_is_recorded() {
    let transport = SequenceTransport::new(vec![Err(HttpRequestError::Transport {
        kind: HttpRequestErrorKind::Timeout,
    })]);
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .with_observer(http_request_observer())
        .build()
        .expect("build client");

    let events = {
        let _guard = METRICS_FACADE_TEST_LOCK.lock().expect("test lock");
        let facade = RecordingHttpMetricsFacade::default();
        let previous = set_metrics_facade(Arc::new(facade.clone()));
        let error = observer_test_runtime()
            .block_on(
                client
                    .request(Method::POST, "https://example.test/resource")
                    .send(),
            )
            .err()
            .expect("transport timeout");
        assert_eq!(error.kind(), HttpRequestErrorKind::Timeout);
        let recorded = facade.events();
        set_metrics_facade(previous);
        recorded
    };

    assert_eq!(
        events,
        vec![
            "counter:http.request.errors:method=POST:1",
            "counter:http.request.attempts:method=POST|outcome=error|status_class=error:1",
            "histogram:http.request.latency.ms:method=POST|outcome=error|status_class=error",
        ]
    );
}

// These synchronous tests own the process-global facade under the shared test
// lock. Async transport work runs on a private runtime, rather than blocking an
// async test executor.
fn observer_test_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("observer test runtime")
}
