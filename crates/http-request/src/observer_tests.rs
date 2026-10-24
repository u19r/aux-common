use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::HeaderMap;
use reqwest::{Method, Request, StatusCode, Url};

use crate::{
    HttpClientBuilder, HttpRequestAttempt, HttpRequestAttemptOutcome, HttpRequestError,
    HttpRequestErrorKind, HttpRequestStatusClass, HttpResponse, RetryConfig, Transport,
    TransportFuture,
};

struct StubTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl std::fmt::Debug for StubTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("StubTransport")
    }
}

impl StubTransport {
    fn new(responses: Vec<Result<HttpResponse, HttpRequestError>>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl Transport for StubTransport {
    fn send(&self, _request: Request) -> TransportFuture {
        let response = self
            .responses
            .lock()
            .expect("stub transport lock")
            .pop_front()
            .expect("stub transport response");
        Box::pin(async move { response })
    }
}

#[tokio::test]
async fn given_client_with_observer_when_request_retries_then_succeeds_then_attempt_facts_are_recorded()
 {
    let observed = Arc::new(Mutex::new(Vec::<HttpRequestAttempt>::new()));
    let observed_clone = Arc::clone(&observed);
    let url = Url::parse("https://example.test/resource").expect("valid url");
    let transport = StubTransport::new(vec![
        Ok(HttpResponse::from_mock(
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            Vec::new(),
            url.clone(),
        )),
        Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            b"{}".to_vec(),
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
        .with_observer(move |attempt: HttpRequestAttempt| {
            observed_clone.lock().expect("observed lock").push(attempt);
        })
        .build()
        .expect("build client");

    let response = client
        .request(Method::GET, "https://example.test/resource")
        .send()
        .await
        .expect("request succeeds after retry");

    assert_eq!(response.status(), StatusCode::OK);
    let attempts = observed.lock().expect("observed lock").clone();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].method(), "GET");
    assert_eq!(attempts[0].attempt(), 0);
    assert!(attempts[0].is_retrying());
    assert_eq!(attempts[0].outcome(), HttpRequestAttemptOutcome::Retry);
    assert_eq!(
        attempts[0].status_class(),
        HttpRequestStatusClass::Status5xx
    );
    assert_eq!(attempts[1].method(), "GET");
    assert_eq!(attempts[1].attempt(), 1);
    assert!(!attempts[1].is_retrying());
    assert_eq!(attempts[1].outcome(), HttpRequestAttemptOutcome::Success);
    assert_eq!(
        attempts[1].status_class(),
        HttpRequestStatusClass::Status2xx
    );
}

#[tokio::test]
async fn given_client_with_observer_when_transport_fails_without_retry_then_error_outcome_is_recorded()
 {
    let observed = Arc::new(Mutex::new(Vec::<HttpRequestAttempt>::new()));
    let observed_clone = Arc::clone(&observed);
    let transport = StubTransport::new(vec![Err(HttpRequestError::Transport {
        kind: HttpRequestErrorKind::Connect,
    })]);

    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 0,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .with_observer(move |attempt: HttpRequestAttempt| {
            observed_clone.lock().expect("observed lock").push(attempt);
        })
        .build()
        .expect("build client");

    let error = client
        .request(Method::POST, "https://example.test/resource")
        .send()
        .await
        .err()
        .expect("transport error expected");

    assert_eq!(error.kind(), HttpRequestErrorKind::Connect);
    let attempts = observed.lock().expect("observed lock").clone();
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].method(), "POST");
    assert!(!attempts[0].is_retrying());
    assert_eq!(attempts[0].outcome(), HttpRequestAttemptOutcome::Error);
    assert_eq!(attempts[0].status_class(), HttpRequestStatusClass::Error);
    assert_eq!(attempts[0].status(), None);
}
