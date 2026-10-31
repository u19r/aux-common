use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bg_jobs::{AttemptId, ExecutionId};
use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use http_request::{HttpRequestError, HttpResponse, Transport, TransportFuture, Url};

use crate::{
    ApprovedEndpoint, AuthorizationFuture, AuthorizationRequest, HttpAttempt, HttpExecutor,
    HttpJob, HttpJobError, HttpPolicy, HttpPolicyId, HttpRequest, HttpRequestInput,
    MAX_HTTP_HEADER_BYTES, MAX_HTTP_HEADER_COUNT, NoopAuthorizer, PolicyBoundTransport,
    RequestAuthorizer,
};

struct CountingAuthorizer {
    calls: Arc<AtomicUsize>,
}

impl RequestAuthorizer for CountingAuthorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let headers = request.into_headers();
        Box::pin(async move { Ok(headers) })
    }
}

struct YieldingAuthorizer;

impl RequestAuthorizer for YieldingAuthorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            Ok(request.into_headers())
        })
    }
}

struct DuplicateHeaderAuthorizer {
    name: &'static str,
}

impl RequestAuthorizer for DuplicateHeaderAuthorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        let mut headers = request.into_headers();
        headers.append(
            HeaderName::from_static(self.name),
            HeaderValue::from_static("first"),
        );
        headers.append(
            HeaderName::from_static(self.name),
            HeaderValue::from_static("second"),
        );
        Box::pin(async move { Ok(headers) })
    }
}

struct AddingHeadersAuthorizer {
    extras: HeaderMap,
}

impl RequestAuthorizer for AddingHeadersAuthorizer {
    fn authorize<'a>(&'a self, request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        let mut headers = request.into_headers();
        for (name, value) in &self.extras {
            headers.append(name.clone(), value.clone());
        }
        Box::pin(async move { Ok(headers) })
    }
}

struct RecordingTransport {
    requests: Arc<Mutex<Vec<http_request::reqwest::Request>>>,
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
    redirects_disabled: bool,
}

impl std::fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordingTransport([REDACTED])")
    }
}

impl RecordingTransport {
    fn new(
        responses: Vec<Result<HttpResponse, HttpRequestError>>,
        redirects_disabled: bool,
    ) -> (Self, Arc<Mutex<Vec<http_request::reqwest::Request>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                requests: Arc::clone(&requests),
                responses: Mutex::new(VecDeque::from(responses)),
                redirects_disabled,
            },
            requests,
        )
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: http_request::reqwest::Request) -> TransportFuture {
        self.requests.lock().expect("request lock").push(request);
        let response = self.responses.lock().expect("response lock").pop_front();
        Box::pin(async move {
            response.unwrap_or_else(|| {
                Err(HttpRequestError::Transport {
                    kind: http_request::HttpRequestErrorKind::Unknown,
                })
            })
        })
    }

    fn redirects_disabled(&self) -> bool {
        self.redirects_disabled
    }

    fn destination_policy_enforced(&self) -> bool {
        true
    }

    fn deadline_enforced(&self) -> bool {
        true
    }
}

impl PolicyBoundTransport for RecordingTransport {}

#[derive(Debug)]
struct CapabilityTransport {
    redirects_disabled: bool,
    destination_policy_enforced: bool,
    deadline_enforced: bool,
}

impl Transport for CapabilityTransport {
    fn send(&self, _request: http_request::reqwest::Request) -> TransportFuture {
        Box::pin(std::future::pending())
    }

    fn redirects_disabled(&self) -> bool {
        self.redirects_disabled
    }

    fn destination_policy_enforced(&self) -> bool {
        self.destination_policy_enforced
    }

    fn deadline_enforced(&self) -> bool {
        self.deadline_enforced
    }
}

impl PolicyBoundTransport for CapabilityTransport {}

fn response(status: StatusCode, body: &[u8]) -> Result<HttpResponse, HttpRequestError> {
    Ok(HttpResponse::from_mock(
        status,
        HeaderMap::new(),
        body.to_vec(),
        Url::parse("https://api.example.com/response").expect("response URL"),
    ))
}

fn policy() -> HttpPolicy {
    HttpPolicy::builder(HttpPolicyId::try_new("identity").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .try_build()
        .expect("policy")
}

fn job(body: &[u8]) -> HttpJob {
    job_with_headers(HeaderMap::new(), body)
}

fn job_with_headers(headers: HeaderMap, body: &[u8]) -> HttpJob {
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").expect("request URL"),
        headers,
        body: Bytes::copy_from_slice(body),
    })
    .expect("request");
    HttpJob::new(policy().id().clone(), request)
}

fn policy_with_authorizer(id: &str, authorizer: impl RequestAuthorizer) -> HttpPolicy {
    HttpPolicy::builder(HttpPolicyId::try_new(id).expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .authorizer(authorizer)
        .try_build()
        .expect("policy")
}

#[test]
fn given_noop_authorizer_when_its_future_is_created_then_work_waits_for_poll() {
    let request = job(b"connector-secret").request.clone();
    let authorization_request = AuthorizationRequest::new(
        request.method(),
        request.url(),
        request.headers().clone(),
        request.body(),
    );
    let mut future = NoopAuthorizer.authorize(authorization_request);
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Ok(_))
    ));
}

fn numbered_headers(count: usize) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for index in 0..count {
        let name = HeaderName::from_bytes(format!("x-authorizer-{index}").as_bytes())
            .expect("header name");
        headers.insert(name, HeaderValue::from_static("v"));
    }
    headers
}

fn job_at(url: &str, body: &[u8], policy: &HttpPolicy) -> HttpJob {
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse(url).expect("request URL"),
        headers: HeaderMap::new(),
        body: Bytes::copy_from_slice(body),
    })
    .expect("request");
    HttpJob::new(policy.id().clone(), request)
}

fn attempt(execution: [u8; 16], attempt: [u8; 16], deadline: Option<Instant>) -> HttpAttempt {
    HttpAttempt::new(
        ExecutionId::from(execution),
        AttemptId::from(attempt),
        deadline,
    )
}

#[tokio::test]
async fn given_retries_when_executed_then_idempotency_is_stable_and_attempt_is_unique() {
    let (transport, requests) = RecordingTransport::new(
        vec![
            response(StatusCode::OK, b"one"),
            response(StatusCode::OK, b"two"),
        ],
        true,
    );
    let executor = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect("executor");
    let job = job(b"payload");
    executor
        .execute(&job, attempt([1; 16], [2; 16], None))
        .await
        .expect("first execution");
    executor
        .execute(&job, attempt([1; 16], [3; 16], None))
        .await
        .expect("second execution");

    let requests = requests.lock().expect("request lock");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].headers().get("idempotency-key"),
        requests[1].headers().get("idempotency-key")
    );
    assert_ne!(
        requests[0].headers().get("x-aux-attempt-id"),
        requests[1].headers().get("x-aux-attempt-id")
    );
}

#[tokio::test]
async fn given_multiple_policies_when_executed_then_each_bound_client_uses_its_policy() {
    let first_id = HttpPolicyId::try_new("primary-api").expect("policy ID");
    let first_timeout = Duration::from_millis(100);
    let first_policy = HttpPolicy::builder(first_id.clone())
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .request_timeout(first_timeout)
        .connect_timeout(Duration::from_secs(2))
        .try_build()
        .expect("first policy");
    let second_id = HttpPolicyId::try_new("secondary-api").expect("policy ID");
    let second_timeout = Duration::from_millis(400);
    let second_policy = HttpPolicy::builder(second_id.clone())
        .endpoint(ApprovedEndpoint::exact_on_port("api.example.com", 8443).expect("endpoint"))
        .request_timeout(second_timeout)
        .connect_timeout(Duration::from_secs(2))
        .try_build()
        .expect("second policy");
    let (transport, requests) = RecordingTransport::new(
        vec![
            response(StatusCode::OK, b"first"),
            response(StatusCode::OK, b"second"),
        ],
        true,
    );
    let executor = HttpExecutor::builder()
        .policy(first_policy)
        .policy(second_policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"first",
                executor.policy(&first_id).expect("first policy"),
            ),
            attempt([42; 16], [43; 16], None),
        )
        .await
        .expect("first request");
    executor
        .execute(
            &job_at(
                "https://api.example.com:8443/jobs",
                b"second",
                executor.policy(&second_id).expect("second policy"),
            ),
            attempt([44; 16], [45; 16], None),
        )
        .await
        .expect("second request");

    let requests = requests.lock().expect("request lock");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url().port_or_known_default(), Some(443));
    assert_eq!(requests[1].url().port_or_known_default(), Some(8443));
    assert!(*requests[0].timeout().expect("first timeout") <= first_timeout);
    assert!(*requests[1].timeout().expect("second timeout") <= second_timeout);
}

#[tokio::test]
async fn given_zero_nested_retry_policy_when_status_is_retryable_then_transport_runs_once() {
    let (transport, requests) = RecordingTransport::new(
        vec![response(StatusCode::SERVICE_UNAVAILABLE, b"retry")],
        true,
    );
    let executor = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect("executor");
    let result = executor
        .execute(&job(b"payload"), attempt([4; 16], [5; 16], None))
        .await
        .expect("classification");
    assert_eq!(result.class(), crate::HttpResultClass::Retry);
    assert_eq!(requests.lock().expect("request lock").len(), 1);
}

#[tokio::test]
async fn given_unapproved_endpoint_when_executed_then_no_transport_or_authorization_occurs() {
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect("executor");
    let error = executor
        .execute(
            &job_at(
                "https://evil.example.net/jobs",
                b"payload",
                executor
                    .policy(&HttpPolicyId::try_new("identity").expect("ID"))
                    .expect("policy"),
            ),
            attempt([12; 16], [13; 16], None),
        )
        .await
        .expect_err("unapproved endpoint");
    assert_eq!(error, HttpJobError::EndpointNotApproved);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_policy_request_and_response_bounds_when_exceeded_then_no_body_is_sent_or_retained() {
    let request_policy = HttpPolicy::builder(HttpPolicyId::try_new("request-bound").expect("ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .max_request_bytes(4)
        .try_build()
        .expect("policy");
    let request_policy_id = request_policy.id().clone();
    let (request_transport, request_log) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let request_executor = HttpExecutor::builder()
        .policy(request_policy)
        .with_transport(request_transport)
        .try_build()
        .expect("executor");
    let error = request_executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"12345",
                request_executor.policy(&request_policy_id).expect("policy"),
            ),
            attempt([14; 16], [15; 16], None),
        )
        .await
        .expect_err("request bound");
    assert_eq!(error, HttpJobError::RequestBodyTooLarge);
    assert!(request_log.lock().expect("request log").is_empty());

    let response_policy = HttpPolicy::builder(HttpPolicyId::try_new("response-bound").expect("ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .max_response_bytes(4)
        .try_build()
        .expect("policy");
    let response_policy_id = response_policy.id().clone();
    let (response_transport, response_log) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"12345")], true);
    let response_executor = HttpExecutor::builder()
        .policy(response_policy)
        .with_transport(response_transport)
        .try_build()
        .expect("executor");
    let result = response_executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"ok",
                response_executor
                    .policy(&response_policy_id)
                    .expect("policy"),
            ),
            attempt([16; 16], [17; 16], None),
        )
        .await
        .expect("response classification");
    assert_eq!(result.class(), crate::HttpResultClass::DeadLetter);
    assert_eq!(result.code(), "http_response_too_large");
    assert_eq!(response_log.lock().expect("response log").len(), 1);
}

#[tokio::test]
async fn given_expired_deadline_when_executed_then_no_request_is_sent() {
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect("executor");
    let error = executor
        .execute(
            &job(b"payload"),
            attempt(
                [6; 16],
                [7; 16],
                Some(Instant::now() - Duration::from_millis(1)),
            ),
        )
        .await
        .expect_err("expired deadline");
    assert_eq!(error, HttpJobError::InvalidDeadline);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_expired_deadline_when_authorization_is_execution_time_then_it_is_not_invoked() {
    let calls = Arc::new(AtomicUsize::new(0));
    let policy = HttpPolicy::builder(HttpPolicyId::try_new("deadline-auth").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .authorizer(CountingAuthorizer {
            calls: Arc::clone(&calls),
        })
        .try_build()
        .expect("policy");
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").expect("request URL"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"payload"),
    })
    .expect("request");
    let error = executor
        .execute(
            &HttpJob::new(policy_id, request),
            attempt(
                [10; 16],
                [11; 16],
                Some(Instant::now() - Duration::from_millis(1)),
            ),
        )
        .await
        .expect_err("expired deadline");
    assert_eq!(error, HttpJobError::InvalidDeadline);
    assert_eq!(calls.load(Ordering::Relaxed), 0);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_authorization_consuming_deadline_does_not_start_transport() {
    let origin = Instant::now();
    let clock_values = Arc::new(Mutex::new(VecDeque::from([
        origin,
        origin,
        origin + Duration::from_secs(1),
    ])));
    let policy =
        HttpPolicy::builder(HttpPolicyId::try_new("deadline-consumed").expect("policy ID"))
            .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
            .authorizer(YieldingAuthorizer)
            .try_build()
            .expect("policy");
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .test_clock({
            let clock_values = Arc::clone(&clock_values);
            move || {
                let mut values = clock_values.lock().expect("clock values");
                values
                    .pop_front()
                    .unwrap_or(origin + Duration::from_secs(1))
            }
        })
        .try_build()
        .expect("executor");
    let error = executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt(
                [18; 16],
                [19; 16],
                Some(origin + Duration::from_millis(100)),
            ),
        )
        .await
        .expect_err("authorization consumed deadline");
    assert_eq!(error, HttpJobError::InvalidDeadline);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_authorization_that_yields_before_the_deadline_when_executed_then_transport_runs() {
    let policy = policy_with_authorizer("yielding-auth", YieldingAuthorizer);
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    let result = executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt([30; 16], [31; 16], None),
        )
        .await
        .expect("yielding authorization should complete");

    assert_eq!(result.class(), crate::HttpResultClass::Complete);
    assert_eq!(requests.lock().expect("request lock").len(), 1);
}

#[tokio::test]
async fn given_custom_transport_when_executed_then_remaining_total_deadline_is_on_request() {
    let policy = HttpPolicy::builder(HttpPolicyId::try_new("request-deadline").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .request_timeout(Duration::from_millis(200))
        .connect_timeout(Duration::from_secs(2))
        .try_build()
        .expect("policy");
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt([40; 16], [41; 16], None),
        )
        .await
        .expect("request");

    let requests = requests.lock().expect("request lock");
    let timeout = requests[0].timeout().expect("request deadline");
    assert!(*timeout <= Duration::from_millis(200));
    assert!(!timeout.is_zero());
}

#[tokio::test]
async fn given_finite_authorization_before_deadline_when_executed_then_transport_runs() {
    let policy = policy_with_authorizer("finite-auth", YieldingAuthorizer);
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    let result = executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt([22; 16], [23; 16], None),
        )
        .await
        .expect("finite authorization should complete");

    assert_eq!(result.class(), crate::HttpResultClass::Complete);
    assert_eq!(requests.lock().expect("request lock").len(), 1);
}

#[tokio::test]
async fn given_authorizer_header_count_above_bound_when_executed_then_transport_is_not_started() {
    let policy = policy_with_authorizer(
        "authorizer-header-count",
        AddingHeadersAuthorizer {
            extras: numbered_headers(MAX_HTTP_HEADER_COUNT),
        },
    );
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    let error = executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt([24; 16], [25; 16], None),
        )
        .await
        .expect_err("authorizer header count must be bounded");

    assert_eq!(error, HttpJobError::HeaderCountTooLarge);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_authorizer_header_bytes_above_bound_when_executed_then_transport_is_not_started() {
    let mut extras = HeaderMap::new();
    extras.insert(
        HeaderName::from_static("x-authorizer-large"),
        HeaderValue::from_bytes(&vec![b'a'; MAX_HTTP_HEADER_BYTES]).expect("large header value"),
    );
    let policy = policy_with_authorizer(
        "authorizer-header-bytes",
        AddingHeadersAuthorizer { extras },
    );
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    let error = executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt([26; 16], [27; 16], None),
        )
        .await
        .expect_err("authorizer header bytes must be bounded");

    assert_eq!(error, HttpJobError::HeaderBytesTooLarge);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_duplicate_identity_header_when_executed_then_it_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static("idempotency-key"),
        HeaderValue::from_static("caller-one"),
    );
    headers.append(
        HeaderName::from_static("idempotency-key"),
        HeaderValue::from_static("caller-two"),
    );
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect("executor");

    let error = executor
        .execute(
            &job_with_headers(headers, b"payload"),
            attempt([32; 16], [33; 16], None),
        )
        .await
        .expect_err("duplicate identity header");

    assert_eq!(error, HttpJobError::SensitiveHeader);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_repeated_non_security_header_when_executed_then_it_is_preserved() {
    let mut headers = HeaderMap::new();
    headers.append(
        HeaderName::from_static("accept"),
        HeaderValue::from_static("application/json"),
    );
    headers.append(
        HeaderName::from_static("accept"),
        HeaderValue::from_static("text/plain"),
    );
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect("executor");

    executor
        .execute(
            &job_with_headers(headers, b"payload"),
            attempt([36; 16], [37; 16], None),
        )
        .await
        .expect("repeated ordinary header");

    let requests = requests.lock().expect("request lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].headers().get_all("accept").iter().count(), 2);
}

#[tokio::test]
async fn given_duplicate_authorizer_header_when_executed_then_it_is_rejected() {
    let policy = policy_with_authorizer(
        "duplicate-authorizer",
        DuplicateHeaderAuthorizer {
            name: "authorization",
        },
    );
    let policy_id = policy.id().clone();
    let (transport, requests) =
        RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");

    let error = executor
        .execute(
            &job_at(
                "https://api.example.com/jobs",
                b"payload",
                executor.policy(&policy_id).expect("policy"),
            ),
            attempt([34; 16], [35; 16], None),
        )
        .await
        .expect_err("duplicate authorizer header");

    assert_eq!(error, HttpJobError::SensitiveHeader);
    assert!(requests.lock().expect("request lock").is_empty());
}

#[tokio::test]
async fn given_duplicate_identity_or_aws_authorizer_header_when_executed_then_it_is_rejected() {
    for (id, name) in [
        ("duplicate-idempotency", "idempotency-key"),
        ("duplicate-attempt", "x-aux-attempt-id"),
        ("duplicate-amz-date", "x-amz-date"),
        ("duplicate-amz-content", "x-amz-content-sha256"),
        ("duplicate-amz-token", "x-amz-security-token"),
    ] {
        let policy = policy_with_authorizer(id, DuplicateHeaderAuthorizer { name });
        let policy_id = policy.id().clone();
        let (transport, requests) =
            RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
        let executor = HttpExecutor::builder()
            .policy(policy)
            .with_transport(transport)
            .try_build()
            .expect("executor");

        let error = executor
            .execute(
                &job_at(
                    "https://api.example.com/jobs",
                    b"payload",
                    executor.policy(&policy_id).expect("policy"),
                ),
                attempt([38; 16], [39; 16], None),
            )
            .await
            .expect_err("duplicate managed header");

        assert_eq!(error, HttpJobError::SensitiveHeader, "header {name}");
        assert!(requests.lock().expect("request lock").is_empty());
    }
}

#[tokio::test]
async fn given_sensitive_or_mismatched_host_authorizer_header_when_executed_then_it_is_rejected() {
    for (id, name, value) in [
        ("authorizer-cookie", "cookie", "blocked"),
        ("authorizer-host", "host", "evil.example.com"),
        ("authorizer-connection", "connection", "keep-alive"),
        ("authorizer-content-length", "content-length", "3"),
    ] {
        let mut extras = HeaderMap::new();
        extras.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("header name"),
            HeaderValue::from_static(value),
        );
        let policy = policy_with_authorizer(id, AddingHeadersAuthorizer { extras });
        let policy_id = policy.id().clone();
        let (transport, requests) =
            RecordingTransport::new(vec![response(StatusCode::OK, b"ok")], true);
        let executor = HttpExecutor::builder()
            .policy(policy)
            .with_transport(transport)
            .try_build()
            .expect("executor");

        let error = executor
            .execute(
                &job_at(
                    "https://api.example.com/jobs",
                    b"payload",
                    executor.policy(&policy_id).expect("policy"),
                ),
                attempt([28; 16], [29; 16], None),
            )
            .await
            .expect_err("authorizer header must be rejected");

        assert_eq!(error, HttpJobError::SensitiveHeader, "header {name}");
        assert!(requests.lock().expect("request lock").is_empty());
    }
}

#[test]
fn given_redirect_following_transport_when_executor_built_then_it_is_rejected() {
    let (transport, _) = RecordingTransport::new(Vec::new(), false);
    let error = HttpExecutor::builder()
        .policy(policy())
        .with_transport(transport)
        .try_build()
        .expect_err("redirecting transport");
    assert_eq!(error, HttpJobError::RequestBuild);
}

#[test]
fn given_custom_transport_missing_any_policy_capability_when_executor_built_then_it_is_rejected() {
    for (name, transport) in [
        (
            "redirect-only",
            CapabilityTransport {
                redirects_disabled: true,
                destination_policy_enforced: false,
                deadline_enforced: false,
            },
        ),
        (
            "redirects",
            CapabilityTransport {
                redirects_disabled: false,
                destination_policy_enforced: true,
                deadline_enforced: true,
            },
        ),
        (
            "destination",
            CapabilityTransport {
                redirects_disabled: true,
                destination_policy_enforced: false,
                deadline_enforced: true,
            },
        ),
        (
            "deadline",
            CapabilityTransport {
                redirects_disabled: true,
                destination_policy_enforced: true,
                deadline_enforced: false,
            },
        ),
    ] {
        let error = HttpExecutor::builder()
            .policy(policy())
            .with_transport(transport)
            .try_build()
            .expect_err("transport missing {name} capability");
        assert_eq!(error, HttpJobError::RequestBuild, "missing {name}");
    }
}

/// A transport whose `send` future never resolves and which lies about
/// enforcing the executor's deadline — the worst-case wedging adversary the
/// executor must survive (Slowloris-class).
#[derive(Debug)]
struct WedgedTransport;

impl Transport for WedgedTransport {
    fn send(&self, _request: http_request::reqwest::Request) -> TransportFuture {
        Box::pin(std::future::pending())
    }

    fn redirects_disabled(&self) -> bool {
        true
    }

    fn destination_policy_enforced(&self) -> bool {
        true
    }

    // The deliberate lie: the hanging send future proves the executor does
    // not trust this flag for its own wall-clock bound.
    fn deadline_enforced(&self) -> bool {
        true
    }
}

impl PolicyBoundTransport for WedgedTransport {}

/// An authorizer future that never resolves (hung upstream token call).
#[derive(Debug)]
struct WedgedAuthorizer;

impl RequestAuthorizer for WedgedAuthorizer {
    fn authorize<'a>(&'a self, _request: AuthorizationRequest<'a>) -> AuthorizationFuture<'a> {
        Box::pin(std::future::pending())
    }
}

fn wedged_policy() -> HttpPolicy {
    HttpPolicy::builder(HttpPolicyId::try_new("wedged").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .request_timeout(Duration::from_millis(150))
        .connect_timeout(Duration::from_millis(50))
        .try_build()
        .expect("policy")
}

fn wedged_job() -> HttpJob {
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").expect("request URL"),
        headers: HeaderMap::new(),
        body: Bytes::copy_from_slice(b"payload"),
    })
    .expect("request");
    HttpJob::new(wedged_policy().id().clone(), request)
}

fn unbounded_attempt() -> HttpAttempt {
    HttpAttempt::new(ExecutionId::from([1; 16]), AttemptId::from([2; 16]), None)
}

/// A transport that both hangs and lies about enforcing the attempt deadline
/// must still produce a classification inside the policy's `request_timeout`,
/// never a hang.
#[tokio::test]
async fn given_wedged_transport_when_execute_runs_then_attempt_is_deadline_bounded() {
    let executor = HttpExecutor::builder()
        .policy(wedged_policy())
        .with_transport(WedgedTransport)
        .try_build()
        .expect("executor");

    let started = std::time::Instant::now();
    let outcome = executor
        .execute(&wedged_job(), unbounded_attempt())
        .await
        .expect("classification");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_millis(600),
        "wedged transport held the attempt past the request deadline: {elapsed:?}"
    );
    assert_eq!(
        outcome.code(),
        "http_transport_retry",
        "a wedged transport must classify as a transport retry"
    );
}

/// An authorizer future that hangs is bounded by the execution deadline; the
/// transport is never invoked and the attempt fails closed.
#[tokio::test]
async fn given_wedged_authorizer_when_execute_runs_then_attempt_is_deadline_bounded() {
    let policy = HttpPolicy::builder(HttpPolicyId::try_new("wedged").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .request_timeout(Duration::from_millis(150))
        .authorizer(WedgedAuthorizer)
        .try_build()
        .expect("policy");
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(WedgedTransport)
        .try_build()
        .expect("executor");

    let started = std::time::Instant::now();
    let result = executor.execute(&wedged_job(), unbounded_attempt()).await;
    {
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(600),
            "wedged authorizer held the attempt past the request deadline: {elapsed:?}"
        );
    }
    match result {
        Ok(outcome) => assert_eq!(outcome.code(), "http_transport_retry"),
        Err(error) => {
            let rendered = format!("{error:?}").to_uppercase();
            assert!(
                rendered.contains("DEADLINE") || rendered.contains("EXCEEDED"),
                "a wedged authorizer must fail on the deadline, not wedging: {error:?}"
            );
        }
    }
}

#[test]
fn given_secret_payload_when_debug_is_rendered_then_no_secret_or_identifier_is_exposed() {
    let secret = "super-secret-body-material";
    let job = job(secret.as_bytes());
    let attempt = attempt([8; 16], [9; 16], None);
    let rendered = format!("{job:?} {attempt:?}");
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("080808"));
    assert!(!rendered.contains("090909"));
}
