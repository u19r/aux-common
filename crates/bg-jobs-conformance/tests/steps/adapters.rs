use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bg_jobs::{AttemptId, ExecutionId};
use bg_jobs_aws::{CredentialSource, SigV4Authorizer};
use bg_jobs_http::{
    ApprovedEndpoint, HttpAttempt, HttpExecutor, HttpJob, HttpPolicy, HttpPolicyId, HttpRequest,
    HttpRequestInput, HttpResultClass, PolicyBoundTransport,
};
use bytes::Bytes;
use cucumber::{given, then, when};
use http::{HeaderMap, Method, StatusCode};
use http_request::{HttpRequestError, HttpResponse, Transport, TransportFuture, Url};

use crate::BddWorld;

#[derive(Default)]
pub(crate) struct HttpEvidence {
    pub(crate) classes: Vec<HttpResultClass>,
    pub(crate) requests: Option<Arc<Mutex<Vec<http_request::reqwest::Request>>>>,
    pub(crate) telemetry: String,
    pub(crate) signed: bool,
    pub(crate) secret: String,
    pub(crate) transport_count: usize,
}

impl fmt::Debug for HttpEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpEvidence")
            .field("classes", &self.classes)
            .field("transport_count", &self.transport_count)
            .field("signed", &self.signed)
            .finish()
    }
}

struct RecordingTransport {
    requests: Arc<Mutex<Vec<http_request::reqwest::Request>>>,
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordingTransport([REDACTED])")
    }
}

impl RecordingTransport {
    fn new(
        responses: Vec<Result<HttpResponse, HttpRequestError>>,
    ) -> (Self, Arc<Mutex<Vec<http_request::reqwest::Request>>>) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                requests: Arc::clone(&requests),
                responses: Mutex::new(responses.into()),
            },
            requests,
        )
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: http_request::reqwest::Request) -> TransportFuture {
        if let Ok(mut requests) = self.requests.lock() {
            requests.push(request);
        }
        let response = self
            .responses
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front());
        Box::pin(async move {
            response.unwrap_or_else(|| {
                Err(HttpRequestError::Transport {
                    kind: http_request::HttpRequestErrorKind::Unknown,
                })
            })
        })
    }

    fn redirects_disabled(&self) -> bool {
        true
    }

    fn destination_policy_enforced(&self) -> bool {
        true
    }

    fn deadline_enforced(&self) -> bool {
        true
    }
}

impl PolicyBoundTransport for RecordingTransport {}

fn response(status: StatusCode, body: &[u8]) -> Result<HttpResponse, HttpRequestError> {
    Ok(HttpResponse::from_mock(
        status,
        HeaderMap::new(),
        body.to_vec(),
        Url::parse("https://api.example.com/response").map_err(|_| HttpRequestError::Build)?,
    ))
}

fn policy(id: &str) -> Result<HttpPolicy, String> {
    HttpPolicy::builder(HttpPolicyId::try_new(id).map_err(|error| error.to_string())?)
        .endpoint(ApprovedEndpoint::exact("api.example.com").map_err(|error| error.to_string())?)
        .try_build()
        .map_err(|error| error.to_string())
}

fn request(policy_id: &HttpPolicyId, body: &[u8]) -> Result<HttpJob, String> {
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").map_err(|error| error.to_string())?,
        headers: HeaderMap::new(),
        body: Bytes::copy_from_slice(body),
    })
    .map_err(|error| error.to_string())?;
    Ok(HttpJob::new(policy_id.clone(), request))
}

fn attempt(execution: u8, attempt: u8) -> HttpAttempt {
    HttpAttempt::new(
        ExecutionId::from([execution; 16]),
        AttemptId::from([attempt; 16]),
        Some(Instant::now() + Duration::from_secs(5)),
    )
}

fn evidence(world: &mut BddWorld) -> &mut HttpEvidence {
    world.http.get_or_insert_with(HttpEvidence::default)
}

#[given("a registered HTTPS job uses the shared executor with transport retries disabled")]
async fn given_registered_https_job(world: &mut BddWorld) -> Result<(), String> {
    evidence(world).secret = "status-matrix-secret".to_owned();
    Ok(())
}

#[when("it receives success throttling permanent rejection or transport failure")]
async fn when_http_status_matrix(world: &mut BddWorld) -> Result<(), String> {
    let responses = vec![
        response(StatusCode::OK, b"ok"),
        response(StatusCode::TOO_MANY_REQUESTS, b"throttled"),
        response(StatusCode::BAD_REQUEST, b"rejected"),
        response(StatusCode::SERVICE_UNAVAILABLE, b"retry"),
        Err(HttpRequestError::Transport {
            kind: http_request::HttpRequestErrorKind::Timeout,
        }),
    ];
    let (transport, requests) = RecordingTransport::new(responses);
    let policy = policy("bdd-status")?;
    let policy_id = policy.id().clone();
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .map_err(|error| error.to_string())?;
    let job = request(&policy_id, b"status-matrix")?;
    let mut classes = Vec::new();
    for attempt_number in 1..=5 {
        let result = executor
            .execute(&job, attempt(1, attempt_number))
            .await
            .map_err(|error| error.to_string())?;
        classes.push(result.class());
    }
    let transport_count = requests.lock().map_err(|_| "request lock poisoned")?.len();
    let state = evidence(world);
    state.classes = classes;
    state.requests = Some(requests);
    state.transport_count = transport_count;
    Ok(())
}

#[then("each response maps to the documented per-job terminal or retry outcome")]
async fn then_http_status_matrix(world: &mut BddWorld) -> Result<(), String> {
    let state = world.http.as_ref().ok_or("HTTP evidence was missing")?;
    let expected = vec![
        HttpResultClass::Complete,
        HttpResultClass::Retry,
        HttpResultClass::DeadLetter,
        HttpResultClass::Retry,
        HttpResultClass::Retry,
    ];
    if state.classes != expected || state.transport_count != 5 {
        return Err(format!("HTTP matrix was not durable: {state:?}"));
    }
    Ok(())
}

#[given("an HTTP job is automatically retried")]
async fn given_retried_http_job(world: &mut BddWorld) -> Result<(), String> {
    evidence(world).secret = "payload-secret-for-telemetry".to_owned();
    Ok(())
}

#[when("each request is built")]
async fn when_http_requests_built(world: &mut BddWorld) -> Result<(), String> {
    let (transport, requests) = RecordingTransport::new(vec![
        response(StatusCode::SERVICE_UNAVAILABLE, b"retry-one"),
        response(StatusCode::OK, b"retry-two"),
    ]);
    let policy = policy("bdd-identity")?;
    let policy_id = policy.id().clone();
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .map_err(|error| error.to_string())?;
    let body = b"payload-secret-for-telemetry";
    let job = request(&policy_id, body)?;
    let first = executor
        .execute(&job, attempt(7, 8))
        .await
        .map_err(|error| error.to_string())?;
    let second = executor
        .execute(&job, attempt(7, 9))
        .await
        .map_err(|error| error.to_string())?;
    let telemetry = format!("{job:?} {first:?} {second:?}");
    let transport_count = requests.lock().map_err(|_| "request lock poisoned")?.len();
    let state = evidence(world);
    state.classes = vec![first.class(), second.class()];
    state.telemetry = telemetry;
    state.requests = Some(requests);
    state.transport_count = transport_count;
    Ok(())
}

#[then("the stable execution ID is sent in the registered idempotency header")]
async fn then_stable_idempotency(world: &mut BddWorld) -> Result<(), String> {
    let state = world.http.as_ref().ok_or("HTTP evidence was missing")?;
    let requests = state
        .requests
        .as_ref()
        .ok_or("HTTP requests were missing")?
        .lock()
        .map_err(|_| "request lock poisoned")?;
    if requests.len() != 2
        || requests[0].headers().get("idempotency-key")
            != requests[1].headers().get("idempotency-key")
        || requests[0].headers().get("x-aux-attempt-id")
            == requests[1].headers().get("x-aux-attempt-id")
    {
        return Err("execution identity was not stable per retry".to_owned());
    }
    Ok(())
}

#[then("URLs bodies headers and raw errors are absent from telemetry")]
async fn then_http_telemetry_is_bounded(world: &mut BddWorld) -> Result<(), String> {
    let state = world.http.as_ref().ok_or("HTTP evidence was missing")?;
    for forbidden in [
        "https://api.example.com/jobs",
        "api.example.com",
        "payload-secret-for-telemetry",
        "idempotency-key",
        "retry-one",
    ] {
        if state.telemetry.contains(forbidden) {
            return Err(format!("telemetry retained forbidden value {forbidden}"));
        }
    }
    Ok(())
}

#[given("a job selects a trusted AWS authorizer reference")]
async fn given_trusted_aws_authorizer(world: &mut BddWorld) -> Result<(), String> {
    evidence(world).secret = "aws-secret-key-value".to_owned();
    Ok(())
}

#[when("the approved HTTPS request executes")]
async fn when_sigv4_request_executes(world: &mut BddWorld) -> Result<(), String> {
    let (transport, requests) = RecordingTransport::new(vec![response(StatusCode::OK, b"signed")]);
    let authorizer = SigV4Authorizer::try_new(
        "eu-west-1",
        "execute-api",
        CredentialSource::Static(aws_credentials::AwsStaticCredentials {
            access_key_id: "BDDACCESS".to_owned(),
            secret_access_key: "aws-secret-key-value".to_owned(),
            session_token: Some("aws-session-token".to_owned()),
        }),
    )
    .map_err(|error| error.to_string())?;
    let policy =
        HttpPolicy::builder(HttpPolicyId::try_new("bdd-sigv4").map_err(|error| error.to_string())?)
            .endpoint(
                ApprovedEndpoint::exact("api.example.com").map_err(|error| error.to_string())?,
            )
            .authorizer(authorizer)
            .try_build()
            .map_err(|error| error.to_string())?;
    let policy_id = policy.id().clone();
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .map_err(|error| error.to_string())?;
    let job = request(&policy_id, b"payload-without-credentials")?;
    let result = executor
        .execute(&job, attempt(10, 11))
        .await
        .map_err(|error| error.to_string())?;
    let telemetry = format!("{job:?} {result:?}");
    let requests_count = requests.lock().map_err(|_| "request lock poisoned")?.len();
    let signed = requests
        .lock()
        .map_err(|_| "request lock poisoned")?
        .first()
        .and_then(|request| request.headers().get("authorization"))
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256"));
    let state = evidence(world);
    state.classes = vec![result.class()];
    state.telemetry = telemetry;
    state.requests = Some(requests);
    state.transport_count = requests_count;
    state.signed = signed;
    Ok(())
}

#[then("existing credential providers resolve and sign it at execution time")]
async fn then_sigv4_signed(world: &mut BddWorld) -> Result<(), String> {
    let state = world.http.as_ref().ok_or("HTTP evidence was missing")?;
    if !state.signed || state.classes != [HttpResultClass::Complete] || state.transport_count != 1 {
        return Err(format!("SigV4 execution did not sign once: {state:?}"));
    }
    let requests = state
        .requests
        .as_ref()
        .ok_or("signed request was missing")?
        .lock()
        .map_err(|_| "request lock poisoned")?;
    if requests[0].headers().get("x-amz-date").is_none() {
        return Err("SigV4 request lacked execution-time date".to_owned());
    }
    Ok(())
}

#[then("no credential is persisted in payload state or events")]
async fn then_sigv4_secret_absent(world: &mut BddWorld) -> Result<(), String> {
    let state = world.http.as_ref().ok_or("HTTP evidence was missing")?;
    for forbidden in ["aws-secret-key-value", "aws-session-token"] {
        if state.telemetry.contains(forbidden) {
            return Err(format!("credential appeared in telemetry: {forbidden}"));
        }
    }
    Ok(())
}
