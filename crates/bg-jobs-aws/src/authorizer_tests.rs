use std::sync::{Arc, Mutex};

use aws_credentials::AwsStaticCredentials;
use bg_jobs::{AttemptId, ExecutionId};
use bg_jobs_http::{
    ApprovedEndpoint, HttpAttempt, HttpExecutor, HttpJob, HttpJobError, HttpPolicy, HttpPolicyId,
    HttpRequest, HttpRequestInput, PolicyBoundTransport,
};
use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use http_request::{HttpResponse, Transport, TransportFuture, Url};

use crate::{CredentialSource, SigV4Authorizer, SigV4AuthorizerError};

fn authorizer() -> SigV4Authorizer {
    SigV4Authorizer::try_new(
        "eu-west-1",
        "execute-api",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIAEXAMPLE".to_owned(),
            secret_access_key: "secret-value-must-not-escape".to_owned(),
            session_token: Some("session-value-must-not-escape".to_owned()),
        }),
    )
    .expect("authorizer")
}

#[derive(Debug)]
struct RecordingTransport {
    request: Arc<Mutex<Option<http_request::reqwest::Request>>>,
}

impl RecordingTransport {
    fn new() -> (Self, Arc<Mutex<Option<http_request::reqwest::Request>>>) {
        let request = Arc::new(Mutex::new(None));
        (
            Self {
                request: Arc::clone(&request),
            },
            request,
        )
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: http_request::reqwest::Request) -> TransportFuture {
        *self.request.lock().expect("request lock") = Some(request);
        Box::pin(async {
            Ok(HttpResponse::from_mock(
                StatusCode::OK,
                HeaderMap::new(),
                Vec::new(),
                Url::parse("https://api.example.com/jobs").expect("response URL"),
            ))
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

#[tokio::test]
async fn given_approved_https_request_when_authorized_then_sigv4_headers_are_added() {
    let policy_id = HttpPolicyId::try_new("sigv4-signing").expect("policy ID");
    let policy = HttpPolicy::builder(policy_id.clone())
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .authorizer(authorizer())
        .try_build()
        .expect("policy");
    let (transport, request_log) = RecordingTransport::new();
    let executor = HttpExecutor::builder()
        .policy(policy)
        .with_transport(transport)
        .try_build()
        .expect("executor");
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs?scope=one").expect("URL"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"payload"),
    })
    .expect("request");
    executor
        .execute(
            &HttpJob::new(policy_id, request),
            HttpAttempt::new(ExecutionId::from([1; 16]), AttemptId::from([2; 16]), None),
        )
        .await
        .expect("signed request");
    let request = request_log
        .lock()
        .expect("request lock")
        .take()
        .expect("transport request");
    let signed = request.headers();
    assert!(signed.contains_key(http::header::AUTHORIZATION));
    assert!(signed.contains_key("x-amz-date"));
    assert!(signed.contains_key("x-amz-content-sha256"));
    let rendered = format!("{signed:?} {:?}", authorizer());
    assert!(!rendered.contains("secret-value-must-not-escape"));
    assert!(!rendered.contains("session-value-must-not-escape"));
}

#[tokio::test]
async fn given_insecure_request_when_constructed_then_it_is_rejected_without_signing() {
    let error = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("http://api.example.com/jobs").expect("URL"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"payload"),
    })
    .expect_err("insecure URL");
    assert_eq!(error, HttpJobError::InsecureEndpoint);
}

#[tokio::test]
async fn given_invalid_header_when_executor_authorizes_then_signing_failure_is_closed() {
    let policy_id = HttpPolicyId::try_new("sigv4-invalid-header").expect("policy ID");
    let policy = HttpPolicy::builder(policy_id.clone())
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .authorizer(authorizer())
        .try_build()
        .expect("policy");
    let executor = HttpExecutor::try_new([policy]).expect("executor");
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("x-invalid"),
        http::HeaderValue::from_bytes(&[0xff]).expect("invalid bytes are allowed in test input"),
    );
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").expect("URL"),
        headers,
        body: Bytes::from_static(b"payload"),
    })
    .expect("request");
    let error = executor
        .execute(
            &HttpJob::new(policy_id, request),
            HttpAttempt::new(ExecutionId::from([3; 16]), AttemptId::from([4; 16]), None),
        )
        .await
        .expect_err("signing failure");
    assert_eq!(
        error,
        HttpJobError::Authorization(bg_jobs_http::AuthorizationErrorKind::SigningFailed)
    );
}

#[tokio::test]
async fn given_unapproved_endpoint_when_executor_uses_sigv4_then_it_is_rejected_before_signing() {
    let policy_id = HttpPolicyId::try_new("sigv4-approved").expect("policy ID");
    let policy = HttpPolicy::builder(policy_id.clone())
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .authorizer(authorizer())
        .try_build()
        .expect("policy");
    let executor = HttpExecutor::try_new([policy]).expect("executor");
    let request = HttpRequest::try_new(HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://evil.example.net/jobs").expect("URL"),
        headers: HeaderMap::new(),
        body: Bytes::from_static(b"payload"),
    })
    .expect("request");
    let error = executor
        .execute(
            &HttpJob::new(policy_id, request),
            HttpAttempt::new(ExecutionId::from([1; 16]), AttemptId::from([2; 16]), None),
        )
        .await
        .expect_err("unapproved endpoint");
    assert_eq!(error, bg_jobs_http::HttpJobError::EndpointNotApproved);
}

#[test]
fn given_invalid_sigv4_configuration_when_built_then_no_signer_is_created() {
    assert_eq!(
        SigV4Authorizer::try_new(
            "",
            "execute-api",
            CredentialSource::Static(AwsStaticCredentials {
                access_key_id: "key".to_owned(),
                secret_access_key: "secret".to_owned(),
                session_token: None,
            }),
        )
        .expect_err("empty region"),
        SigV4AuthorizerError::InvalidConfiguration
    );
    assert_eq!(
        SigV4Authorizer::try_new("eu-west-1", "execute-api\n", CredentialSource::DefaultChain,)
            .expect_err("control character"),
        SigV4AuthorizerError::InvalidConfiguration
    );
}
