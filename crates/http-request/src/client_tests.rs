use std::{
    collections::VecDeque,
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};

use http::{HeaderMap, HeaderValue};
use reqwest::{Method, Request, StatusCode, Url};
use serde_json::json;

use crate::{
    HttpClientBuilder, HttpRequestError, HttpResponse, RetryConfig, Transport, TransportFuture,
    client::retry_delay_for_response,
};

struct SequenceTransport {
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl std::fmt::Debug for SequenceTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SequenceTransport(..)")
    }
}

impl SequenceTransport {
    fn from_responses(responses: Vec<Result<HttpResponse, HttpRequestError>>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl Transport for SequenceTransport {
    fn send(&self, _request: Request) -> TransportFuture {
        let response = self
            .responses
            .lock()
            .expect("sequence transport lock")
            .pop_front()
            .expect("sequence transport response");
        Box::pin(async move { response })
    }
}

struct CountingTransport {
    attempts: Arc<Mutex<u32>>,
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl std::fmt::Debug for CountingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CountingTransport(..)")
    }
}

impl CountingTransport {
    fn from_responses(responses: Vec<Result<HttpResponse, HttpRequestError>>) -> Self {
        Self {
            attempts: Arc::new(Mutex::new(0)),
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl Transport for CountingTransport {
    fn send(&self, _request: Request) -> TransportFuture {
        *self
            .attempts
            .lock()
            .expect("counting transport attempts lock") += 1;
        let response = self
            .responses
            .lock()
            .expect("counting transport responses lock")
            .pop_front()
            .expect("counting transport response");
        Box::pin(async move { response })
    }
}

struct RecordingTransport {
    requests: Arc<Mutex<Vec<Request>>>,
    responses: Mutex<VecDeque<Result<HttpResponse, HttpRequestError>>>,
}

impl std::fmt::Debug for RecordingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecordingTransport(..)")
    }
}

impl RecordingTransport {
    fn from_responses(responses: Vec<Result<HttpResponse, HttpRequestError>>) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: Request) -> TransportFuture {
        self.requests
            .lock()
            .expect("recording transport requests lock")
            .push(request);
        let response = self
            .responses
            .lock()
            .expect("recording transport responses lock")
            .pop_front()
            .expect("recording transport response");
        Box::pin(async move { response })
    }
}

fn mock_json_response(headers: HeaderMap, body: &serde_json::Value) -> HttpResponse {
    HttpResponse::from_mock(
        StatusCode::OK,
        headers,
        serde_json::to_vec(&body).expect("encode mock json body"),
        Url::parse("https://example.test/resource").expect("mock response url"),
    )
}

fn transport_error_with_sensitive_url() -> HttpRequestError {
    let source = reqwest::Proxy::all("not a valid proxy url")
        .expect_err("invalid proxy should produce a reqwest error")
        .with_url(Url::parse("https://example.test/resource?access_token=sentinel").expect("url"));
    source.into()
}

#[test]
fn request_attempt_diagnostics_do_not_log_sensitive_path_or_query() {
    let url = Url::parse("https://example.test/private/secret-token?access_token=sentinel")
        .expect("request URL");
    let diagnostics = crate::client::request_attempt_diagnostics(&url);
    let output = format!("{diagnostics:?}");
    assert!(output.contains("host: \"example.test\""));
    assert!(output.contains("path_length: 21"));
    assert!(output.contains("query_present: true"));
    assert!(!output.contains("secret-token"));
    assert!(!output.contains("access_token=sentinel"));
}

#[tokio::test]
async fn get_json_with_cache_treats_cache_control_no_store_as_immediately_expired_even_with_max_age()
 {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=600"),
    );
    let client = HttpClientBuilder::new()
        .with_transport(SequenceTransport::from_responses(vec![Ok(
            mock_json_response(headers, &json!({ "issuer": "https://issuer.example.test" })),
        )]))
        .build()
        .expect("build http client");

    let response = client
        .get_json_with_cache::<serde_json::Value>(
            "https://example.test/resource",
            Duration::from_secs(300),
        )
        .await
        .expect("cached json response");

    assert!(
        response.expired(),
        "no-store responses must not stay cacheable, got future expiry for {:?}",
        response.value
    );
}

#[tokio::test]
async fn get_json_with_cache_treats_cache_control_no_cache_as_immediately_expired_even_with_max_age()
 {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=600, no-cache"),
    );
    let client = HttpClientBuilder::new()
        .with_transport(SequenceTransport::from_responses(vec![Ok(
            mock_json_response(headers, &json!({ "issuer": "https://issuer.example.test" })),
        )]))
        .build()
        .expect("build http client");

    let response = client
        .get_json_with_cache::<serde_json::Value>(
            "https://example.test/resource",
            Duration::from_secs(300),
        )
        .await
        .expect("cached json response");

    assert!(
        response.expired(),
        "no-cache responses must expire immediately so callers revalidate before reuse"
    );
}

#[tokio::test]
async fn execute_retries_idempotent_get_after_transient_server_error_until_the_request_succeeds() {
    let transport = CountingTransport::from_responses(vec![
        Ok(HttpResponse::from_mock(
            StatusCode::SERVICE_UNAVAILABLE,
            HeaderMap::new(),
            Vec::new(),
            Url::parse("https://example.test/resource").expect("503 response url"),
        )),
        Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            br#"{"ok":true}"#.to_vec(),
            Url::parse("https://example.test/resource").expect("200 response url"),
        )),
    ]);
    let attempts = transport.attempts.clone();
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 1,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .build()
        .expect("build http client");

    let response = client
        .request(Method::GET, "https://example.test/resource")
        .send()
        .await
        .expect("retried GET response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(*attempts.lock().expect("attempts lock"), 2);
}

#[tokio::test]
async fn execute_does_not_retry_post_after_server_error_when_non_idempotent_retries_are_disabled() {
    let transport = CountingTransport::from_responses(vec![Ok(HttpResponse::from_mock(
        StatusCode::SERVICE_UNAVAILABLE,
        HeaderMap::new(),
        Vec::new(),
        Url::parse("https://example.test/resource").expect("503 response url"),
    ))]);
    let attempts = transport.attempts.clone();
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .build()
        .expect("build http client");

    let response = client
        .request(Method::POST, "https://example.test/resource")
        .send()
        .await
        .expect("POST response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        *attempts.lock().expect("attempts lock"),
        1,
        "non-idempotent POST must not be retried by default"
    );
}

#[tokio::test]
async fn error_for_status_with_body_preserves_response_body_for_non_success_responses() {
    let result = HttpResponse::from_mock(
        StatusCode::BAD_REQUEST,
        HeaderMap::new(),
        br#"{"message":"bad request"}"#.to_vec(),
        Url::parse("https://example.test/resource").expect("400 response url"),
    )
    .error_for_status_with_body()
    .await;

    match result {
        Err(HttpRequestError::HttpStatus {
            status,
            body: Some(body),
        }) => {
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(body, "{\"message\":\"bad request\"}");
        }
        Err(other) => panic!("expected status error with body, got {other:?}"),
        Ok(_) => panic!("expected non-success response to fail"),
    }
}

#[tokio::test]
async fn error_for_status_with_body_applies_default_size_limit() {
    let body = vec![b'x'; crate::constants::DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES + 1];
    let result = HttpResponse::from_mock(
        StatusCode::BAD_GATEWAY,
        HeaderMap::new(),
        body,
        Url::parse("https://example.test/resource").expect("502 response url"),
    )
    .error_for_status_with_body()
    .await;
    let error = match result {
        Ok(_) => panic!("oversized error body must be bounded by default"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        HttpRequestError::ResponseTooLarge { size, max }
            if size == crate::constants::DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES + 1
                && max == crate::constants::DEFAULT_MAX_ERROR_BODY_LENGTH_BYTES
    ));
}

#[tokio::test]
async fn mock_response_text_respects_max_body_size_limit() {
    let error = HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        b"too-large".to_vec(),
        Url::parse("https://example.test/resource").expect("mock response url"),
    )
    .with_max_body_size(Some(3))
    .text()
    .await
    .expect_err("response larger than limit should fail");

    assert!(matches!(
        error,
        HttpRequestError::ResponseTooLarge { size: 9, max: 3 }
    ));
}

#[tokio::test]
async fn execute_retries_idempotent_get_after_too_many_requests_until_success() {
    let transport = CountingTransport::from_responses(vec![
        Ok(HttpResponse::from_mock(
            StatusCode::TOO_MANY_REQUESTS,
            HeaderMap::new(),
            Vec::new(),
            Url::parse("https://example.test/resource").expect("429 response url"),
        )),
        Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            br#"{"ok":true}"#.to_vec(),
            Url::parse("https://example.test/resource").expect("200 response url"),
        )),
    ]);
    let attempts = transport.attempts.clone();
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 1,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .build()
        .expect("build http client");

    let response = client
        .request(Method::GET, "https://example.test/resource")
        .send()
        .await
        .expect("retried GET response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        *attempts.lock().expect("attempts lock"),
        2,
        "429 responses should follow the same retry contract as transient 5xx responses"
    );
}

#[tokio::test(start_paused = true)]
async fn execute_uses_retry_after_header_delay_for_retryable_status() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("2"));
    let transport = CountingTransport::from_responses(vec![
        Ok(HttpResponse::from_mock(
            StatusCode::TOO_MANY_REQUESTS,
            headers,
            Vec::new(),
            Url::parse("https://example.test/resource").expect("429 response url"),
        )),
        Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            br#"{"ok":true}"#.to_vec(),
            Url::parse("https://example.test/resource").expect("200 response url"),
        )),
    ]);
    let attempts = transport.attempts.clone();
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 1,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_secs(5),
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .build()
        .expect("build http client");

    let started_at = tokio::time::Instant::now();
    let response = client
        .request(Method::GET, "https://example.test/resource")
        .send()
        .await
        .expect("retried GET response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(*attempts.lock().expect("attempts lock"), 2);
    assert_eq!(
        tokio::time::Instant::now() - started_at,
        Duration::from_secs(2)
    );
}

#[tokio::test(start_paused = true)]
async fn execute_clamps_retry_after_header_to_configured_max_delay() {
    let mut headers = HeaderMap::new();
    headers.insert(http::header::RETRY_AFTER, HeaderValue::from_static("86400"));
    let transport = CountingTransport::from_responses(vec![
        Ok(HttpResponse::from_mock(
            StatusCode::TOO_MANY_REQUESTS,
            headers,
            Vec::new(),
            Url::parse("https://example.test/resource").expect("429 response url"),
        )),
        Ok(HttpResponse::from_mock(
            StatusCode::OK,
            HeaderMap::new(),
            Vec::new(),
            Url::parse("https://example.test/resource").expect("200 response url"),
        )),
    ]);
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 1,
            base_delay: Duration::ZERO,
            max_delay: Duration::from_secs(3),
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .build()
        .expect("build http client");

    let started_at = tokio::time::Instant::now();
    client
        .get("https://example.test/resource")
        .send()
        .await
        .expect("retried response");

    assert_eq!(
        tokio::time::Instant::now() - started_at,
        Duration::from_secs(3)
    );
}

#[test]
fn builder_clients_disable_redirects_but_external_clients_are_not_assumed_safe() {
    let built = HttpClientBuilder::new().build().expect("built client");
    assert!(built.redirects_disabled());

    let external = reqwest::Client::builder().build().expect("external client");
    let wrapped = crate::HttpClient::with_client(external, RetryConfig::default());
    assert!(!wrapped.redirects_disabled());
}

#[test]
fn retry_after_http_date_is_clamped_to_configured_max_delay() {
    let retry = RetryConfig {
        max_retries: 1,
        base_delay: Duration::ZERO,
        max_delay: Duration::from_secs(4),
        retry_non_idempotent: false,
    };
    let mut headers = HeaderMap::new();
    let retry_at = std::time::SystemTime::now() + Duration::from_secs(86_400);
    headers.insert(
        http::header::RETRY_AFTER,
        httpdate::fmt_http_date(retry_at)
            .parse()
            .expect("Retry-After date"),
    );
    let response = HttpResponse::from_mock(
        StatusCode::SERVICE_UNAVAILABLE,
        headers,
        Vec::new(),
        Url::parse("https://example.test/resource").expect("response URL"),
    );

    assert_eq!(
        retry_delay_for_response(&retry, &response, 0),
        Duration::from_secs(4)
    );
}

#[tokio::test]
async fn execute_does_not_retry_non_retryable_server_status() {
    let transport = CountingTransport::from_responses(vec![Ok(HttpResponse::from_mock(
        StatusCode::HTTP_VERSION_NOT_SUPPORTED,
        HeaderMap::new(),
        Vec::new(),
        Url::parse("https://example.test/resource").expect("505 response url"),
    ))]);
    let attempts = transport.attempts.clone();
    let client = HttpClientBuilder::new()
        .retry(RetryConfig {
            max_retries: 3,
            base_delay: Duration::from_millis(0),
            max_delay: Duration::from_millis(0),
            retry_non_idempotent: false,
        })
        .with_transport(transport)
        .build()
        .expect("build http client");

    let response = client
        .request(Method::GET, "https://example.test/resource")
        .send()
        .await
        .expect("GET response");

    assert_eq!(response.status(), StatusCode::HTTP_VERSION_NOT_SUPPORTED);
    assert_eq!(*attempts.lock().expect("attempts lock"), 1);
}

#[tokio::test]
async fn convenience_helpers_send_expected_methods_headers_and_payload_encodings() {
    let transport = RecordingTransport::from_responses(vec![
        Ok(mock_json_response(
            HeaderMap::new(),
            &json!({ "issuer": "https://issuer.example.test" }),
        )),
        Ok(mock_json_response(
            HeaderMap::new(),
            &json!({ "sub": "user-123" }),
        )),
        Ok(mock_json_response(
            HeaderMap::new(),
            &json!({ "access_token": "token-123" }),
        )),
        Ok(mock_json_response(
            HeaderMap::new(),
            &json!({ "status": "created" }),
        )),
    ]);
    let recorded_requests = transport.requests.clone();
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("build http client");

    let issuer = client
        .get_json::<serde_json::Value>("https://example.test/openid-configuration")
        .await
        .expect("openid configuration");
    let me = client
        .get_json_with_bearer::<serde_json::Value>("https://example.test/me", "opaque-bearer")
        .await
        .expect("bearer request");
    let token = client
        .post_form::<serde_json::Value, _>(
            "https://example.test/oauth/token",
            &[("grant_type", "client_credentials")],
        )
        .await
        .expect("form request");
    let created = client
        .post_json::<serde_json::Value, _>(
            "https://example.test/resources",
            &json!({ "name": "example" }),
        )
        .await
        .expect("json request");

    assert_eq!(issuer["issuer"], "https://issuer.example.test");
    assert_eq!(me["sub"], "user-123");
    assert_eq!(token["access_token"], "token-123");
    assert_eq!(created["status"], "created");

    let requests = recorded_requests.lock().expect("recorded requests lock");
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[0].method(), Method::GET);
    assert_eq!(requests[1].method(), Method::GET);
    assert_eq!(requests[2].method(), Method::POST);
    assert_eq!(requests[3].method(), Method::POST);
    assert_eq!(
        requests[1]
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer opaque-bearer")
    );
    assert!(
        requests[2]
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded")),
        "post_form should encode bodies as application/x-www-form-urlencoded"
    );
    assert!(
        requests[3]
            .headers()
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json")),
        "post_json should encode bodies as application/json"
    );
}

#[test]
fn request_builder_build_and_try_clone_preserve_headers_query_and_auth() {
    let client = HttpClientBuilder::default()
        .with_reqwest_builder(|builder| builder.user_agent("http-request-client-tests"))
        .build()
        .expect("build http client");

    let mut extra_headers = HeaderMap::new();
    extra_headers.insert("x-extra", HeaderValue::from_static("from-map"));

    let builder = client
        .patch("https://example.test/resource")
        .header("x-inline", "inline-value")
        .headers(extra_headers)
        .query(&[("query", "value")])
        .basic_auth("aladdin", Some("open sesame"))
        .timeout(Duration::from_secs(7))
        .body("payload");
    let cloned_builder = builder.try_clone().expect("cloneable builder");

    let request = builder.build().expect("build request");
    let cloned_request = cloned_builder.build().expect("build cloned request");

    assert_eq!(request.method(), Method::PATCH);
    assert_eq!(cloned_request.method(), Method::PATCH);
    assert_eq!(
        request.url().as_str(),
        "https://example.test/resource?query=value"
    );
    assert_eq!(
        request
            .headers()
            .get("x-inline")
            .and_then(|value| value.to_str().ok()),
        Some("inline-value")
    );
    assert_eq!(
        request
            .headers()
            .get("x-extra")
            .and_then(|value| value.to_str().ok()),
        Some("from-map")
    );
    assert_eq!(
        request
            .headers()
            .get(http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Basic YWxhZGRpbjpvcGVuIHNlc2FtZQ==")
    );
}

#[test]
fn verb_helpers_build_requests_with_expected_methods() {
    let client = crate::HttpClient::new().expect("build default client");
    let client_with_inner =
        crate::HttpClient::with_client(client.inner().clone(), RetryConfig::default());

    let put = client_with_inner
        .put("https://example.test/resource")
        .build()
        .expect("put request");
    let delete = client_with_inner
        .delete("https://example.test/resource")
        .build()
        .expect("delete request");
    let head = client_with_inner
        .head("https://example.test/resource")
        .build()
        .expect("head request");

    assert_eq!(put.method(), Method::PUT);
    assert_eq!(delete.method(), Method::DELETE);
    assert_eq!(head.method(), Method::HEAD);
}

#[tokio::test]
async fn response_helpers_fail_closed_for_invalid_status_and_decode_errors() {
    let status_error = HttpResponse::from_mock(
        StatusCode::BAD_REQUEST,
        HeaderMap::new(),
        Vec::new(),
        Url::parse("https://example.test/resource").expect("400 response url"),
    )
    .error_for_status();
    assert!(matches!(
        status_error,
        Err(HttpRequestError::HttpStatus {
            status: StatusCode::BAD_REQUEST,
            body: None
        })
    ));

    let response = HttpResponse::from_mock(
        StatusCode::INTERNAL_SERVER_ERROR,
        HeaderMap::new(),
        Vec::new(),
        Url::parse("https://example.test/resource").expect("500 response url"),
    );
    let status_ref_error = response.error_for_status_ref();
    assert!(matches!(
        status_ref_error,
        Err(HttpRequestError::HttpStatus {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: None
        })
    ));

    let decode_error = HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        vec![0xff, 0xfe],
        Url::parse("https://example.test/resource").expect("mock response url"),
    )
    .text()
    .await
    .expect_err("invalid utf-8 should fail");
    assert!(matches!(decode_error, HttpRequestError::Decode { .. }));

    let json_error = HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        br#"{"missing":"brace""#.to_vec(),
        Url::parse("https://example.test/resource").expect("mock response url"),
    )
    .json::<serde_json::Value>()
    .await
    .expect_err("invalid json should fail");
    assert!(matches!(json_error, HttpRequestError::Decode { .. }));
}

#[tokio::test]
async fn mock_response_bytes_url_and_cache_ttl_fallback_are_preserved() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=not-a-number"),
    );
    let url = Url::parse("https://example.test/resource").expect("mock response url");
    let response = HttpResponse::from_mock(
        StatusCode::OK,
        headers.clone(),
        b"body".to_vec(),
        url.clone(),
    );

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.url(), &url);
    assert_eq!(
        response
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok()),
        Some("max-age=not-a-number")
    );
    assert!(
        response.into_reqwest().is_none(),
        "mock responses should not pretend to be reqwest responses"
    );

    let bytes = HttpResponse::from_mock(StatusCode::OK, HeaderMap::new(), b"body".to_vec(), url)
        .bytes()
        .await
        .expect("mock bytes");
    assert_eq!(bytes.as_ref(), b"body");

    let client = HttpClientBuilder::new()
        .with_transport(SequenceTransport::from_responses(vec![Ok(
            mock_json_response(headers, &json!({ "issuer": "https://issuer.example.test" })),
        )]))
        .build()
        .expect("build http client");
    let response = client
        .get_json_with_cache::<serde_json::Value>(
            "https://example.test/resource",
            Duration::from_millis(25),
        )
        .await
        .expect("cached json response");

    assert!(
        !response.expired(),
        "invalid max-age directives should fall back to the caller-provided ttl"
    );
}

#[tokio::test]
async fn default_success_body_limit_rejects_oversized_response() {
    let body = vec![b'x'; crate::constants::DEFAULT_MAX_RESPONSE_LENGTH_BYTES + 1];
    let error = HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        body,
        Url::parse("https://example.test/large").expect("response url"),
    )
    .bytes()
    .await
    .expect_err("successful response bodies must have a default bound");

    assert!(matches!(error, HttpRequestError::ResponseTooLarge { .. }));
}

#[tokio::test]
async fn extreme_cache_control_max_age_does_not_panic() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("max-age=18446744073709551615"),
    );
    let client = HttpClientBuilder::new()
        .with_transport(SequenceTransport::from_responses(vec![Ok(
            mock_json_response(headers, &json!({ "issuer": "https://issuer.example.test" })),
        )]))
        .build()
        .expect("build http client");

    let join = tokio::spawn(async move {
        client
            .get_json_with_cache::<serde_json::Value>(
                "https://example.test/discovery",
                Duration::from_secs(30),
            )
            .await
    })
    .await;

    assert!(
        join.is_ok(),
        "untrusted cache metadata must not panic the task"
    );
}

#[test]
fn returned_transport_error_diagnostics_redact_sensitive_url() {
    let error = transport_error_with_sensitive_url();
    let display = error.to_string();
    let debug = format!("{error:?}");
    let source = std::error::Error::source(&error).expect("transport source");
    let source_display = source.to_string();
    let source_debug = format!("{source:?}");

    assert!(
        !display.contains("access_token=sentinel"),
        "display leaked URL"
    );
    assert!(!debug.contains("access_token=sentinel"), "debug leaked URL");
    assert!(
        !source_display.contains("access_token=sentinel"),
        "source display leaked URL"
    );
    assert!(
        !source_debug.contains("access_token=sentinel"),
        "source debug leaked URL"
    );
}

#[test]
fn capped_reqwest_response_cannot_escape_as_raw_response() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind response server");
    let address = listener.local_addr().expect("response server address");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept response request");
        let mut request = [0_u8; 1024];
        let _ = std::io::Read::read(&mut stream, &mut request);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbody")
            .expect("write response");
    });

    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    runtime.block_on(async move {
        let response = reqwest::Client::new()
            .get(format!("http://{address}/resource"))
            .send()
            .await
            .expect("response");
        assert!(
            HttpResponse::from_reqwest(response)
                .with_max_body_size(Some(1))
                .into_reqwest()
                .is_none(),
            "capped responses must not expose an uncapped reqwest body"
        );
    });
}

#[test]
fn http_client_builder_debug_redacts_default_header_values() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer client-debug-sentinel"),
    );
    let builder =
        HttpClientBuilder::new().with_reqwest_builder(|builder| builder.default_headers(headers));
    let builder_debug = format!("{builder:?}");
    assert!(!builder_debug.contains("client-debug-sentinel"));
}

#[test]
fn http_client_debug_redacts_default_header_values() {
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::AUTHORIZATION,
        HeaderValue::from_static("Bearer client-debug-sentinel"),
    );
    let builder =
        HttpClientBuilder::new().with_reqwest_builder(|builder| builder.default_headers(headers));

    let client = builder.build().expect("build client");
    let client_debug = format!("{client:?}");
    assert!(!client_debug.contains("client-debug-sentinel"));
}

#[test]
fn http_request_builder_debug_redacts_headers_query_and_body() {
    let client = HttpClientBuilder::new().build().expect("build client");
    let request = client
        .get("https://example.test/resource")
        .header("authorization", "Bearer request-debug-sentinel")
        .query(&[("secret", "query-debug-sentinel")])
        .body("body-debug-sentinel");
    let request_debug = format!("{request:?}");
    for secret in [
        "request-debug-sentinel",
        "query-debug-sentinel",
        "body-debug-sentinel",
    ] {
        assert!(
            !request_debug.contains(secret),
            "request debug leaked {secret}"
        );
    }
}

#[test]
fn http_error_debug_redacts_retained_response_body() {
    let error = HttpRequestError::HttpStatus {
        status: StatusCode::BAD_REQUEST,
        body: Some("response-body-debug-sentinel".to_string()),
    };
    assert!(!format!("{error:?}").contains("response-body-debug-sentinel"));
}

#[test]
fn custom_transport_does_not_claim_redirects_are_disabled() {
    let client = HttpClientBuilder::new()
        .with_transport(SequenceTransport::from_responses(Vec::new()))
        .build()
        .expect("build client");

    assert!(!client.redirects_disabled());
}
