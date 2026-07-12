use std::{collections::VecDeque, sync::Mutex};

use http::{HeaderMap, Method, StatusCode};
use http_request::{
    HttpClient, HttpResponse, RetryConfig, Transport, TransportFuture, reqwest::Request,
};

use crate::{AwsSigv4HttpClient, AwsStaticCredentials, CredentialSource};

struct QueuedResponse {
    method: Method,
    url: String,
    expected_content_type: Option<String>,
    response: HttpResponse,
}

struct QueueTransport {
    responses: Mutex<VecDeque<QueuedResponse>>,
}

impl std::fmt::Debug for QueueTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QueueTransport").finish()
    }
}

impl QueueTransport {
    fn new(responses: Vec<QueuedResponse>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }
}

impl Transport for QueueTransport {
    fn send(&self, request: Request) -> TransportFuture {
        let next = self
            .responses
            .lock()
            .expect("responses lock")
            .pop_front()
            .expect("queued response");
        let method = request.method().clone();
        let url = request.url().to_string();
        let authorization = request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let amz_date = request
            .headers()
            .get("x-amz-date")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let content_type = request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        Box::pin(async move {
            assert_eq!(next.method, method);
            assert_eq!(next.url, url);
            assert!(
                authorization
                    .as_deref()
                    .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 ")),
                "expected Authorization header to contain AWS SigV4 auth, got {authorization:?}"
            );
            assert!(
                amz_date.is_some(),
                "expected x-amz-date header to be present"
            );
            assert_eq!(content_type, next.expected_content_type);
            Ok(next.response)
        })
    }
}

fn static_credentials() -> CredentialSource {
    CredentialSource::Static(AwsStaticCredentials {
        access_key_id: "AKIDEXAMPLE".to_string(),
        secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
        session_token: None,
    })
}

#[test]
fn signed_client_rejects_http_clients_without_a_no_redirect_guarantee() {
    let external = http_request::reqwest::Client::builder()
        .build()
        .expect("external reqwest client");
    let client = HttpClient::with_client(external, RetryConfig::default());

    let error = AwsSigv4HttpClient::new(
        client,
        "https://service.test",
        "us-east-1",
        static_credentials(),
        "execute-api",
    )
    .err()
    .expect("unconstrained redirect client must be rejected");

    assert!(matches!(error, crate::SigningError::RedirectPolicyRequired));
}

#[tokio::test]
async fn send_xml_returns_text_body_and_etag() {
    let mut headers = HeaderMap::new();
    headers.insert("etag", http::HeaderValue::from_static("etag-123"));
    let response = HttpResponse::from_mock(
        StatusCode::CREATED,
        headers,
        b"<DistributionTenant><Id>dtenant_123</Id></DistributionTenant>".to_vec(),
        "https://cloudfront.test/2020-05-31/distribution-tenant"
            .parse()
            .expect("url"),
    );
    let client = HttpClient::builder()
        .with_transport(QueueTransport::new(vec![QueuedResponse {
            method: Method::POST,
            url: "https://cloudfront.test/2020-05-31/distribution-tenant".to_string(),
            expected_content_type: Some("application/xml".to_string()),
            response,
        }]))
        .build()
        .expect("http client");
    let signed = AwsSigv4HttpClient::new(
        client,
        "https://cloudfront.test",
        "us-east-1",
        static_credentials(),
        "cloudfront",
    )
    .expect("signed client");

    let response = signed
        .send_xml(
            Method::POST,
            "/2020-05-31/distribution-tenant",
            Some("<CreateDistributionTenantRequest />".to_string()),
            HeaderMap::new(),
        )
        .await
        .expect("xml response");

    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.etag(), Some("etag-123"));
    assert_eq!(
        response.body(),
        "<DistributionTenant><Id>dtenant_123</Id></DistributionTenant>"
    );
    assert_eq!(
        response.url(),
        "https://cloudfront.test/2020-05-31/distribution-tenant"
    );
}

#[tokio::test]
async fn send_text_preserves_explicit_content_type_override() {
    let response = HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        b"{\"ok\":true}".to_vec(),
        "https://service.test/resource".parse().expect("url"),
    );
    let client = HttpClient::builder()
        .with_transport(QueueTransport::new(vec![QueuedResponse {
            method: Method::PUT,
            url: "https://service.test/resource".to_string(),
            expected_content_type: Some("application/custom+json".to_string()),
            response,
        }]))
        .build()
        .expect("http client");
    let signed = AwsSigv4HttpClient::new(
        client,
        "https://service.test",
        "us-east-1",
        static_credentials(),
        "execute-api",
    )
    .expect("signed client");
    let mut headers = HeaderMap::new();
    headers.insert(
        "content-type",
        http::HeaderValue::from_static("application/custom+json"),
    );

    let response = signed
        .send_text(
            Method::PUT,
            "/resource",
            Some("{\"hello\":\"world\"}".to_string()),
            headers,
            Some("application/json"),
        )
        .await
        .expect("text response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.body(), "{\"ok\":true}");
    assert_eq!(response.etag(), None);
}
