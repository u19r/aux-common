use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use futures_util::FutureExt;
use http::HeaderMap;
use reqwest::{Request, StatusCode, Url, header};

use crate::{
    HttpClientBuilder, HttpResponse, OAuthAuthorizationCodeRequest, OAuthRefreshTokenRequest,
    OAuthRevocationEndpoint, OAuthRevocationRequest, OAuthTokenEndpoint, OAuthUserinfoEndpoint,
    Transport, TransportFuture,
};

#[derive(Clone)]
struct RecordingTransport {
    responses: Arc<Mutex<VecDeque<HttpResponse>>>,
    requests: Arc<Mutex<Vec<Request>>>,
}

impl std::fmt::Debug for RecordingTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RecordingTransport")
    }
}

impl RecordingTransport {
    fn new(responses: Vec<HttpResponse>) -> Self {
        Self {
            responses: Arc::new(Mutex::new(responses.into())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: Request) -> TransportFuture {
        self.requests
            .lock()
            .expect("recorded request lock")
            .push(request);
        let response = self
            .responses
            .lock()
            .expect("response queue lock")
            .pop_front()
            .expect("mock response");
        async move { Ok(response) }.boxed()
    }
}

#[tokio::test]
async fn given_authorization_code_request_when_exchanged_then_public_client_form_is_sent() {
    let transport = RecordingTransport::new(vec![json_response(
        r#"{"access_token":"access","refresh_token":"refresh","token_type":"Bearer","expires_in":60}"#,
    )]);
    let requests = transport.requests.clone();
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("http client");

    let token = client
        .oauth_authorization_code_public_client(
            &OAuthTokenEndpoint::new("https://auth.example.test/oauth2/token"),
            &OAuthAuthorizationCodeRequest::public_client(
                "client-id",
                "auth-code",
                "http://127.0.0.1:8787/callback",
                "code-verifier",
            ),
        )
        .await
        .expect("oauth token");

    assert_eq!(token.access_token(), "access");
    assert_eq!(token.refresh_token(), Some("refresh"));
    let requests = requests.lock().expect("request lock");
    assert_eq!(requests[0].method(), reqwest::Method::POST);
    assert_eq!(
        requests[0].url().as_str(),
        "https://auth.example.test/oauth2/token"
    );
    assert!(form_body(&requests[0]).contains("grant_type=authorization_code"));
    assert!(form_body(&requests[0]).contains("client_id=client-id"));
    assert!(form_body(&requests[0]).contains("code=auth-code"));
    assert!(form_body(&requests[0]).contains("code_verifier=code-verifier"));
    assert!(!form_body(&requests[0]).contains("client_secret"));
}

#[tokio::test]
async fn given_refresh_token_request_when_exchanged_then_refresh_grant_form_is_sent() {
    let transport =
        RecordingTransport::new(vec![json_response(r#"{"access_token":"new-access"}"#)]);
    let requests = transport.requests.clone();
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("http client");

    let token = client
        .oauth_refresh_token_public_client(
            &OAuthTokenEndpoint::new("https://auth.example.test/oauth2/token"),
            &OAuthRefreshTokenRequest::public_client("client-id", "refresh-token"),
        )
        .await
        .expect("oauth refresh");

    assert_eq!(token.access_token(), "new-access");
    let requests = requests.lock().expect("request lock");
    assert!(form_body(&requests[0]).contains("grant_type=refresh_token"));
    assert!(form_body(&requests[0]).contains("refresh_token=refresh-token"));
    assert!(!form_body(&requests[0]).contains("client_secret"));
}

#[tokio::test]
async fn given_token_endpoint_headers_when_exchanged_then_headers_are_sent_with_form_request() {
    let transport =
        RecordingTransport::new(vec![json_response(r#"{"access_token":"new-access"}"#)]);
    let requests = transport.requests.clone();
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("http client");

    let token = client
        .oauth_refresh_token_public_client(
            &OAuthTokenEndpoint::new("https://auth.example.test/oauth2/token")
                .with_header("cf-connecting-host", "tenant.example.test"),
            &OAuthRefreshTokenRequest::public_client("client-id", "refresh-token"),
        )
        .await
        .expect("oauth refresh");

    assert_eq!(token.access_token(), "new-access");
    let requests = requests.lock().expect("request lock");
    assert_eq!(
        requests[0]
            .headers()
            .get("cf-connecting-host")
            .and_then(|value| value.to_str().ok()),
        Some("tenant.example.test")
    );
    assert!(form_body(&requests[0]).contains("grant_type=refresh_token"));
}

#[tokio::test]
async fn given_userinfo_request_when_sent_then_bearer_token_is_in_authorization_header_only() {
    let transport = RecordingTransport::new(vec![json_response(r#"{"sub":"user-1"}"#)]);
    let requests = transport.requests.clone();
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("http client");

    let userinfo: serde_json::Value = client
        .oauth_userinfo(
            &OAuthUserinfoEndpoint::new("https://auth.example.test/userinfo"),
            "access-token",
        )
        .await
        .expect("userinfo");

    assert_eq!(userinfo["sub"], "user-1");
    let requests = requests.lock().expect("request lock");
    assert_eq!(requests[0].method(), reqwest::Method::GET);
    assert_eq!(
        requests[0]
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok()),
        Some("Bearer access-token")
    );
    assert!(!requests[0].url().as_str().contains("access-token"));
}

#[tokio::test]
async fn given_revocation_request_when_sent_then_public_client_form_is_sent() {
    let transport = RecordingTransport::new(vec![HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        Vec::new(),
        Url::parse("https://auth.example.test/oauth2/revoke").expect("mock url"),
    )]);
    let requests = transport.requests.clone();
    let client = HttpClientBuilder::new()
        .with_transport(transport)
        .build()
        .expect("http client");

    client
        .oauth_revoke_public_client(
            &OAuthRevocationEndpoint::new("https://auth.example.test/oauth2/revoke")
                .with_header("cf-connecting-host", "tenant.example.test"),
            &OAuthRevocationRequest::public_client("client-id", "refresh-token", "refresh_token"),
        )
        .await
        .expect("oauth revoke");

    let requests = requests.lock().expect("request lock");
    assert_eq!(requests[0].method(), reqwest::Method::POST);
    assert_eq!(
        requests[0]
            .headers()
            .get("cf-connecting-host")
            .and_then(|value| value.to_str().ok()),
        Some("tenant.example.test")
    );
    assert!(form_body(&requests[0]).contains("client_id=client-id"));
    assert!(form_body(&requests[0]).contains("token=refresh-token"));
    assert!(form_body(&requests[0]).contains("token_type_hint=refresh_token"));
    assert!(!form_body(&requests[0]).contains("client_secret"));
}

fn json_response(body: &str) -> HttpResponse {
    HttpResponse::from_mock(
        StatusCode::OK,
        HeaderMap::new(),
        body.as_bytes().to_vec(),
        Url::parse("https://auth.example.test/mock").expect("mock url"),
    )
}

fn form_body(request: &Request) -> String {
    request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default()
}
