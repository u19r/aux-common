use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};
use http_request::Url;

use crate::{
    AuthorizationRequest, HttpJobError, HttpRequest, HttpRequestInput, MAX_HTTP_HEADER_BYTES,
    MAX_HTTP_HEADER_COUNT,
};

fn request(headers: HeaderMap) -> HttpRequestInput {
    HttpRequestInput {
        method: Method::POST,
        url: Url::parse("https://api.example.com/jobs").expect("request URL"),
        headers,
        body: Bytes::new(),
    }
}

fn headers_with_count(count: usize) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for index in 0..count {
        let name =
            HeaderName::from_bytes(format!("x-test-{index}").as_bytes()).expect("test header name");
        headers.insert(name, HeaderValue::from_static("v"));
    }
    headers
}

#[test]
fn given_header_count_at_bound_when_request_is_built_then_it_is_accepted() {
    let result = HttpRequest::try_new(request(headers_with_count(MAX_HTTP_HEADER_COUNT)));

    assert!(result.is_ok());
}

#[test]
fn given_header_count_above_bound_when_request_is_built_then_it_is_rejected() {
    let result = HttpRequest::try_new(request(headers_with_count(MAX_HTTP_HEADER_COUNT + 1)));

    assert_eq!(
        result.expect_err("header count must be bounded"),
        HttpJobError::HeaderCountTooLarge
    );
}

#[test]
fn given_header_bytes_at_bound_when_request_is_built_then_it_is_accepted() {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-test");
    let value = vec![b'a'; MAX_HTTP_HEADER_BYTES - name.as_str().len()];
    headers.insert(
        name,
        HeaderValue::from_bytes(&value).expect("test header value"),
    );

    assert!(HttpRequest::try_new(request(headers)).is_ok());
}

#[test]
fn given_header_bytes_above_bound_when_request_is_built_then_it_is_rejected() {
    let mut headers = HeaderMap::new();
    let name = HeaderName::from_static("x-test");
    let value = vec![b'a'; MAX_HTTP_HEADER_BYTES - name.as_str().len() + 1];
    headers.insert(
        name,
        HeaderValue::from_bytes(&value).expect("test header value"),
    );

    assert_eq!(
        HttpRequest::try_new(request(headers)).expect_err("header bytes must be bounded"),
        HttpJobError::HeaderBytesTooLarge
    );
}

#[test]
fn given_sensitive_or_host_header_when_request_is_built_then_it_is_rejected() {
    for name in [
        "authorization",
        "cookie",
        "host",
        "proxy-authorization",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "x-amz-date",
        "x-amz-content-sha256",
        "x-amz-security-token",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-real-ip",
        "forwarded",
        "cf-connecting-ip",
        "true-client-ip",
        "x-original-url",
        "x-rewrite-url",
        "x-http-method-override",
        "x-method-override",
        "x-amzn-trace-id",
        "referer",
        "origin",
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(name, HeaderValue::from_static("blocked"));

        assert_eq!(
            HttpRequest::try_new(request(headers)).expect_err("sensitive header must be blocked"),
            HttpJobError::SensitiveHeader,
            "header {name}"
        );
    }
}

#[test]
fn given_secret_request_when_safe_diagnostic_is_requested_then_only_bounded_sizes_are_returned() {
    let mut input = request(HeaderMap::new());
    input.body = Bytes::from_static(b"connector-secret");
    input.headers.insert(
        HeaderName::from_static("x-ordinary"),
        HeaderValue::from_static("ordinary-value"),
    );
    let request = HttpRequest::try_new(input).expect("request");

    let diagnostic = request
        .diagnostic_projection(false)
        .expect("safe projection");
    assert_eq!(diagnostic.header_count, 1);
    assert_eq!(diagnostic.body_bytes, b"connector-secret".len());
    let rendered = format!("{diagnostic:?}");
    assert!(!rendered.contains("connector-secret"));
    assert!(!rendered.contains("ordinary-value"));
    assert!(!rendered.contains("api.example.com"));
}

#[test]
fn given_secret_request_when_secret_diagnostic_is_requested_then_it_is_rejected_at_the_boundary() {
    let mut input = request(HeaderMap::new());
    input.body = Bytes::from_static(b"connector-secret");
    let request = HttpRequest::try_new(input).expect("request");

    assert_eq!(
        request
            .diagnostic_projection(true)
            .expect_err("secret projection must be rejected"),
        HttpJobError::SensitiveProjection
    );
}

#[test]
fn given_extension_method_when_debug_is_rendered_then_the_method_is_bounded() {
    let extension_method = Method::from_bytes(b"x-secret-token").expect("extension method");
    assert_eq!(
        http_request::method_telemetry_label(&extension_method),
        "OTHER"
    );
    let mut input = request(HeaderMap::new());
    input.method = extension_method;
    let rendered_input = format!("{input:?}");
    assert!(rendered_input.contains("OTHER"));
    assert!(!rendered_input.contains("x-secret-token"));

    let request = HttpRequest::try_new(input).expect("request");
    let rendered_request = format!("{request:?}");
    assert!(rendered_request.contains("OTHER"));
    assert!(!rendered_request.contains("x-secret-token"));

    let authorization = AuthorizationRequest::new(
        request.method(),
        request.url(),
        request.headers().clone(),
        request.body(),
    );
    let rendered_authorization = format!("{authorization:?}");
    assert!(rendered_authorization.contains("OTHER"));
    assert!(!rendered_authorization.contains("x-secret-token"));
}
