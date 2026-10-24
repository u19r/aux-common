use std::time::Duration;

use bg_jobs::ValidationError;
use bytes::Bytes;
use http::{HeaderMap, Method};
use http_request::Url;

use crate::{
    ApprovedEndpoint, HttpJobError, HttpPolicy, HttpPolicyId, HttpRequest, HttpRequestInput,
};

fn policy() -> crate::HttpPolicy {
    HttpPolicy::builder(HttpPolicyId::try_new("test").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .try_build()
        .expect("policy")
}

fn request(url: &str, body: Bytes) -> HttpRequestInput {
    HttpRequestInput {
        method: Method::POST,
        url: Url::parse(url).expect("URL"),
        headers: HeaderMap::new(),
        body,
    }
}

#[test]
fn given_endpoint_registration_when_matching_then_https_host_and_port_are_required() {
    let exact = ApprovedEndpoint::exact("API.EXAMPLE.COM.").expect("endpoint");
    assert!(exact.matches(&Url::parse("https://api.example.com/path").expect("URL")));
    assert!(!exact.matches(&Url::parse("http://api.example.com/path").expect("URL")));
    assert!(!exact.matches(&Url::parse("https://other.example.com/path").expect("URL")));
    assert!(!exact.matches(&Url::parse("https://api.example.com:8443/path").expect("URL")));

    let subdomains = ApprovedEndpoint::with_subdomains("example.com").expect("endpoint");
    assert!(subdomains.matches(&Url::parse("https://api.example.com/path").expect("URL")));
    assert!(!subdomains.matches(&Url::parse("https://example.com.evil/path").expect("URL")));
}

#[test]
fn given_http_or_secret_url_when_constructed_then_request_is_rejected() {
    for (url, expected) in [
        (
            "http://api.example.com/path",
            HttpJobError::InsecureEndpoint,
        ),
        (
            "https://user:password@api.example.com/path",
            HttpJobError::EndpointNotApproved,
        ),
        (
            "https://api.example.com/path#fragment",
            HttpJobError::EndpointNotApproved,
        ),
        ("https://127.0.0.1/path", HttpJobError::EndpointNotApproved),
    ] {
        assert!(matches!(
            HttpRequest::try_new(request(url, Bytes::new())),
            Err(error) if error == expected
        ));
    }
}

#[test]
fn given_policy_limits_when_built_then_zero_or_oversized_values_fail_closed() {
    let id = HttpPolicyId::try_new("limits").expect("policy ID");
    let endpoint = ApprovedEndpoint::exact("api.example.com").expect("endpoint");
    assert!(matches!(
        HttpPolicy::builder(id.clone())
            .endpoint(endpoint.clone())
            .max_request_bytes(0)
            .try_build(),
        Err(HttpJobError::Validation(_))
    ));
    assert_eq!(
        HttpPolicy::builder(id.clone())
            .endpoint(endpoint.clone())
            .max_response_bytes(0)
            .try_build()
            .expect_err("zero response bound"),
        HttpJobError::Validation(ValidationError::InvalidValue {
            field: "HTTP response body limit",
        })
    );
    assert_eq!(
        HttpPolicy::builder(id.clone())
            .endpoint(endpoint.clone())
            .request_timeout(Duration::ZERO)
            .try_build()
            .expect_err("zero timeout"),
        HttpJobError::Validation(ValidationError::InvalidValue {
            field: "HTTP request timeout",
        })
    );
    assert_eq!(
        HttpPolicy::builder(id)
            .endpoint(endpoint)
            .retry_after_max(Duration::ZERO)
            .try_build()
            .expect_err("zero retry-after bound"),
        HttpJobError::Validation(ValidationError::InvalidValue {
            field: "Retry-After maximum",
        })
    );
}

#[test]
fn given_connect_timeout_longer_than_request_timeout_when_policy_is_built_then_it_is_clamped() {
    let policy = HttpPolicy::builder(HttpPolicyId::try_new("timeout-bound").expect("policy ID"))
        .endpoint(ApprovedEndpoint::exact("api.example.com").expect("endpoint"))
        .connect_timeout(Duration::from_secs(10))
        .request_timeout(Duration::from_secs(2))
        .try_build()
        .expect("policy");

    assert_eq!(policy.connect_timeout(), Duration::from_secs(2));
    assert_eq!(policy.request_timeout(), Duration::from_secs(2));
}

#[test]
fn given_sensitive_headers_when_request_or_policy_is_built_then_material_is_rejected() {
    for name in [
        "authorization",
        "cookie",
        "connection",
        "content-length",
        "x-amz-date",
        "x-amz-content-sha256",
        "x-amz-security-token",
    ] {
        let mut input = request("https://api.example.com/path", Bytes::new());
        input
            .headers
            .insert(name, "secret".parse().expect("header"));
        assert_eq!(
            HttpRequest::try_new(input).expect_err("forbidden header"),
            HttpJobError::SensitiveHeader,
            "header {name}"
        );
    }

    for name in [
        "authorization",
        "connection",
        "content-length",
        "x-amz-date",
        "x-amz-content-sha256",
        "x-amz-security-token",
    ] {
        let id = HttpPolicyId::try_new(format!("headers-{name}")).expect("policy ID");
        let endpoint = ApprovedEndpoint::exact("api.example.com").expect("endpoint");
        assert_eq!(
            HttpPolicy::builder(id)
                .endpoint(endpoint)
                .idempotency_header(http::HeaderName::from_bytes(name.as_bytes()).expect("name"))
                .try_build()
                .expect_err("forbidden identity header"),
            HttpJobError::SensitiveHeader,
            "header {name}"
        );
    }
}

#[test]
fn given_ip_literal_or_numeric_host_when_registering_endpoint_then_rejects() {
    for host in [
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        "[::1]",
        "[fe80::1]",
        "[::ffff:127.0.0.1]",
        "2130706433",
        "0x7f000001",
        "017700000001",
        "127.1",
    ] {
        assert!(
            ApprovedEndpoint::exact(host).is_err(),
            "numeric host must be rejected: {host}"
        );
    }
    let endpoint = ApprovedEndpoint::exact("api.example.com").expect("domain endpoint");
    assert!(!endpoint.matches(&Url::parse("https://127.0.0.1/jobs").expect("URL")));
    assert!(!endpoint.matches(&Url::parse("https://[::1]/jobs").expect("URL")));
}

#[test]
fn given_approved_endpoint_when_debug_is_rendered_then_host_is_redacted() {
    let endpoint = ApprovedEndpoint::exact("private.customer.example").expect("endpoint");
    let id = HttpPolicyId::try_new("debug-redaction").expect("policy ID");
    let policy = HttpPolicy::builder(id)
        .endpoint(endpoint.clone())
        .try_build()
        .expect("policy");

    let rendered = format!("{endpoint:?} {policy:?}");
    assert!(rendered.contains("host_present: true"));
    assert!(!rendered.contains("private.customer.example"));
}

#[test]
fn given_request_body_when_above_global_bound_then_request_is_rejected() {
    let oversized = Bytes::from(vec![0; bg_jobs::MAX_INLINE_PAYLOAD_BYTES + 1]);
    assert_eq!(
        HttpRequest::try_new(request("https://api.example.com/path", oversized))
            .expect_err("oversized request"),
        HttpJobError::RequestBodyTooLarge
    );
    let _ = policy();
}
