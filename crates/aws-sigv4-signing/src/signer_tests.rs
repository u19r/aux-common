use std::time::Duration;

use http::{HeaderMap, HeaderValue, Uri, header::HOST};
use url::Url;

use crate::{AwsRequestSigner, AwsStaticCredentials, CredentialSource, SignableBody};

#[tokio::test]
async fn sign_wrapper_adds_authorization_headers_for_post_requests() {
    let signer = AwsRequestSigner::new(
        "eu-west-2",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: None,
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    let headers = signer
        .sign(&uri, &HeaderMap::new(), br#"{"hello":"world"}"#)
        .await
        .expect("signed request");

    assert_eq!(
        headers.get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
    assert!(headers.contains_key("x-amz-date"));
    assert!(headers.contains_key("x-amz-content-sha256"));
    assert!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
    );
}

#[tokio::test]
async fn sign_request_adds_host_checksum_and_session_token_headers() {
    let signer = AwsRequestSigner::new(
        "eu-west-2",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: Some("session-token".to_string()),
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    let headers = signer
        .sign_request("GET", &uri, &HeaderMap::new(), SignableBody::Bytes(&[]))
        .await
        .expect("signed request");

    assert_eq!(
        headers.get(HOST).and_then(|value| value.to_str().ok()),
        Some("api.example.com")
    );
    assert_eq!(
        headers
            .get("x-amz-security-token")
            .and_then(|value| value.to_str().ok()),
        Some("session-token")
    );
    assert!(headers.contains_key("x-amz-date"));
    assert!(headers.contains_key("x-amz-content-sha256"));
    assert!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("AWS4-HMAC-SHA256 "))
    );
}

#[tokio::test]
async fn sign_request_preserves_explicit_host_header_and_presign_uses_query_params() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: Some("session-token".to_string()),
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers?existing=1"
        .parse()
        .expect("uri");
    let mut base_headers = HeaderMap::new();
    base_headers.insert(HOST, HeaderValue::from_static("override.example.com"));

    let signed_headers = signer
        .sign_request("POST", &uri, &base_headers, SignableBody::Bytes(b"{}"))
        .await
        .expect("signed headers");
    assert_eq!(
        signed_headers
            .get(HOST)
            .and_then(|value| value.to_str().ok()),
        Some("override.example.com")
    );

    let presigned = signer
        .presign_request(
            "GET",
            &uri,
            &base_headers,
            SignableBody::Bytes(&[]),
            Duration::from_mins(2),
        )
        .await
        .expect("presigned uri");
    let presigned_url = Url::parse(&presigned.to_string()).expect("presigned url");
    let query = presigned_url.query_pairs().collect::<Vec<_>>();

    assert!(
        query
            .iter()
            .any(|(key, value)| key == "existing" && value == "1")
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| { key == "X-Amz-Algorithm" && value == "AWS4-HMAC-SHA256" })
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| key == "X-Amz-Security-Token" && value == "session-token")
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| key == "X-Amz-Expires" && value == "120")
    );
    assert!(
        query
            .iter()
            .any(|(key, value)| { key == "X-Amz-SignedHeaders" && value.contains("host") })
    );
    assert!(!query.iter().any(|(key, _)| key == "X-Amz-Content-Sha256"));
}
