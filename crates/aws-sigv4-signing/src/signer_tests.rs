use std::time::{Duration, UNIX_EPOCH};

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
    assert!(
        headers
            .get("x-amz-security-token")
            .is_some_and(HeaderValue::is_sensitive)
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
async fn sign_request_matches_aws_s3_lifecycle_golden_vector() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }),
        "s3",
    )
    .expect("signer");
    let uri: Uri = "https://examplebucket.s3.amazonaws.com/?lifecycle"
        .parse()
        .expect("uri");
    let signing_time = UNIX_EPOCH + Duration::from_hours(380_376);

    let headers = signer
        .sign_request_at(
            "GET",
            &uri,
            &HeaderMap::new(),
            SignableBody::Bytes(&[]),
            signing_time,
        )
        .await
        .expect("signed request");

    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(concat!(
            "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ",
            "SignedHeaders=host;x-amz-content-sha256;x-amz-date, ",
            "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"
        ))
    );
}

#[tokio::test]
async fn presign_request_matches_aws_s3_golden_vector() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }),
        "s3",
    )
    .expect("signer");
    let uri: Uri = "https://examplebucket.s3.amazonaws.com/test.txt"
        .parse()
        .expect("uri");
    let signing_time = UNIX_EPOCH + Duration::from_hours(380_376);

    let presigned = signer
        .presign_request_at(
            "GET",
            &uri,
            &HeaderMap::new(),
            SignableBody::UnsignedPayload,
            Duration::from_hours(24),
            signing_time,
        )
        .await
        .expect("presigned request");
    let url = Url::parse(&presigned.to_string()).expect("presigned url");
    let signature = url
        .query_pairs()
        .find_map(|(key, value)| (key == "X-Amz-Signature").then(|| value.into_owned()));

    assert_eq!(
        signature.as_deref(),
        Some("aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404")
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
