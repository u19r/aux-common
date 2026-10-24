use std::{
    future::Future,
    pin::Pin,
    time::{Duration, UNIX_EPOCH},
};

use aws_credentials::{
    Credentials, CredentialsError, ProvideCredentials, SharedCredentialsProvider,
};
use http::{HeaderMap, HeaderValue, Uri, header::HOST};
use url::Url;

use crate::{AwsRequestSigner, AwsStaticCredentials, CredentialSource, SignableBody, SigningError};

#[derive(Debug)]
struct UnavailableCredentials;

impl ProvideCredentials for UnavailableCredentials {
    fn provide_credentials(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<Credentials, CredentialsError>> + Send + '_>> {
        Box::pin(std::future::ready(Err(
            CredentialsError::not_loaded_no_source(),
        )))
    }
}

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
async fn given_a_custom_unavailable_provider_when_signing_then_it_is_used_without_fallback() {
    let signer = AwsRequestSigner::new_with_provider(
        "eu-west-2",
        SharedCredentialsProvider::new(UnavailableCredentials),
        "execute-api",
    );
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    let error = signer
        .sign(&uri, &HeaderMap::new(), b"payload")
        .await
        .expect_err("custom unavailable provider must be used");

    assert!(matches!(error, SigningError::Credentials(_)));
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

#[tokio::test]
async fn given_subsecond_presign_expiry_when_presigning_then_rejects_request() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: None,
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    for expiry in [
        Duration::ZERO,
        Duration::from_nanos(1),
        Duration::from_millis(999),
    ] {
        let error = signer
            .presign_request(
                "GET",
                &uri,
                &HeaderMap::new(),
                SignableBody::Bytes(&[]),
                expiry,
            )
            .await
            .expect_err("subsecond expiry must be rejected");

        assert!(matches!(error, crate::SigningError::InvalidPresignExpiry));
    }
}

#[tokio::test]
async fn given_expiry_over_seven_days_when_presigning_then_rejects_request() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "very-secret".to_string(),
            session_token: None,
        }),
        "execute-api",
    )
    .expect("signer");
    let uri: Uri = "https://api.example.com/customers".parse().expect("uri");

    let error = signer
        .presign_request(
            "GET",
            &uri,
            &HeaderMap::new(),
            SignableBody::Bytes(&[]),
            Duration::from_secs(604_801),
        )
        .await
        .expect_err("expiry above AWS limit must be rejected");

    assert!(matches!(error, crate::SigningError::InvalidPresignExpiry));
}

#[derive(Clone, Copy)]
struct ReferenceRequest<'a> {
    method: &'a str,
    uri: &'a Uri,
    headers: &'a HeaderMap,
    body: &'a SignableBody<'a>,
}

fn reference_signature(
    request: ReferenceRequest<'_>,
    credentials: &AwsStaticCredentials,
    service: &str,
    expiry: Option<Duration>,
) -> String {
    use aws_sigv4::{
        http_request::{
            PayloadChecksumKind, PercentEncodingMode, SignableRequest, SignatureLocation,
            SigningParams, SigningSettings, UriPathNormalizationMode, sign,
        },
        sign::v4,
    };
    let credentials = aws_credential_types::Credentials::new(
        &credentials.access_key_id,
        &credentials.secret_access_key,
        credentials.session_token.clone(),
        None,
        "reference",
    );
    let identity = aws_smithy_runtime_api::client::identity::Identity::new(credentials, None);
    let mut settings = SigningSettings::default();
    settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
    if service == "s3" {
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    }
    if let Some(expiry) = expiry {
        settings.payload_checksum_kind = PayloadChecksumKind::NoHeader;
        settings.signature_location = SignatureLocation::QueryParams;
        settings.expires_in = Some(expiry);
    }
    let params: SigningParams = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name(service)
        .time(reference_time())
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let body = reference_body(request.body);
    let signable = SignableRequest::new(
        request.method,
        request.uri.to_string(),
        request
            .headers
            .iter()
            .map(|(key, value)| (key.as_str(), value.to_str().unwrap())),
        body,
    )
    .unwrap();
    let (instructions, _) = sign(signable, &params).unwrap().into_parts();
    match expiry {
        Some(_) => instructions
            .params()
            .iter()
            .find(|(key, _)| *key == "X-Amz-Signature")
            .unwrap()
            .1
            .to_string(),
        None => instructions
            .headers()
            .find(|(key, _)| *key == "authorization")
            .unwrap()
            .1
            .to_owned(),
    }
}

fn reference_time() -> std::time::SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn reference_body<'a>(body: &'a SignableBody<'a>) -> aws_sigv4::http_request::SignableBody<'a> {
    use aws_sigv4::http_request::SignableBody as Reference;
    match body {
        SignableBody::Bytes(bytes) => Reference::Bytes(bytes),
        SignableBody::UnsignedPayload => Reference::UnsignedPayload,
        SignableBody::Precomputed(hash) => Reference::Precomputed(hash.clone()),
        SignableBody::StreamingUnsignedPayloadTrailer => Reference::StreamingUnsignedPayloadTrailer,
        SignableBody::StreamingSignedPayloadTrailer => Reference::StreamingSignedPayloadTrailer,
    }
}

#[tokio::test]
async fn given_protocol_cases_when_signing_then_match_test_only_aws_reference() {
    let bodies = [
        SignableBody::Bytes(b"\0\xff\nbody"),
        SignableBody::UnsignedPayload,
        SignableBody::Precomputed("0".repeat(64)),
        SignableBody::StreamingUnsignedPayloadTrailer,
        SignableBody::StreamingSignedPayloadTrailer,
    ];
    for session in [None, Some("session/token+with=reserved&chars".to_owned())] {
        let credentials = AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "reference-secret".to_owned(),
            session_token: session,
        };
        for (service, url, method) in reference_cases() {
            let signer = AwsRequestSigner::new(
                "us-east-1",
                CredentialSource::Static(credentials.clone()),
                service,
            )
            .unwrap();
            let uri: Uri = url.parse().unwrap();
            let mut headers = HeaderMap::new();
            headers.append("x-example", HeaderValue::from_static("  a   b  "));
            headers.append("x-example", HeaderValue::from_static("c"));
            headers.insert("content-type", HeaderValue::from_static("application/json"));
            headers.insert("user-agent", HeaderValue::from_static("excluded"));
            headers.insert("x-tab", HeaderValue::from_static(" \ta\t\tb \t "));
            for body in &bodies {
                let expected = reference_signature(
                    ReferenceRequest {
                        method,
                        uri: &uri,
                        headers: &headers,
                        body,
                    },
                    &credentials,
                    service,
                    None,
                );
                let headers_result = signer
                    .sign_request_at(method, &uri, &headers, body.clone(), reference_time())
                    .await
                    .unwrap();
                assert_eq!(
                    headers_result["authorization"].to_str().unwrap(),
                    expected,
                    "{service} {url} {body:?}"
                );
                let expiry = Duration::from_mins(2);
                let expected = reference_signature(
                    ReferenceRequest {
                        method,
                        uri: &uri,
                        headers: &headers,
                        body,
                    },
                    &credentials,
                    service,
                    Some(expiry),
                );
                let presigned = signer
                    .presign_request_at(
                        method,
                        &uri,
                        &headers,
                        body.clone(),
                        expiry,
                        reference_time(),
                    )
                    .await
                    .unwrap();
                let url = Url::parse(&presigned.to_string()).unwrap();
                let actual = url
                    .query_pairs()
                    .find(|(key, _)| key == "X-Amz-Signature")
                    .unwrap()
                    .1
                    .into_owned();
                assert_eq!(actual, expected, "{service} {url} {body:?}");
            }
        }
    }
}

fn reference_cases() -> [(&'static str, &'static str, &'static str); 11] {
    [
        ("execute-api", "https://api.example.com/", "GET"),
        (
            "execute-api",
            "https://api.example.com/a:b/@p!$&'()*+,;=[]?x=:/@!$&y=2",
            "POST",
        ),
        (
            "dynamodb",
            "https://dynamodb.us-east-1.amazonaws.com/",
            "POST",
        ),
        (
            "sqs",
            "https://sqs.us-east-1.amazonaws.com/123/queue?Action=SendMessage",
            "POST",
        ),
        (
            "execute-api",
            "https://api.example.com/a/../b//c/./?z=9&x=2&x=1&empty=&acl",
            "PUT",
        ),
        (
            "execute-api",
            "https://api.example.com/a%2Fb/%E2%98%83?space=hello+world&literal=%2B&u=%E2%98%83",
            "GET",
        ),
        (
            "execute-api",
            "https://api.example.com:443/a/?encoded=%2f&x=%26%3D",
            "HEAD",
        ),
        (
            "execute-api",
            "https://api.example.com:8443/a/?missing&=value&&x=",
            "DELETE",
        ),
        (
            "s3",
            "https://bucket.s3.amazonaws.com/a//b/../%E2%98%83%20%2B?versionId=a%2Fb&acl",
            "GET",
        ),
        (
            "s3",
            "https://bucket.s3.amazonaws.com/a%2fb%2520c?tagging",
            "PUT",
        ),
        ("execute-api", "https://[::1]:8443/a?x=y", "POST"),
    ]
}

#[tokio::test]
async fn given_existing_query_when_presigned_then_preserve_original_path_and_query() {
    let signer = AwsRequestSigner::new(
        "us-east-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "example-secret".to_owned(),
            session_token: None,
        }),
        "execute-api",
    )
    .unwrap();
    let original = "/a%2fb/../c?z=9&x=2&x=1&encoded=%2f&literal=%2B&empty&=value&&";
    let uri: Uri = format!("https://api.example.com{original}")
        .parse()
        .unwrap();
    let presigned = signer
        .presign_request_at(
            "GET",
            &uri,
            &HeaderMap::new(),
            SignableBody::Bytes(b""),
            Duration::from_mins(2),
            reference_time(),
        )
        .await
        .unwrap();
    let emitted = presigned.path_and_query().unwrap().as_str();
    assert!(
        emitted.starts_with(&format!("{original}&X-Amz-Algorithm=")),
        "{emitted}"
    );
    assert!(emitted.contains("&X-Amz-Signature="));
}
