use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use aws_credentials::AwsStaticCredentials;
use aws_sigv4_signing::AwsRequestSigner;
use http::{
    HeaderMap, HeaderValue, Method, StatusCode,
    header::{CONTENT_LENGTH, IF_NONE_MATCH},
};
use http_request::{
    HttpClient, HttpRequestError, HttpResponse, RetryConfig, Transport, TransportFuture, Url,
};

use crate::{
    CredentialSource, S3_SOURCE_IDENTITY_HEADER, S3ObjectInput, S3ObjectPublication,
    S3ObjectPublisher, S3PublicationError,
};

type Responses = VecDeque<Result<HttpResponse, HttpRequestError>>;

#[derive(Clone)]
struct PublicationTransport {
    responses: Arc<Mutex<Responses>>,
    requests: Arc<Mutex<Vec<http_request::reqwest::Request>>>,
}

impl std::fmt::Debug for PublicationTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PublicationTransport")
    }
}

impl Transport for PublicationTransport {
    fn send(&self, request: http_request::reqwest::Request) -> TransportFuture {
        self.requests.lock().unwrap().push(request);
        let response = self
            .responses
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted response");
        Box::pin(async move { response })
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

fn input() -> S3ObjectInput {
    S3ObjectInput {
        url: Url::parse("https://bucket.example.test/object").unwrap(),
        source_identity: "sealed-source-1".to_owned(),
        content_length: 3,
        content_type: "application/json".to_owned(),
        content_encoding: Some("gzip".to_owned()),
    }
}

fn response(
    status: StatusCode,
    identity: Option<&str>,
    bytes: u64,
) -> Result<HttpResponse, HttpRequestError> {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_LENGTH, HeaderValue::from(bytes));
    if let Some(identity) = identity {
        headers.insert(
            S3_SOURCE_IDENTITY_HEADER,
            HeaderValue::from_str(identity).unwrap(),
        );
    }
    Ok(HttpResponse::from_mock(
        status,
        headers,
        Vec::new(),
        input().url,
    ))
}

fn fixture(responses: Responses) -> (HttpClient, AwsRequestSigner, PublicationTransport) {
    let transport = PublicationTransport {
        responses: Arc::new(Mutex::new(responses)),
        requests: Arc::default(),
    };
    let client = HttpClient::builder()
        .retry(RetryConfig {
            max_retries: 0,
            ..Default::default()
        })
        .with_transport(transport.clone())
        .build()
        .unwrap();
    let signer = AwsRequestSigner::new(
        "eu-west-1",
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test-secret".into(),
            session_token: None,
        }),
        "s3",
    )
    .unwrap();
    (client, signer, transport)
}

#[tokio::test]
async fn given_a_lost_put_response_when_publication_retries_then_head_reconciles_without_a_second_put()
 {
    let (client, signer, transport) = fixture(VecDeque::from([
        response(StatusCode::NOT_FOUND, None, 0),
        Err(HttpRequestError::HttpStatus {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: None,
        }),
        response(StatusCode::OK, Some("sealed-source-1"), 3),
    ]));
    let object = S3ObjectPublication::try_from(input()).unwrap();
    let publisher = S3ObjectPublisher::new(&client, &signer);
    assert_eq!(
        publisher.publish(&object, "abc".into()).await,
        Err(S3PublicationError::RequestFailed)
    );
    publisher.publish(&object, "abc".into()).await.unwrap();
    let requests = transport.requests.lock().unwrap();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.method().clone())
            .collect::<Vec<_>>(),
        [Method::HEAD, Method::PUT, Method::HEAD]
    );
    assert_eq!(requests[1].headers().get(IF_NONE_MATCH).unwrap(), "*");
    assert_eq!(
        requests[1]
            .headers()
            .get(S3_SOURCE_IDENTITY_HEADER)
            .unwrap(),
        "sealed-source-1"
    );
    assert!(requests[1].headers().contains_key("authorization"));
}

#[tokio::test]
async fn given_a_competing_conditional_put_when_the_same_source_wins_then_publication_reconciles() {
    for status in [StatusCode::PRECONDITION_FAILED, StatusCode::CONFLICT] {
        let (client, signer, transport) = fixture(VecDeque::from([
            response(StatusCode::NOT_FOUND, None, 0),
            response(status, None, 0),
            response(StatusCode::OK, Some("sealed-source-1"), 3),
        ]));
        S3ObjectPublisher::new(&client, &signer)
            .publish(
                &S3ObjectPublication::try_from(input()).unwrap(),
                "abc".into(),
            )
            .await
            .unwrap();
        assert_eq!(transport.requests.lock().unwrap().len(), 3);
    }
}

#[tokio::test]
async fn given_an_existing_different_source_or_size_when_publication_runs_then_it_rejects_without_overwriting()
 {
    for (identity, bytes) in [
        (Some("another-source"), 3),
        (Some("sealed-source-1"), 2),
        (None, 3),
    ] {
        let (client, signer, transport) =
            fixture(VecDeque::from([response(StatusCode::OK, identity, bytes)]));
        let result = S3ObjectPublisher::new(&client, &signer)
            .publish(
                &S3ObjectPublication::try_from(input()).unwrap(),
                "abc".into(),
            )
            .await;
        assert_eq!(result, Err(S3PublicationError::IdentityMismatch));
        assert_eq!(transport.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn given_a_missing_object_when_conditional_publication_succeeds_then_one_signed_put_is_sent()
{
    let (client, signer, transport) = fixture(VecDeque::from([
        response(StatusCode::NOT_FOUND, None, 0),
        response(StatusCode::OK, None, 0),
    ]));
    S3ObjectPublisher::new(&client, &signer)
        .publish(
            &S3ObjectPublication::try_from(input()).unwrap(),
            "abc".into(),
        )
        .await
        .unwrap();
    assert_eq!(transport.requests.lock().unwrap().len(), 2);
}
