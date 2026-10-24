#![cfg(feature = "sqs")]

use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use aws_credentials::{AwsStaticCredentials, CredentialSource};
use buffered_writes::{Deadline, QueueConfig, QueueError, ReplayQueue, SqsQueue};
use bytes::Bytes;
use http_request::{HttpClient, HttpResponse, Transport, TransportFuture, reqwest::Request};

#[derive(Clone, Debug)]
struct ProtocolTransport(Arc<Mutex<Vec<Request>>>, &'static str, http::StatusCode);
impl Default for ProtocolTransport {
    fn default() -> Self {
        Self(
            Arc::default(),
            r#"{"MessageId":"test-message","Messages":[]}"#,
            http::StatusCode::OK,
        )
    }
}

impl Transport for ProtocolTransport {
    fn send(&self, request: Request) -> TransportFuture {
        self.0.lock().unwrap().push(request);
        let body = self.1.as_bytes().to_vec();
        let status = self.2;
        Box::pin(async move {
            Ok(HttpResponse::from_mock(
                status,
                http::HeaderMap::new(),
                body,
                "https://sqs.eu-west-2.amazonaws.com/123456789012/source"
                    .parse()
                    .unwrap(),
            ))
        })
    }
    fn redirects_disabled(&self) -> bool {
        true
    }
}

fn queue(transport: &ProtocolTransport, endpoint: Option<String>) -> SqsQueue {
    let client = HttpClient::builder()
        .with_transport(transport.clone())
        .build()
        .unwrap();
    let mut config = QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
        .with_region("eu-west-2")
        .with_quarantine_url("https://sqs.eu-west-2.amazonaws.com/123456789012/quarantine");
    if let Some(endpoint) = endpoint {
        config = config.with_endpoint(endpoint);
    }
    SqsQueue::try_new_with_client(
        config,
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test-access".into(),
            secret_access_key: "test-secret".into(),
            session_token: None,
        }),
        client,
    )
    .unwrap()
}

#[tokio::test]
async fn given_endpoint_override_when_receiving_then_dispatch_uses_override_and_preserves_queue_url()
 {
    let transport = ProtocolTransport::default();
    queue(&transport, Some("https://queue.test.invalid".into()))
        .receive(1, Deadline::after(Duration::from_secs(2)))
        .await
        .unwrap();
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url().host_str(), Some("queue.test.invalid"));
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(
        body["QueueUrl"],
        "https://sqs.eu-west-2.amazonaws.com/123456789012/source"
    );
}

#[tokio::test]
async fn given_oversized_quarantine_when_publishing_then_reject_without_source_deletion() {
    let transport = ProtocolTransport::default();
    let result = queue(&transport, None)
        .quarantine(
            "source-receipt",
            Bytes::from(vec![b'x'; 1_048_577]),
            "poison",
            Deadline::after(Duration::from_secs(2)),
        )
        .await;
    assert!(
        matches!(result, Err(QueueError::EnvelopeTooLarge { .. })),
        "{result:?}"
    );
    assert!(transport.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn given_invalid_quarantine_utf8_when_publishing_then_reject_without_lossy_conversion() {
    let transport = ProtocolTransport::default();
    let result = queue(&transport, None)
        .quarantine(
            "source-receipt",
            Bytes::from_static(&[0xff]),
            "poison",
            Deadline::after(Duration::from_secs(2)),
        )
        .await;
    assert!(
        matches!(result, Err(QueueError::Permanent { .. })),
        "{result:?}"
    );
    assert!(transport.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn given_lost_quarantine_ack_when_publishing_then_source_is_not_deleted() {
    let transport = ProtocolTransport(Arc::default(), "invalid JSON", http::StatusCode::OK);
    let result = queue(&transport, None)
        .quarantine(
            "source-receipt",
            Bytes::from_static(b"{}"),
            "poison",
            Deadline::after(Duration::from_secs(2)),
        )
        .await;
    assert_eq!(result, Err(QueueError::AmbiguousPublish));
    assert_eq!(transport.0.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn given_current_service_limit_when_quarantining_then_body_limit_excludes_json_request_escaping()
 {
    let transport = ProtocolTransport::default();
    let queue = queue(&transport, None);
    assert_eq!(
        buffered_writes::WriteQueue::limits(&queue).max_envelope_bytes(),
        1_048_576
    );
    queue
        .quarantine(
            "source-receipt",
            Bytes::from(vec![b'"'; 1_048_576]),
            "poison",
            Deadline::after(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].body().unwrap().as_bytes().unwrap().len() > 1_048_576);
    assert_eq!(
        requests[1].headers()["x-amz-target"],
        "AmazonSQS.DeleteMessage"
    );
}

#[tokio::test]
async fn given_visibility_outside_service_range_when_renewing_then_no_dispatch() {
    let transport = ProtocolTransport::default();
    let queue = queue(&transport, None);
    for duration in [Duration::ZERO, Duration::from_secs(43_201), Duration::MAX] {
        assert!(matches!(
            queue
                .renew_visibility("receipt", duration, Deadline::after(Duration::from_secs(2)))
                .await,
            Err(QueueError::Permanent { .. })
        ));
    }
    assert!(transport.0.lock().unwrap().is_empty());
    queue
        .renew_visibility(
            "receipt",
            Duration::from_millis(1500),
            Deadline::after(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    let requests = transport.0.lock().unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(body["VisibilityTimeout"], 2);
}

#[derive(Debug, Default)]
struct HungTransport(Arc<std::sync::atomic::AtomicUsize>);
impl Transport for HungTransport {
    fn send(&self, _: Request) -> TransportFuture {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(std::future::pending())
    }
    fn redirects_disabled(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn given_hung_transport_when_receiving_then_total_deadline_bounds_operation() {
    let client = HttpClient::builder()
        .with_transport(HungTransport::default())
        .build()
        .unwrap();
    let queue = SqsQueue::try_new_with_client(
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source"),
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }),
        client,
    )
    .unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        queue.receive(1, Deadline::after(Duration::from_millis(10))),
    )
    .await
    .expect("caller deadline must win");
    assert_eq!(result, Err(QueueError::DeadlineExceeded));
}

#[test]
fn given_invalid_transport_configuration_when_building_then_reject_before_dispatch() {
    for config in [
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
            .with_fifo_group_id("group"),
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source.fifo")
            .with_fifo_group_id(""),
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source.fifo")
            .with_fifo_group_id("a".repeat(129)),
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
            .with_quarantine_url("https://sqs.eu-west-2.amazonaws.com/123456789012/source"),
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
            .with_endpoint("https://secret@queue.invalid"),
    ] {
        assert!(SqsQueue::try_new(config).is_err());
    }
}

#[tokio::test]
async fn given_smaller_queue_limit_when_quarantining_then_reject_without_dispatch() {
    let transport = ProtocolTransport::default();
    let queue = SqsQueue::try_new_with_client(
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
            .with_quarantine_url("https://sqs.eu-west-2.amazonaws.com/123456789012/quarantine")
            .with_max_envelope_bytes(8),
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }),
        HttpClient::builder()
            .with_transport(transport.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        queue
            .quarantine(
                "receipt",
                Bytes::from_static(b"123456789"),
                "poison",
                Deadline::after(Duration::from_secs(2))
            )
            .await,
        Err(QueueError::EnvelopeTooLarge { size: 9, limit: 8 })
    );
    assert!(transport.0.lock().unwrap().is_empty());
    for limit in [0, 1_048_577] {
        assert!(
            SqsQueue::try_new(
                QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
                    .with_max_envelope_bytes(limit)
            )
            .is_err()
        );
    }
}

#[test]
fn given_transparent_post_retries_when_building_then_reject_second_attempt_owner() {
    let transport = ProtocolTransport::default();
    let client = HttpClient::builder()
        .with_transport(transport.clone())
        .retry(http_request::RetryConfig {
            max_retries: 1,
            retry_non_idempotent: true,
            base_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        })
        .build()
        .unwrap();
    assert!(
        SqsQueue::try_new_with_client(
            QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source"),
            CredentialSource::DefaultChain,
            client
        )
        .is_err()
    );
    assert!(transport.0.lock().unwrap().is_empty());
}

async fn capture_batch() -> buffered_writes::SealedBatch {
    let captured = Arc::new(Mutex::new(None));
    let observed = captured.clone();
    let sink = buffered_writes::AtomicSink::try_new(
        buffered_writes::SinkLimits::default(),
        move |attempt: buffered_writes::WriteAttempt<u32>| {
            *observed.lock().unwrap() = Some(attempt.sealed_batch().clone());
            async { Ok::<(), buffered_writes::SinkError>(()) }
        },
    )
    .unwrap();
    let writer = buffered_writes::BufferedWrites::builder("sqs-protocol/v1", sink)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    writer.flush_writes().await;
    captured.lock().unwrap().take().unwrap()
}

#[tokio::test]
async fn given_fifo_transport_when_retrying_then_batch_identity_and_bounded_group_are_stable() {
    let transport = ProtocolTransport::default();
    let queue = SqsQueue::try_new_with_client(
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source.fifo")
            .with_quarantine_url(
                "https://sqs.eu-west-2.amazonaws.com/123456789012/quarantine.fifo",
            ),
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }),
        HttpClient::builder()
            .with_transport(transport.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    let batch = capture_batch().await;
    let expected_id = batch.batch_id().to_string();
    let deadline = Deadline::after(Duration::from_secs(2));
    buffered_writes::WriteQueue::publish(&queue, batch.clone(), deadline)
        .await
        .unwrap();
    buffered_writes::WriteQueue::publish(&queue, batch, deadline)
        .await
        .unwrap();
    queue
        .quarantine(
            "source-receipt",
            Bytes::from_static(b"{}"),
            "poison",
            deadline,
        )
        .await
        .unwrap();
    let requests = transport.0.lock().unwrap();
    let bodies: Vec<serde_json::Value> = requests
        .iter()
        .map(|request| serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap())
        .collect();
    assert_eq!(bodies[0], bodies[1]);
    assert_eq!(bodies[0]["MessageDeduplicationId"], expected_id);
    assert_eq!(bodies[0]["MessageGroupId"].as_str().unwrap().len(), 64);
    assert_eq!(bodies[2]["MessageGroupId"], "quarantine");
    assert_eq!(
        bodies[2]["MessageDeduplicationId"].as_str().unwrap().len(),
        64
    );
    assert_eq!(
        requests[3].headers()["x-amz-target"],
        "AmazonSQS.DeleteMessage"
    );
}

#[tokio::test]
async fn given_invalid_receive_response_when_receiving_then_reject_without_delivering_or_deleting()
{
    for response in [
        r#"{"Messages":[{"MessageId":"","ReceiptHandle":"handle","Body":"{}"}]}"#,
        r#"{"Messages":[{"MessageId":"id","ReceiptHandle":"","Body":"{}"}]}"#,
        r#"{"Messages":[{"MessageId":"one","ReceiptHandle":"one","Body":"{}"},{"MessageId":"two","ReceiptHandle":"two","Body":"{}"}]}"#,
    ] {
        let transport = ProtocolTransport(Arc::default(), response, http::StatusCode::OK);
        let result = queue(&transport, None)
            .receive(1, Deadline::after(Duration::from_secs(2)))
            .await;
        assert!(
            matches!(result, Err(QueueError::Unavailable { .. })),
            "{result:?}"
        );
        assert_eq!(transport.0.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn given_cross_region_quarantine_when_publishing_then_sign_each_queue_for_its_region() {
    let transport = ProtocolTransport::default();
    let queue = SqsQueue::try_new_with_client(
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
            .with_quarantine_url("https://sqs.eu-central-1.amazonaws.com/123456789012/quarantine"),
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }),
        HttpClient::builder()
            .with_transport(transport.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    queue
        .quarantine(
            "receipt",
            Bytes::from_static(b"{}"),
            "poison",
            Deadline::after(Duration::from_secs(2)),
        )
        .await
        .unwrap();
    let requests = transport.0.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(
        requests[0].headers()["authorization"]
            .to_str()
            .unwrap()
            .contains("/eu-central-1/sqs/aws4_request")
    );
    assert!(
        requests[1].headers()["authorization"]
            .to_str()
            .unwrap()
            .contains("/eu-west-2/sqs/aws4_request")
    );
}

#[tokio::test]
async fn given_service_error_when_receiving_then_classification_is_typed_and_redacted_without_retry()
 {
    for (status, body, expected) in [
        (
            400,
            r#"{"__type":"com.amazonaws.sqs#RequestThrottled","message":"PRIVATE-DATA"}"#,
            QueueError::Unavailable {
                reason: "SQS throttled request",
            },
        ),
        (
            400,
            r#"{"__type":"ReceiptHandleIsInvalid","message":"PRIVATE-DATA"}"#,
            QueueError::InvalidReceipt,
        ),
        (
            403,
            r#"{"__type":"AccessDeniedException","message":"PRIVATE-DATA"}"#,
            QueueError::Permanent {
                reason: "SQS rejected request",
            },
        ),
        (
            503,
            "PRIVATE-DATA",
            QueueError::Unavailable {
                reason: "SQS returned retryable status",
            },
        ),
    ] {
        let transport = ProtocolTransport(
            Arc::default(),
            body,
            http::StatusCode::from_u16(status).unwrap(),
        );
        let error = queue(&transport, None)
            .receive(1, Deadline::after(Duration::from_secs(2)))
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains("PRIVATE-DATA"));
        assert_eq!(transport.0.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn given_unknown_publication_when_deadline_expires_then_do_not_delete_source() {
    let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let client = HttpClient::builder()
        .with_transport(HungTransport(requests.clone()))
        .build()
        .unwrap();
    let queue = SqsQueue::try_new_with_client(
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source")
            .with_quarantine_url("https://sqs.eu-west-2.amazonaws.com/123456789012/quarantine"),
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }),
        client,
    )
    .unwrap();
    let result = queue
        .quarantine(
            "receipt",
            Bytes::from_static(b"{}"),
            "poison",
            Deadline::after(Duration::from_millis(10)),
        )
        .await;
    assert_eq!(result, Err(QueueError::AmbiguousPublish));
    assert_eq!(requests.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[tokio::test]
async fn given_zero_receive_budget_when_receiving_then_do_not_lease_or_dispatch() {
    let transport = ProtocolTransport::default();
    assert!(
        queue(&transport, None)
            .receive(0, Deadline::after(Duration::from_secs(2)))
            .await
            .unwrap()
            .is_empty()
    );
    assert!(transport.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn given_transient_queue_response_when_retrying_then_keep_unknown_publications_and_capacity_pressure_retryable()
 {
    for (status, body) in [
        (400, r#"{"__type":"OverLimit"}"#),
        (408, "timeout"),
        (423, "locked"),
        (425, "too early"),
    ] {
        let transport = ProtocolTransport(
            Arc::default(),
            body,
            http::StatusCode::from_u16(status).unwrap(),
        );
        assert!(matches!(
            queue(&transport, None)
                .receive(1, Deadline::after(Duration::from_secs(2)))
                .await,
            Err(QueueError::Unavailable { .. })
        ));
        assert_eq!(
            queue(&transport, None)
                .quarantine(
                    "receipt",
                    Bytes::from_static(b"{}"),
                    "poison",
                    Deadline::after(Duration::from_secs(2))
                )
                .await,
            Err(QueueError::AmbiguousPublish)
        );
        assert_eq!(transport.0.lock().unwrap().len(), 2);
    }
}

#[derive(Clone, Debug, Default)]
struct HoldAcceptedResponse {
    requests: Arc<Mutex<Vec<Request>>>,
    accepted: Arc<tokio::sync::Notify>,
}
impl Transport for HoldAcceptedResponse {
    fn send(&self, request: Request) -> TransportFuture {
        let first = {
            let mut requests = self.requests.lock().unwrap();
            requests.push(request);
            requests.len() == 1
        };
        let accepted = self.accepted.clone();
        Box::pin(async move {
            if first {
                accepted.notify_one();
                return std::future::pending().await;
            }
            Ok(HttpResponse::from_mock(
                http::StatusCode::OK,
                http::HeaderMap::new(),
                br#"{"MessageId":"accepted-retry"}"#.to_vec(),
                "https://sqs.eu-west-2.amazonaws.com/123456789012/source"
                    .parse()
                    .unwrap(),
            ))
        })
    }
    fn redirects_disabled(&self) -> bool {
        true
    }
}

#[tokio::test]
async fn given_accepted_sqs_dispatch_when_flush_is_aborted_then_retained_batch_retries_with_identical_identity_and_bytes()
 {
    use buffered_writes::{
        AtomicSink, BufferedWrites, Clock, MemoryBuffer, SinkError, SinkLimits, TestClock,
        WriteAttempt, WriteBuffer,
    };
    let transport = HoldAcceptedResponse::default();
    let queue = SqsQueue::try_new_with_client(
        QueueConfig::sqs("https://sqs.eu-west-2.amazonaws.com/123456789012/source"),
        CredentialSource::Static(AwsStaticCredentials {
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        }),
        HttpClient::builder()
            .with_transport(transport.clone())
            .build()
            .unwrap(),
    )
    .unwrap();
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Err::<(), _>(SinkError::retryable("outage"))
    })
    .unwrap();
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let buffer = MemoryBuffer::new("cancel-sqs/v1".try_into().unwrap());
    let writer = BufferedWrites::builder("cancel-sqs/v1", sink)
        .with_clock(clock.clone())
        .with_buffer_provider(buffer.clone())
        .fallback(QueueConfig::custom(queue))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    let flushing = writer.clone();
    let task = tokio::spawn(async move { flushing.flush_writes().await });
    tokio::time::timeout(Duration::from_secs(2), transport.accepted.notified())
        .await
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let snapshot = buffer
        .inspect(buffered_writes::BufferInspectRequest {
            operation_id: None,
            now_utc_ms: clock.now_utc().timestamp_millis(),
            now_instant: clock.now_instant(),
            deadline: Deadline::after(Duration::from_secs(2)),
        })
        .await
        .unwrap();
    assert_eq!(snapshot.unsettled_items, 1);
    assert_eq!(snapshot.unresolved_batch_ids.len(), 1);
    clock.advance(Duration::from_secs(6));
    assert_eq!(writer.flush_writes().await.batches_queued, 1);
    let requests = transport.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    let bodies: Vec<serde_json::Value> = requests
        .iter()
        .map(|request| serde_json::from_slice(request.body().unwrap().as_bytes().unwrap()).unwrap())
        .collect();
    assert_eq!(bodies[0]["MessageBody"], bodies[1]["MessageBody"]);
    let original = buffered_writes::SealedBatch::from_envelope_bytes(
        bodies[0]["MessageBody"].as_str().unwrap().as_bytes(),
    )
    .unwrap();
    assert_eq!(original.batch_id(), snapshot.unresolved_batch_ids[0]);
}

#[tokio::test]
async fn given_queue_url_when_using_json_protocol_then_post_to_service_root_and_keep_queue_identity_in_body()
 {
    let transport = ProtocolTransport::default();
    queue(&transport, None)
        .receive(1, Deadline::after(Duration::from_secs(2)))
        .await
        .unwrap();
    let requests = transport.0.lock().unwrap();
    assert_eq!(
        requests[0].url().path(),
        "/",
        "AWS JSON protocol posts to the service root"
    );
    let body: serde_json::Value =
        serde_json::from_slice(requests[0].body().unwrap().as_bytes().unwrap()).unwrap();
    assert_eq!(
        body["QueueUrl"],
        "https://sqs.eu-west-2.amazonaws.com/123456789012/source"
    );
}
