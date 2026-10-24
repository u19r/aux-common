#![cfg(feature = "ec2")]

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use buffered_writes::{Deadline, ImdsSpotSource, LifecycleError, SpotActionKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

enum Reply {
    HoldBody {
        status: u16,
        reached: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
    Body(u16, Vec<u8>),
    Hold {
        reached: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    },
}
impl Reply {
    fn text(status: u16, body: &str) -> Self {
        Self::Body(status, body.as_bytes().to_vec())
    }
}
struct MetadataService {
    endpoint: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl MetadataService {
    async fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = requests.clone();
        let task = tokio::spawn(async move {
            let mut replies = VecDeque::from(replies);
            while let Some(reply) = replies.pop_front() {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                loop {
                    let mut chunk = [0; 1024];
                    let count = socket.read(&mut chunk).await.unwrap();
                    if count == 0 {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..count]);
                    if bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                        break;
                    }
                    assert!(bytes.len() < 65536);
                }
                observed
                    .lock()
                    .unwrap()
                    .push(String::from_utf8(bytes).unwrap());
                let (status, body) = match reply {
                    Reply::HoldBody {
                        status,
                        reached,
                        release,
                    } => {
                        socket
                            .write_all(
                                format!(
                                    "HTTP/1.1 {status} Fixture\r\nContent-Length: \
                                     100\r\nConnection: close\r\n\r\nx"
                                )
                                .as_bytes(),
                            )
                            .await
                            .unwrap();
                        reached.notify_one();
                        release.notified().await;
                        continue;
                    }
                    Reply::Body(status, body) => (status, body),
                    Reply::Hold { reached, release } => {
                        reached.notify_one();
                        release.notified().await;
                        (200, b"withheld-token".to_vec())
                    }
                };
                let location = if status == 301 {
                    "Location: http://127.0.0.1:1/redirected\r\n"
                } else {
                    ""
                };
                let headers = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: \
                     close\r\n{location}\r\n",
                    body.len()
                );
                let _ = socket.write_all(headers.as_bytes()).await;
                let _ = socket.write_all(&body).await;
            }
        });
        Self {
            endpoint,
            requests,
            task,
        }
    }
    fn source(&self) -> ImdsSpotSource {
        ImdsSpotSource::try_new_with_endpoint(&self.endpoint).unwrap()
    }
}
impl Drop for MetadataService {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn notice() -> String {
    serde_json::json!({"action":"terminate", "time":(chrono::Utc::now() + chrono::Duration::seconds(60)).to_rfc3339()}).to_string()
}

#[tokio::test]
async fn given_imdsv2_when_polling_repeatedly_then_reuse_token_and_treat_404_as_no_notice() {
    let service = MetadataService::start(vec![
        Reply::text(200, "private-session-token"),
        Reply::text(404, "not found"),
        Reply::text(200, &notice()),
    ])
    .await;
    let source = service.source();
    assert_eq!(
        source.poll_once(Duration::from_secs(2)).await.unwrap(),
        None
    );
    assert_eq!(
        source
            .poll_once(Duration::from_secs(2))
            .await
            .unwrap()
            .unwrap()
            .action,
        SpotActionKind::Terminate
    );
    let requests = service.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[0].starts_with("PUT /latest/api/token "));
    assert!(
        requests[0]
            .to_ascii_lowercase()
            .contains("x-aws-ec2-metadata-token-ttl-seconds: 21600")
    );
    for request in &requests[1..] {
        assert!(request.starts_with("GET /latest/meta-data/spot/instance-action "));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("x-aws-ec2-metadata-token: private-session-token")
        );
    }
    assert!(!format!("{source:?}").contains("private-session-token"));
}

#[tokio::test]
async fn given_rejected_token_when_polling_again_then_refresh_before_get_without_v1_fallback() {
    let service = MetadataService::start(vec![
        Reply::text(200, "token-one"),
        Reply::text(401, "expired"),
        Reply::text(200, "token-two"),
        Reply::text(200, &notice()),
    ])
    .await;
    let source = service.source();
    assert!(matches!(
        source.poll_once(Duration::from_secs(2)).await,
        Err(LifecycleError::SourceUnavailable { .. })
    ));
    assert!(
        source
            .poll_once(Duration::from_secs(2))
            .await
            .unwrap()
            .is_some()
    );
    let requests = service.requests.lock().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[2].starts_with("PUT /latest/api/token "));
    assert!(requests[3].contains("token-two"));
    assert!(!requests[3].contains("token-one"));
}

#[tokio::test]
async fn given_invalid_token_response_when_polling_then_no_get_and_no_backend_bytes_in_error() {
    for reply in [
        Reply::text(403, "PRIVATE-DATA"),
        Reply::text(301, "PRIVATE-DATA"),
        Reply::text(200, "bad\r\nPRIVATE-DATA"),
        Reply::Body(200, vec![b'x'; 8193]),
        Reply::Body(200, vec![0xff]),
    ] {
        let service = MetadataService::start(vec![reply]).await;
        let error = service
            .source()
            .poll_once(Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(error, LifecycleError::SourceUnavailable { .. }));
        assert!(!format!("{error:?} {error}").contains("PRIVATE-DATA"));
        assert_eq!(service.requests.lock().unwrap().len(), 1);
    }
}

#[tokio::test]
async fn given_invalid_or_oversized_notice_when_polled_then_error_and_no_unauthenticated_retry() {
    for reply in [
        Reply::text(500, "PRIVATE-DATA"),
        Reply::text(200, "PRIVATE-DATA"),
        Reply::Body(200, vec![b'x'; 16385]),
        Reply::text(200, r#"{"action":"unknown"}"#),
    ] {
        let service = MetadataService::start(vec![Reply::text(200, "token"), reply]).await;
        let error = service
            .source()
            .poll_once(Duration::from_secs(2))
            .await
            .unwrap_err();
        assert!(matches!(error, LifecycleError::SourceUnavailable { .. }));
        assert!(!format!("{error:?} {error}").contains("PRIVATE-DATA"));
        assert_eq!(service.requests.lock().unwrap().len(), 2);
    }
}

#[tokio::test]
async fn given_cancelled_token_or_action_exchange_when_retried_then_release_lock_and_preserve_valid_cache_only()
 {
    for cancel_token in [true, false] {
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let held = Reply::Hold {
            reached: reached.clone(),
            release: release.clone(),
        };
        let replies = if cancel_token {
            vec![
                held,
                Reply::text(200, "token-two"),
                Reply::text(404, "none"),
            ]
        } else {
            vec![
                Reply::text(200, "token-one"),
                held,
                Reply::text(404, "none"),
            ]
        };
        let service = MetadataService::start(replies).await;
        let source = service.source();
        let polling = source.clone();
        let task = tokio::spawn(async move { polling.poll_once(Duration::from_secs(5)).await });
        tokio::time::timeout(Duration::from_secs(2), reached.notified())
            .await
            .unwrap();
        assert_eq!(
            source.poll_once(Duration::from_millis(10)).await,
            Err(LifecycleError::DeadlineExceeded)
        );
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.notify_one();
        assert_eq!(
            source.poll_once(Duration::from_secs(2)).await.unwrap(),
            None
        );
        let requests = service.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        if cancel_token {
            assert!(requests[1].starts_with("PUT "));
        } else {
            assert!(requests[2].contains("token-one"));
        }
    }
}

#[tokio::test]
async fn given_expired_deadline_when_polling_then_no_network() {
    let service = MetadataService::start(vec![Reply::text(200, "token")]).await;
    assert_eq!(
        service
            .source()
            .poll_once(Deadline::after(Duration::ZERO))
            .await,
        Err(LifecycleError::DeadlineExceeded)
    );
    assert!(service.requests.lock().unwrap().is_empty());
}

#[test]
fn given_non_metadata_endpoint_when_constructing_then_reject_without_network() {
    for endpoint in [
        "https://169.254.169.254",
        "http://example.com",
        "http://localhost:8000",
        "http://10.0.0.1",
        "http://127.0.0.1/path",
        "http://secret@127.0.0.1",
        "http://127.0.0.1?secret",
        "http://127.0.0.1#secret",
    ] {
        assert!(ImdsSpotSource::try_new_with_endpoint(endpoint).is_err());
    }
    assert!(ImdsSpotSource::try_new().is_ok());
    assert!(ImdsSpotSource::try_new_with_endpoint("http://[fd00:ec2::254]").is_ok());
}

#[tokio::test]
async fn given_stalled_response_body_when_deadline_expires_then_retry_releases_cache_lock_and_never_uses_partial_token()
 {
    for token_body in [true, false] {
        let reached = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let held = Reply::HoldBody {
            status: 200,
            reached: reached.clone(),
            release: release.clone(),
        };
        let replies = if token_body {
            vec![
                held,
                Reply::text(200, "complete-token"),
                Reply::text(404, "none"),
            ]
        } else {
            vec![
                Reply::text(200, "complete-token"),
                held,
                Reply::text(404, "none"),
            ]
        };
        let service = MetadataService::start(replies).await;
        let source = service.source();
        assert_eq!(
            source.poll_once(Duration::from_millis(20)).await,
            Err(LifecycleError::DeadlineExceeded)
        );
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .unwrap();
        release.notify_one();
        assert_eq!(
            source.poll_once(Duration::from_secs(2)).await.unwrap(),
            None
        );
        let requests = service.requests.lock().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(requests[2].contains("x-aws-ec2-metadata-token: complete-token"));
    }
}

#[tokio::test]
async fn given_401_or_404_with_stalled_or_oversized_body_when_polling_then_apply_status_before_body()
 {
    for status in [401, 404] {
        for stalled in [false, true] {
            let release = Arc::new(tokio::sync::Notify::new());
            let reply = if stalled {
                Reply::HoldBody {
                    status,
                    reached: Arc::new(tokio::sync::Notify::new()),
                    release: release.clone(),
                }
            } else {
                Reply::Body(status, vec![b'x'; 16385])
            };
            let mut replies = vec![Reply::text(200, "token-one"), reply];
            if status == 401 {
                replies.push(Reply::text(200, "token-two"));
            }
            replies.push(Reply::text(200, &notice()));
            let service = MetadataService::start(replies).await;
            let source = service.source();
            let result = source.poll_once(Duration::from_millis(100)).await;
            release.notify_one();
            if status == 401 {
                assert!(
                    matches!(result, Err(LifecycleError::SourceUnavailable { .. })),
                    "401 invalidation cannot depend on consuming its body: {result:?}"
                );
            } else {
                assert_eq!(
                    result,
                    Ok(None),
                    "404 means no notice immediately after headers"
                );
            }
            assert!(
                source
                    .poll_once(Duration::from_secs(2))
                    .await
                    .unwrap()
                    .is_some()
            );
            let requests = service.requests.lock().unwrap();
            if status == 401 {
                assert_eq!(requests.len(), 4);
                assert!(requests[2].starts_with("PUT /latest/api/token "));
                assert!(requests[3].contains("token-two"));
            } else {
                assert_eq!(requests.len(), 3);
                assert!(requests[2].contains("token-one"));
            }
        }
    }
}
