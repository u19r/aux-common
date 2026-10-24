#![cfg(feature = "lambda")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferedWrites, LambdaExtensionClient, LambdaExtensionServer, LambdaInvocation,
    LambdaIpcConfig, LifecycleError, RecordingWriteObserver, SinkError, SinkLimits, TestClock,
    WriteAttempt, WriteEvent,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn request(listener: &TcpListener) -> (TcpStream, String) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0; 1024];
        let count = stream.read(&mut chunk).await.unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() < 8192);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            let headers = String::from_utf8_lossy(&bytes[..end]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|value| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if bytes.len() >= end + 4 + length {
                break;
            }
        }
    }
    (stream, String::from_utf8(bytes).unwrap())
}
async fn reply(stream: &mut TcpStream, status: u16, headers: &str, body: &[u8]) {
    let headers = format!(
        "Lambda-Extension-Event-Identifier: {}\r\n{headers}",
        uuid::Uuid::now_v7()
    );
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: \
                 close\r\n{headers}\r\n",
                body.len()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    stream.write_all(body).await.unwrap();
}
async fn register(listener: &TcpListener) {
    let (mut stream, text) = request(listener).await;
    assert!(text.starts_with("POST /2020-01-01/extension/register "));
    assert!(
        text.to_ascii_lowercase()
            .contains("lambda-extension-name: test-extension")
    );
    let body: serde_json::Value =
        serde_json::from_str(text.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body, serde_json::json!({"events":["INVOKE","SHUTDOWN"]}));
    reply(
        &mut stream,
        200,
        "Lambda-Extension-Identifier: private-extension-id\r\n",
        b"{}",
    )
    .await;
}
async fn next(listener: &TcpListener) -> TcpStream {
    let (stream, text) = request(listener).await;
    assert!(text.starts_with("GET /2020-01-01/extension/event/next "));
    assert!(
        text.to_ascii_lowercase()
            .contains("lambda-extension-identifier: private-extension-id")
    );
    stream
}
fn deadline_ms(after: Duration) -> u64 {
    u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap()
        + u64::try_from(after.as_millis()).unwrap()
}
async fn invoke(stream: &mut TcpStream, id: &str, budget: Duration) {
    reply(
        stream,
        200,
        "",
        serde_json::json!({"eventType":"INVOKE", "deadlineMs":deadline_ms(budget), "requestId":id})
            .to_string()
            .as_bytes(),
    )
    .await;
}
async fn shutdown(stream: &mut TcpStream, reason: &str) {
    reply(stream, 200, "", serde_json::json!({"eventType":"SHUTDOWN", "deadlineMs":deadline_ms(Duration::from_secs(1)), "shutdownReason":reason}).to_string().as_bytes()).await;
}
async fn bind(writer: BufferedWrites<u32>) -> LambdaExtensionServer<u32> {
    LambdaExtensionServer::bind(
        writer,
        LambdaIpcConfig::try_new("127.0.0.1:0".parse().unwrap(), "test-token").unwrap(),
    )
    .await
    .unwrap()
}
fn runtime(server: &LambdaExtensionServer<u32>) -> LambdaExtensionClient<u32> {
    LambdaExtensionClient::new(
        LambdaIpcConfig::try_new(server.local_addr().unwrap(), "test-token").unwrap(),
    )
}

async fn client(
    server: &LambdaExtensionServer<u32>,
    id: &str,
    attempt: &str,
) -> LambdaInvocation<u32> {
    runtime(server).begin_invocation(id, attempt).await.unwrap()
}
#[tokio::test]
async fn given_classic_provider_when_invocations_complete_then_next_follows_flush_and_shutdown_drains_young_writes()
 {
    let finished = Arc::new(AtomicUsize::new(0));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let observed = finished.clone();
    let reached = entered.clone();
    let allowed = release.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let finished = observed.clone();
        let entered = reached.clone();
        let release = allowed.clone();
        async move {
            if attempt.items().contains(&2) {
                entered.notify_one();
                release.notified().await;
            }
            finished.fetch_add(attempt.items().len(), Ordering::SeqCst);
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let writer = BufferedWrites::builder("lambda-provider/v1", sink)
        .with_clock(clock.clone())
        .build()
        .unwrap();
    let server = bind(writer).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let invoked = Arc::new(tokio::sync::Notify::new());
    let next_seen = Arc::new(tokio::sync::Notify::new());
    let ready = invoked.clone();
    let seen = next_seen.clone();
    let effects = finished.clone();
    let provider = tokio::spawn(async move {
        register(&listener).await;
        let mut stream = next(&listener).await;
        invoke(&mut stream, "invoke-1", Duration::from_secs(3)).await;
        ready.notify_one();
        let mut stream = next(&listener).await;
        seen.notify_one();
        assert_eq!(effects.load(Ordering::SeqCst), 0);
        invoke(&mut stream, "invoke-2", Duration::from_secs(3)).await;
        ready.notify_one();
        let mut stream = next(&listener).await;
        seen.notify_one();
        assert_eq!(
            effects.load(Ordering::SeqCst),
            2,
            "the eligible flush finished before Next"
        );
        invoke(&mut stream, "invoke-3", Duration::from_secs(3)).await;
        ready.notify_one();
        let mut stream = next(&listener).await;
        assert_eq!(
            effects.load(Ordering::SeqCst),
            2,
            "the third write is still young"
        );
        shutdown(&mut stream, "SPINDOWN").await;
    });
    let running = tokio::spawn({
        let server = server.clone();
        async move { server.run(&endpoint, "test-extension").await }
    });
    invoked.notified().await;
    let client = crate::client(&server, "invoke-1", "attempt-1").await;
    client.add_write_item(1).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), next_seen.notified())
            .await
            .is_err(),
        "INVOKE is not response completion"
    );
    assert_eq!(client.after_response().await.unwrap().items_settled, 0);
    next_seen.notified().await;
    invoked.notified().await;
    clock.advance(Duration::from_millis(250));
    let client = crate::client(&server, "invoke-2", "attempt-2").await;
    client.add_write_item(2).await.unwrap();
    let completing = tokio::spawn({
        let client = client.clone();
        async move { client.after_response().await.unwrap() }
    });
    entered.notified().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), next_seen.notified())
            .await
            .is_err()
    );
    release.notify_one();
    assert_eq!(completing.await.unwrap().items_settled, 2);
    next_seen.notified().await;
    invoked.notified().await;
    let client = crate::client(&server, "invoke-3", "attempt-3").await;
    client.add_write_item(3).await.unwrap();
    assert_eq!(client.after_response().await.unwrap().items_settled, 0);
    let report = tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(report.is_clean());
    assert_eq!(report.items_settled, 1);
    assert_eq!(finished.load(Ordering::SeqCst), 3);
    provider.await.unwrap();
}

#[tokio::test]
async fn given_missing_marker_and_runtime_timeout_when_shutdown_arrives_then_report_failure_and_drain_retained_work()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        observed.fetch_add(attempt.items().len(), Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-provider-timeout/v1", sink)
        .build()
        .unwrap();
    let observer = RecordingWriteObserver::default();
    let server = bind(writer).await.with_observer(observer.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let invoked = Arc::new(tokio::sync::Notify::new());
    let ready = invoked.clone();
    let effects = calls.clone();
    let provider = tokio::spawn(async move {
        register(&listener).await;
        let mut stream = next(&listener).await;
        invoke(&mut stream, "invoke-timeout", Duration::from_millis(150)).await;
        ready.notify_one();
        let mut stream = next(&listener).await;
        assert_eq!(
            effects.load(Ordering::SeqCst),
            0,
            "timeout is not response-complete permission"
        );
        shutdown(&mut stream, "TIMEOUT").await;
    });
    let running = tokio::spawn({
        let server = server.clone();
        async move { server.run(&endpoint, "test-extension").await }
    });
    invoked.notified().await;
    client(&server, "invoke-timeout", "attempt-timeout")
        .await
        .add_write_item(1)
        .await
        .unwrap();
    let report = tokio::time::timeout(Duration::from_secs(2), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(report.is_clean());
    assert_eq!(report.items_settled, 1);
    assert!(observer.events().iter().any(|event| matches!(
        event,
        WriteEvent::LifecycleSourceFailed {
            error: LifecycleError::DeadlineExceeded
        }
    )));
    provider.await.unwrap();
}

#[tokio::test]
async fn given_invalid_api_configuration_when_running_then_reject_without_network() {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = bind(
        BufferedWrites::builder("lambda-api-config/v1", sink)
            .build()
            .unwrap(),
    )
    .await;
    for (endpoint, name) in [
        ("https://127.0.0.1:9001", "test-extension"),
        ("example.com:9001", "test-extension"),
        ("10.0.0.1:9001", "test-extension"),
        ("127.0.0.1:9001", "bad/name"),
    ] {
        assert!(matches!(
            server.run(endpoint, name).await,
            Err(LifecycleError::InvalidConfiguration { .. })
        ));
    }
}

#[tokio::test]
async fn given_provider_next_is_waiting_when_ordinary_http_timeout_elapses_then_keep_long_poll_open()
 {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = bind(
        BufferedWrites::builder("lambda-long-poll/v1", sink)
            .build()
            .unwrap(),
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let waiting = Arc::new(tokio::sync::Notify::new());
    let ready = waiting.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let allowed = release.clone();
    let provider = tokio::spawn(async move {
        register(&listener).await;
        let mut stream = next(&listener).await;
        ready.notify_one();
        allowed.notified().await;
        shutdown(&mut stream, "SPINDOWN").await;
    });
    let running = tokio::spawn({
        let server = server.clone();
        async move { server.run(&endpoint, "test-extension").await }
    });
    waiting.notified().await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(120)).await;
    tokio::task::yield_now().await;
    assert!(
        !running.is_finished(),
        "provider Next must survive the ordinary client's request/read timeout"
    );
    tokio::time::resume();
    release.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), running)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_clean()
    );
    provider.await.unwrap();
}

#[tokio::test]
async fn given_registration_rejection_or_missing_identifier_when_running_then_fail_safely_without_retry()
 {
    for status in [301, 403, 200] {
        let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Ok::<(), SinkError>(())
        })
        .unwrap();
        let server = bind(
            BufferedWrites::builder("lambda-register-error/v1", sink)
                .build()
                .unwrap(),
        )
        .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let provider = tokio::spawn(async move {
            let (mut stream, _) = request(&listener).await;
            reply(
                &mut stream,
                status,
                "Location: http://127.0.0.1:1/private-redirect\r\n",
                b"PRIVATE-DATA",
            )
            .await;
            assert!(
                tokio::time::timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err(),
                "no transparent POST retry or redirect"
            );
        });
        let error = server.run(&endpoint, "test-extension").await.unwrap_err();
        assert!(matches!(error, LifecycleError::SourceUnavailable { .. }));
        assert!(!format!("{error:?} {error}").contains("PRIVATE-DATA"));
        provider.await.unwrap();
    }
}

#[tokio::test]
async fn given_invalid_oversized_or_stalled_event_when_running_then_fail_with_a_bounded_safe_error()
{
    enum Body {
        Invalid,
        Oversized,
        Stalled,
    }
    for body in [Body::Invalid, Body::Oversized, Body::Stalled] {
        let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Ok::<(), SinkError>(())
        })
        .unwrap();
        let server = bind(
            BufferedWrites::builder("lambda-event-error/v1", sink)
                .build()
                .unwrap(),
        )
        .await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let release = Arc::new(tokio::sync::Notify::new());
        let allowed = release.clone();
        let provider = tokio::spawn(async move {
            register(&listener).await;
            let mut stream = next(&listener).await;
            match body {
                Body::Invalid => {
                    reply(&mut stream, 200, "", b"{\"eventType\":\"PRIVATE-DATA\"}").await
                }
                Body::Oversized => reply(&mut stream, 200, "", &vec![b'x'; 65537]).await,
                Body::Stalled => {
                    stream.write_all(b"HTTP/1.1 200 Fixture\r\nContent-Length: 100\r\nConnection: close\r\n\r\nx").await.unwrap();
                    allowed.notified().await;
                }
            }
        });
        let error = tokio::time::timeout(
            Duration::from_secs(2),
            server.run(&endpoint, "test-extension"),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(matches!(
            error,
            LifecycleError::SourceUnavailable { .. } | LifecycleError::DeadlineExceeded
        ));
        assert!(!format!("{error:?} {error}").contains("PRIVATE-DATA"));
        release.notify_one();
        provider.await.unwrap();
    }
}

#[tokio::test]
async fn given_retried_event_with_same_request_id_when_new_provider_phase_arrives_then_keep_extension_available()
 {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = bind(
        BufferedWrites::builder("lambda-repeated-event/v1", sink)
            .build()
            .unwrap(),
    )
    .await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let first = Arc::new(tokio::sync::Notify::new());
    let first_ready = first.clone();
    let second = Arc::new(tokio::sync::Notify::new());
    let second_ready = second.clone();
    let provider = tokio::spawn(async move {
        register(&listener).await;
        let mut stream = next(&listener).await;
        invoke(&mut stream, "same-event", Duration::from_secs(2)).await;
        first_ready.notify_one();
        let mut stream = next(&listener).await;
        invoke(&mut stream, "same-event", Duration::from_secs(2)).await;
        second_ready.notify_one();
        let mut stream = next(&listener).await;
        shutdown(&mut stream, "SPINDOWN").await;
    });
    let mut running = tokio::spawn({
        let server = server.clone();
        async move { server.run(&endpoint, "test-extension").await }
    });
    first.notified().await;
    let first_handle = client(&server, "same-event", "attempt-first").await;
    first_handle.add_write_item(1).await.unwrap();
    first_handle.after_response().await.unwrap();
    second.notified().await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut running)
            .await
            .is_err(),
        "a new provider phase may repeat the event request ID"
    );
    assert!(first_handle.after_response().await.is_err());
    assert!(matches!(
        first_handle.add_write_item(99).await,
        Err(buffered_writes::WriteError::Rejected { .. })
    ));
    assert!(
        runtime(&server)
            .begin_invocation("same-event", "attempt-first")
            .await
            .is_err()
    );
    let second_handle = client(&server, "same-event", "attempt-second").await;
    second_handle.add_write_item(2).await.unwrap();
    second_handle.after_response().await.unwrap();
    assert!(running.await.unwrap().unwrap().is_clean());
    provider.await.unwrap();
}
