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
    LambdaIpcConfig, SinkError, SinkLimits, TestClock, WriteAttempt,
};

#[tokio::test]
async fn given_completion_flush_is_pending_when_extension_waits_then_next_cannot_finish_early() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let observed = entered.clone();
    let allowed = release.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        let entered = observed.clone();
        let release = allowed.clone();
        async move {
            entered.notify_one();
            release.notified().await;
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-order/v1", sink)
        .build()
        .unwrap();
    let server = bind(writer).await;
    server
        .begin_invocation("event-invoke-1", "invoke-1", Duration::from_secs(2))
        .unwrap();
    let serving = serve(&server);
    let client = client(&server, "invoke-1").await;
    for item in 0..25 {
        client.add_write_item(item).await.unwrap();
    }
    let completion = tokio::spawn(async move { client.after_response().await.unwrap() });
    entered.notified().await;
    let mut next = Box::pin(server.await_invoke_completion("event-invoke-1"));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), &mut next)
            .await
            .is_err(),
        "Next must wait for the eligible flush, not only the marker"
    );
    release.notify_one();
    assert_eq!(completion.await.unwrap().items_settled, 25);
    tokio::time::timeout(Duration::from_secs(1), next)
        .await
        .unwrap()
        .unwrap();
    server.shutdown(Duration::from_secs(1)).await.unwrap();
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_missing_marker_when_wait_expires_then_no_response_complete_delivery_permission() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-missing/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let server = bind(writer.clone()).await;
    server
        .begin_invocation("event-invoke-1", "invoke-1", Duration::from_millis(300))
        .unwrap();
    let serving = serve(&server);
    let client = client(&server, "invoke-1").await;
    for item in 0..25 {
        client.add_write_item(item).await.unwrap();
    }
    assert!(
        server
            .await_invoke_completion("event-invoke-1")
            .await
            .is_err()
    );
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "a missing marker cannot authorize a response-complete flush"
    );
    assert_eq!(writer.flush_writes().await.items_settled, 25);
    server.shutdown(Duration::from_secs(1)).await.unwrap();
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_overflowing_invocation_budget_when_beginning_then_reject_without_panic() {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-overflow/v1", sink)
        .build()
        .unwrap();
    let server = bind(writer).await;
    assert!(
        server
            .begin_invocation("event-invoke-overflow", "invoke-overflow", Duration::MAX)
            .is_err()
    );
    server
        .begin_invocation("event-invoke-done", "invoke-done", Duration::from_secs(2))
        .unwrap();
    let serving = serve(&server);
    client(&server, "invoke-done")
        .await
        .after_response()
        .await
        .unwrap();
    server
        .await_invoke_completion("event-invoke-done")
        .await
        .unwrap();
    server.shutdown(Duration::from_secs(1)).await.unwrap();
    serving.await.unwrap().unwrap();
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
async fn client(server: &LambdaExtensionServer<u32>, id: &str) -> LambdaInvocation<u32> {
    runtime(server)
        .begin_invocation(id, &format!("attempt-{id}"))
        .await
        .unwrap()
}
fn serve(
    server: &LambdaExtensionServer<u32>,
) -> tokio::task::JoinHandle<Result<(), buffered_writes::LifecycleError>> {
    tokio::spawn({
        let server = server.clone();
        async move { server.serve().await }
    })
}

#[tokio::test]
async fn given_wrong_authority_or_stale_invocation_when_submitting_then_reject_without_delivery() {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        observed.fetch_add(attempt.items().len(), Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-authority/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let server = bind(writer).await;
    server
        .begin_invocation("event-invoke-1", "invoke-1", Duration::from_secs(2))
        .unwrap();
    let serving = serve(&server);
    let mut wrong = LambdaExtensionClient::<u32>::new(
        LambdaIpcConfig::try_new(server.local_addr().unwrap(), "wrong-token").unwrap(),
    );
    assert!(matches!(
        wrong.begin_invocation("invoke-1", "attempt-1").await,
        Err(buffered_writes::LifecycleError::IpcProtocolViolation { .. })
    ));
    let client = client(&server, "invoke-1").await;
    assert!(matches!(
        runtime(&server)
            .begin_invocation("other-invocation", "wrong-attempt")
            .await,
        Err(buffered_writes::LifecycleError::IpcProtocolViolation { .. })
    ));
    client.add_write_item(1).await.unwrap();
    let first = client.after_response().await.unwrap();
    assert_eq!(first.items_settled, 0, "a young batch remains buffered");
    assert_eq!(client.after_response().await.unwrap(), first);
    assert!(
        server
            .begin_invocation("event-invoke-1", "invoke-1", Duration::from_secs(2))
            .is_err(),
        "repeated provider identity cannot reopen a completed phase"
    );
    assert!(matches!(
        client.add_write_item(2).await,
        Err(buffered_writes::WriteError::Rejected { .. })
    ));
    server
        .begin_invocation("event-invoke-2", "invoke-2", Duration::from_secs(2))
        .unwrap();
    assert!(client.after_response().await.is_err());
    let current = crate::client(&server, "invoke-2").await;
    current.add_write_item(2).await.unwrap();
    current.after_response().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .items_settled,
        2
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_missing_marker_when_phase_expires_then_retain_writes_and_allow_next_provider_invocation()
 {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-expire/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let server = bind(writer).await;
    server
        .begin_invocation("event-invoke-1", "invoke-1", Duration::from_millis(100))
        .unwrap();
    let serving = serve(&server);
    let client = client(&server, "invoke-1").await;
    client.add_write_item(1).await.unwrap();
    assert!(matches!(
        server.await_invoke_completion("event-invoke-1").await,
        Err(buffered_writes::LifecycleError::DeadlineExceeded)
    ));
    server
        .begin_invocation("event-invoke-2", "invoke-2", Duration::from_secs(2))
        .unwrap();
    assert!(client.after_response().await.is_err());
    let current = crate::client(&server, "invoke-2").await;
    current.add_write_item(2).await.unwrap();
    assert_eq!(current.after_response().await.unwrap().items_settled, 0);
    assert_eq!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .items_settled,
        2
    );
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_accepted_admission_with_lost_ipc_ack_when_retried_then_reuse_operation_identity_once()
 {
    use buffered_writes::{WriteError, WriteOptions};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-lost-ack/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let server = bind(writer).await;
    server
        .begin_invocation("event-invoke-1", "invoke-1", Duration::from_secs(2))
        .unwrap();
    let serving = serve(&server);
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_address = proxy.local_addr().unwrap();
    let target = server.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut bind_inbound, _) = proxy.accept().await.unwrap();
        let mut bind_outbound = TcpStream::connect(target).await.unwrap();
        let length = bind_inbound.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        bind_inbound.read_exact(&mut bytes).await.unwrap();
        bind_outbound.write_u32(length).await.unwrap();
        bind_outbound.write_all(&bytes).await.unwrap();
        let length = bind_outbound.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        bind_outbound.read_exact(&mut bytes).await.unwrap();
        bind_inbound.write_u32(length).await.unwrap();
        bind_inbound.write_all(&bytes).await.unwrap();
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let length = inbound.read_u32().await.unwrap();
        let mut request = vec![0; length as usize];
        inbound.read_exact(&mut request).await.unwrap();
        let mut outbound = TcpStream::connect(target).await.unwrap();
        outbound.write_u32(length).await.unwrap();
        outbound.write_all(&request).await.unwrap();
        let length = outbound.read_u32().await.unwrap();
        let mut receipt = vec![0; length as usize];
        outbound.read_exact(&mut receipt).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&receipt).unwrap();
        assert!(
            value.get("Admitted").is_some(),
            "real server acknowledged before the proxy drops the reply"
        );
    });
    let faulty =
        LambdaExtensionClient::new(LambdaIpcConfig::try_new(proxy_address, "test-token").unwrap())
            .begin_invocation("invoke-1", "attempt-invoke-1")
            .await
            .unwrap();
    let operation_id = match faulty.add_write_item(7u32).await.unwrap_err() {
        WriteError::Ambiguous { operation_id } => operation_id,
        other => panic!("lost post-dispatch reply must be ambiguous: {other:?}"),
    };
    proxy_task.await.unwrap();
    assert!(
        uuid::Uuid::parse_str(operation_id.as_str())
            .unwrap()
            .get_version_num()
            == 7
    );
    let client = client(&server, "invoke-1").await;
    let admission = client
        .add_write_item_with_options(
            7,
            WriteOptions::new().with_operation_id(operation_id.clone()),
        )
        .await
        .unwrap();
    assert_eq!(admission.operation_id(), &operation_id);
    let conflict = client
        .add_write_item_with_options(
            8,
            WriteOptions::new().with_operation_id(operation_id.clone()),
        )
        .await
        .unwrap_err();
    assert_eq!(conflict, WriteError::IdentityConflict { operation_id });
    assert_eq!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .items_settled,
        1
    );
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_oversized_or_stalled_frame_when_server_recovers_then_next_admission_still_works() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpStream,
    };
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-framing/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let config = LambdaIpcConfig::try_new("127.0.0.1:0".parse().unwrap(), "test-token")
        .unwrap()
        .try_with_timeout(Duration::from_millis(100))
        .unwrap();
    let server = LambdaExtensionServer::bind(writer, config).await.unwrap();
    server
        .begin_invocation("event-invoke-1", "invoke-1", Duration::from_secs(2))
        .unwrap();
    let serving = serve(&server);
    for (length, partial) in [(1_048_577u32, false), (100, true), (0, false)] {
        let mut stream = TcpStream::connect(server.local_addr().unwrap())
            .await
            .unwrap();
        stream.write_u32(length).await.unwrap();
        if partial {
            stream.write_all(b"x").await.unwrap();
        }
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    client(&server, "invoke-1")
        .await
        .add_write_item(1)
        .await
        .unwrap();
    assert_eq!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .items_settled,
        1
    );
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_invalid_configuration_or_oversized_encoding_when_client_runs_then_no_network_admission()
 {
    use buffered_writes::WriteError;
    assert!(LambdaIpcConfig::try_new("10.0.0.1:1234".parse().unwrap(), "token").is_err());
    assert!(LambdaIpcConfig::try_new("127.0.0.1:1234".parse().unwrap(), "").is_err());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = LambdaIpcConfig::try_new(listener.local_addr().unwrap(), "private-token").unwrap();
    assert!(!format!("{config:?}").contains("private-token"));
    assert!(config.clone().try_with_timeout(Duration::ZERO).is_err());
    assert!(config.clone().try_with_timeout(Duration::MAX).is_err());
    let binding = tokio::spawn({
        let address = listener.local_addr().unwrap();
        async move {
            LambdaExtensionClient::<String>::new(
                LambdaIpcConfig::try_new(address, "private-token").unwrap(),
            )
            .begin_invocation("invoke-1", "attempt-1")
            .await
            .unwrap()
        }
    });
    fake_binding(&listener).await;
    let client = binding.await.unwrap();
    assert!(matches!(
        client.add_write_item("x".repeat(1_048_577)).await,
        Err(WriteError::OversizedItem { .. })
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), listener.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn given_persistent_driver_or_periodic_policy_when_binding_extension_then_reject_competing_lifecycle()
 {
    fn writer(periodic: bool) -> BufferedWrites<u32> {
        let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
            Ok::<(), SinkError>(())
        })
        .unwrap();
        let builder = BufferedWrites::builder("lambda-driver-owner/v1", sink);
        if periodic {
            builder
                .periodic_flush(Duration::from_secs(1))
                .build()
                .unwrap()
        } else {
            builder.build().unwrap()
        }
    }
    let config = || LambdaIpcConfig::try_new("127.0.0.1:0".parse().unwrap(), "test-token").unwrap();
    let persistent = writer(false);
    let guard = persistent
        .start(buffered_writes::Lifecycle::tokio())
        .await
        .unwrap();
    assert!(matches!(
        LambdaExtensionServer::bind(persistent.clone(), config()).await,
        Err(buffered_writes::LifecycleError::DriverAlreadyStarted)
    ));
    assert!(persistent.shutdown(Duration::from_secs(1)).await.is_clean());
    drop(guard);
    let periodic = writer(true);
    assert!(matches!(
        LambdaExtensionServer::bind(periodic.clone(), config()).await,
        Err(buffered_writes::LifecycleError::InvalidConfiguration { .. })
    ));
    let guard = periodic
        .start(buffered_writes::Lifecycle::tokio())
        .await
        .unwrap();
    assert!(periodic.shutdown(Duration::from_secs(1)).await.is_clean());
    drop(guard);
    let owned = writer(false);
    let server = LambdaExtensionServer::bind(owned.clone(), config())
        .await
        .unwrap();
    assert!(matches!(
        owned.start(buffered_writes::Lifecycle::tokio()).await,
        Err(buffered_writes::LifecycleError::DriverAlreadyStarted)
    ));
    assert!(matches!(
        LambdaExtensionServer::bind(owned, config()).await,
        Err(buffered_writes::LifecycleError::DriverAlreadyStarted)
    ));
    assert!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .is_clean()
    );
}

#[tokio::test]
async fn given_busy_endpoint_when_extension_bind_fails_then_writer_driver_slot_remains_available() {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("lambda-bind-failure/v1", sink)
        .build()
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = LambdaIpcConfig::try_new(listener.local_addr().unwrap(), "test-token").unwrap();
    assert!(
        LambdaExtensionServer::bind(writer.clone(), config)
            .await
            .is_err()
    );
    let guard = writer
        .start(buffered_writes::Lifecycle::tokio())
        .await
        .unwrap();
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    drop(guard);
}

#[tokio::test]
async fn given_stored_invocation_deadline_when_completion_is_waited_then_cannot_extend_provider_budget()
 {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = bind(
        BufferedWrites::builder("lambda-one-deadline/v1", sink)
            .build()
            .unwrap(),
    )
    .await;
    server
        .begin_invocation(
            "event-invoke-short",
            "invoke-short",
            Duration::from_millis(20),
        )
        .unwrap();
    assert!(matches!(
        tokio::time::timeout(
            Duration::from_millis(100),
            server.await_invoke_completion("event-invoke-short")
        )
        .await
        .expect("stored provider deadline must bound the wait"),
        Err(buffered_writes::LifecycleError::DeadlineExceeded)
    ));
    server
        .begin_invocation("event-invoke-next", "invoke-next", Duration::from_secs(1))
        .unwrap();
    assert!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .is_clean()
    );
}

#[tokio::test]
async fn given_active_ipc_service_when_another_handle_serves_or_runs_then_reject_until_owner_is_cancelled()
 {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = bind(
        BufferedWrites::builder("lambda-service-owner/v1", sink)
            .build()
            .unwrap(),
    )
    .await;
    let mut first = Box::pin(server.serve());
    assert!(futures_util::poll!(&mut first).is_pending());
    let mut second = Box::pin(server.serve());
    assert!(matches!(
        futures_util::poll!(&mut second),
        std::task::Poll::Ready(Err(buffered_writes::LifecycleError::DriverAlreadyStarted))
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    assert!(matches!(
        server
            .run(
                &listener.local_addr().unwrap().to_string(),
                "test-extension"
            )
            .await,
        Err(buffered_writes::LifecycleError::DriverAlreadyStarted)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(10), listener.accept())
            .await
            .is_err(),
        "a second runner cannot register another provider lifecycle"
    );
    drop(first);
    let mut restarted = Box::pin(server.serve());
    assert!(futures_util::poll!(&mut restarted).is_pending());
    drop(restarted);
    assert!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .is_clean()
    );
}

#[tokio::test]
async fn given_mismatched_admission_receipt_when_client_receives_it_then_preserve_ambiguous_operation_identity()
 {
    use buffered_writes::{
        Admission, AdmissionStatus, DurabilityClass, OperationId, WriteError, WriteOptions,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        fake_binding(&listener).await;
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = stream.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        stream.read_exact(&mut bytes).await.unwrap();
        let reply = serde_json::json!({"Admitted": Admission::new(AdmissionStatus::Buffered, DurabilityClass::Volatile, OperationId::generate_v7())}).to_string();
        stream.write_u32(reply.len() as u32).await.unwrap();
        stream.write_all(reply.as_bytes()).await.unwrap();
    });
    let client =
        LambdaExtensionClient::new(LambdaIpcConfig::try_new(address, "test-token").unwrap())
            .begin_invocation("invoke-1", "attempt-1")
            .await
            .unwrap();
    let operation_id = OperationId::generate_v7();
    assert_eq!(
        client
            .add_write_item_with_options(
                1u32,
                WriteOptions::new().with_operation_id(operation_id.clone())
            )
            .await,
        Err(WriteError::Ambiguous { operation_id })
    );
    peer.await.unwrap();
}

async fn fake_binding(listener: &tokio::net::TcpListener) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut stream, _) = listener.accept().await.unwrap();
    let length = stream.read_u32().await.unwrap();
    let mut bytes = vec![0; length as usize];
    stream.read_exact(&mut bytes).await.unwrap();
    let request: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let bind = &request["command"]["Bind"];
    let bytes = serde_json::to_vec(&serde_json::json!({"Bound": {"request_id": bind["request_id"], "attempt_id": bind["attempt_id"], "session": uuid::Uuid::now_v7().to_string(), "namespace": "test/v1"}})).unwrap();
    stream.write_u32(bytes.len() as u32).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn given_bind_ack_is_lost_when_runtime_rebinds_then_recover_same_phase_and_fence_old_handles()
{
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
    };
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let server = bind(
        BufferedWrites::builder("lambda-bind-retry/v1", sink)
            .with_clock(TestClock::new())
            .build()
            .unwrap(),
    )
    .await;
    let serving = serve(&server);
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = proxy.local_addr().unwrap();
    let target = server.local_addr().unwrap();
    let proxy_task = tokio::spawn(async move {
        let (mut inbound, _) = proxy.accept().await.unwrap();
        let length = inbound.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        inbound.read_exact(&mut bytes).await.unwrap();
        let mut outbound = TcpStream::connect(target).await.unwrap();
        outbound.write_u32(length).await.unwrap();
        outbound.write_all(&bytes).await.unwrap();
        let length = outbound.read_u32().await.unwrap();
        let mut bytes = vec![0; length as usize];
        outbound.read_exact(&mut bytes).await.unwrap();
        assert!(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .unwrap()
                .get("Bound")
                .is_some()
        );
    });
    let binding = tokio::spawn(async move {
        LambdaExtensionClient::<u32>::new(LambdaIpcConfig::try_new(address, "test-token").unwrap())
            .begin_invocation("same-request", "attempt-1")
            .await
    });
    tokio::task::yield_now().await;
    assert!(
        !binding.is_finished(),
        "a bind cannot create a provider phase"
    );
    server
        .begin_invocation("event-first", "same-request", Duration::from_secs(2))
        .unwrap();
    assert!(
        binding.await.unwrap().is_err(),
        "the proxy drops the real Bound response"
    );
    proxy_task.await.unwrap();
    let old = runtime(&server)
        .begin_invocation("same-request", "attempt-1")
        .await
        .unwrap();
    assert!(
        runtime(&server)
            .begin_invocation("same-request", "attempt-intruder")
            .await
            .is_err()
    );
    old.add_write_item(1).await.unwrap();
    let summary = old.after_response().await.unwrap();
    assert_eq!(old.clone().after_response().await.unwrap(), summary);
    server.await_invoke_completion("event-first").await.unwrap();
    server
        .begin_invocation("event-second", "same-request", Duration::from_secs(2))
        .unwrap();
    assert!(
        runtime(&server)
            .begin_invocation("same-request", "attempt-1")
            .await
            .is_err()
    );
    assert!(old.after_response().await.is_err());
    assert!(matches!(
        old.add_write_item(99).await,
        Err(buffered_writes::WriteError::Rejected { .. })
    ));
    let current = runtime(&server)
        .begin_invocation("same-request", "attempt-2")
        .await
        .unwrap();
    current.add_write_item(2).await.unwrap();
    current.after_response().await.unwrap();
    assert_eq!(
        server
            .shutdown(Duration::from_secs(1))
            .await
            .unwrap()
            .items_settled,
        2
    );
    serving.await.unwrap().unwrap();
}
