#![cfg(all(feature = "lambda", unix))]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BackpressurePolicy, BufferCapacity, BufferStats, BufferedWrites, Deadline,
    LambdaExtensionClient, LambdaExtensionServer, LambdaIpcConfig, SinkError, SinkLimits,
    WriteAttempt, WriteError, WriteOptions,
};
use tokio::io::AsyncWriteExt;

async fn extension(
    capacity: usize,
) -> (
    LambdaExtensionServer<u32>,
    LambdaExtensionClient<u32>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<Result<(), buffered_writes::LifecycleError>>,
) {
    let delivered = Arc::new(AtomicUsize::new(0));
    let saved = delivered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        let saved = saved.clone();
        async move {
            saved.fetch_add(attempt.items().len(), Ordering::SeqCst);
            Ok::<(), SinkError>(())
        }
    })
    .unwrap();
    let writer = BufferedWrites::builder("deadline/v1", sink)
        .buffer_capacity(
            BufferCapacity::default()
                .max_items(capacity)
                .backpressure(BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &BufferStats| false)
        .build()
        .unwrap();
    let server = LambdaExtensionServer::bind(
        writer,
        LambdaIpcConfig::try_new("127.0.0.1:0".parse().unwrap(), "deadline-token").unwrap(),
    )
    .await
    .unwrap();
    server
        .begin_invocation("event-1", "request-1", Duration::from_secs(3))
        .unwrap();
    let serving = tokio::spawn({
        let server = server.clone();
        async move { server.serve().await }
    });
    let client = LambdaExtensionClient::new(
        LambdaIpcConfig::try_new(server.local_addr().unwrap(), "deadline-token").unwrap(),
    );
    (server, client, delivered, serving)
}

#[tokio::test]
async fn given_full_extension_buffer_when_submit_expires_then_completion_is_not_blocked_by_a_renewed_ipc_budget()
 {
    let (server, mut runtime, delivered, serving) = extension(1).await;
    let client = runtime
        .begin_invocation("request-1", "attempt-1")
        .await
        .unwrap();
    client.add_write_item(1).await.unwrap();
    let result = client
        .add_write_item_with_options(
            2,
            WriteOptions::new().with_deadline(Deadline::after(Duration::from_millis(40))),
        )
        .await;
    assert!(matches!(
        result,
        Err(WriteError::Ambiguous { .. } | WriteError::DeadlineExceeded { .. })
    ));
    let report = tokio::time::timeout(Duration::from_millis(250), client.after_response())
        .await
        .expect("expired admission must release the serial server")
        .unwrap();
    assert!(!report.has_failures);
    let report = server.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(report.is_clean());
    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    serving.await.unwrap().unwrap();
}

#[tokio::test]
async fn given_submit_queued_behind_an_incomplete_frame_when_its_deadline_expires_then_it_cannot_be_admitted_later()
 {
    let (server, mut runtime, delivered, serving) = extension(2).await;
    let client = runtime
        .begin_invocation("request-1", "attempt-1")
        .await
        .unwrap();
    let mut blocker = tokio::net::TcpStream::connect(server.local_addr().unwrap())
        .await
        .unwrap();
    blocker.write_all(&[0]).await.unwrap();
    let result = client
        .add_write_item_with_options(
            1,
            WriteOptions::new().with_deadline(Deadline::after(Duration::from_millis(30))),
        )
        .await;
    assert!(matches!(result, Err(WriteError::Ambiguous { .. })));
    drop(blocker);
    let completion = tokio::time::timeout(Duration::from_millis(250), client.after_response())
        .await
        .unwrap()
        .unwrap();
    assert!(!completion.has_failures);
    let report = server.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(report.is_clean());
    assert_eq!(
        report.items_settled, 0,
        "queueing must consume the original admission budget"
    );
    assert_eq!(delivered.load(Ordering::SeqCst), 0);
    serving.await.unwrap().unwrap();
}
