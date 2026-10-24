use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferedWrites, Deadline, InMemoryQueue, OperationId, PartialSink, ReplayWorker,
    SinkError, SinkLimits, TestClock, WriteAttempt, WriteOutcome,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct OwnedItem {
    value: Box<u64>,
}

#[tokio::test]
async fn given_non_clone_item_when_factory_handles_and_replay_are_used_then_share_views_without_copying_items()
 {
    let committed = Arc::new(Mutex::new(
        std::collections::BTreeMap::<OperationId, u64>::new(),
    ));
    let observed = committed.clone();
    let envelope = Arc::new(Mutex::new(None));
    let captured = envelope.clone();
    let sink = AtomicSink::try_new(
        SinkLimits::default(),
        move |attempt: WriteAttempt<OwnedItem>| {
            let view = attempt.clone();
            assert!(std::ptr::eq(&attempt.items()[0], &view.items()[0]));
            let pending = attempt.pending_items()[0].clone();
            assert!(std::ptr::eq(pending.item(), &attempt.items()[0]));
            observed
                .lock()
                .unwrap()
                .insert(pending.operation_id().clone(), *pending.value);
            *captured.lock().unwrap() = Some(attempt.sealed_batch().to_envelope_bytes().unwrap());
            async { Ok::<(), SinkError>(()) }
        },
    )
    .unwrap();
    let clock = TestClock::new();
    let writer = BufferedWrites::builder("owned/v1", sink.clone())
        .with_clock(clock.clone())
        .build()
        .unwrap();
    let shared = writer.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let value = Box::new(7);
    shared
        .add_write_item_with(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(OwnedItem { value })
        })
        .await
        .unwrap();
    clock.advance(Duration::from_millis(200));
    assert_eq!(writer.after_response().await.items_settled, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let queue = InMemoryQueue::default();
    queue.inject_raw_envelope(envelope.lock().unwrap().clone().unwrap());
    let replay = ReplayWorker::builder("owned/v1", queue.clone(), sink)
        .build()
        .unwrap();
    assert_eq!(
        replay
            .replay_once(1, Deadline::after(Duration::from_secs(1)))
            .await
            .unwrap()
            .batches_delivered,
        1
    );
    assert_eq!(queue.acknowledged_count(), 1);
    assert_eq!(
        committed
            .lock()
            .unwrap()
            .values()
            .copied()
            .collect::<Vec<_>>(),
        [7]
    );
    assert_eq!(
        writer
            .shutdown(Duration::from_secs(1))
            .await
            .unresolved_items,
        0
    );
}

#[tokio::test]
async fn given_non_clone_item_when_partial_sink_is_shared_then_delivery_does_not_require_item_clone()
 {
    let sink = PartialSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<OwnedItem>| async move {
            assert_eq!(*attempt.items()[0].value, 9);
            Ok::<_, SinkError>(WriteOutcome::Complete)
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("owned-partial/v1", sink.clone())
        .build()
        .unwrap();
    writer
        .add_write_item(OwnedItem { value: Box::new(9) })
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
}

#[cfg(feature = "lambda")]
#[tokio::test]
async fn given_non_clone_item_when_extension_client_is_shared_then_ipc_submission_can_move_the_item()
 {
    let sink = AtomicSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<OwnedItem>| async move {
            assert_eq!(*attempt.items()[0].value, 11);
            Ok::<(), SinkError>(())
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("owned-lambda/v1", sink)
        .build()
        .unwrap();
    let server = buffered_writes::LambdaExtensionServer::bind(
        writer.clone(),
        buffered_writes::LambdaIpcConfig::try_new("127.0.0.1:0".parse().unwrap(), "test-token")
            .unwrap(),
    )
    .await
    .unwrap();
    server
        .begin_invocation("event-invocation-1", "invocation-1", Duration::from_secs(2))
        .unwrap();
    let serving = tokio::spawn({
        let server = server.clone();
        async move { server.serve().await }
    });
    let mut runtime = buffered_writes::LambdaExtensionClient::new(
        buffered_writes::LambdaIpcConfig::try_new(server.local_addr().unwrap(), "test-token")
            .unwrap(),
    );
    let client = runtime
        .begin_invocation("invocation-1", "attempt-invocation-1")
        .await
        .unwrap()
        .clone();

    assert!(
        client
            .add_write_item(OwnedItem {
                value: Box::new(11)
            })
            .await
            .unwrap()
            .is_buffered()
    );
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    server.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(serving.await.unwrap().is_ok());
}
