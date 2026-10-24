#![cfg(feature = "tokio")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferedWrites, DeliveryMode, DeliveryPolicy, FlushThresholds, Lifecycle,
    LifecycleError, LifecycleEvents, LifecycleTrigger, SinkError, SinkLimits, TestClock,
    WriteAttempt, WriteError,
};

async fn wait_until(predicate: impl Fn() -> bool) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("lifecycle task must make bounded progress");
}

fn counting_sink() -> (AtomicSink<u32>, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        observed.fetch_add(attempt.items().len(), Ordering::SeqCst);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    (sink, calls)
}

struct StateReadingObserver(Arc<std::sync::Mutex<Option<BufferedWrites<u32>>>>);

impl buffered_writes::WriteObserver for StateReadingObserver {
    fn observe(&self, event: buffered_writes::WriteEvent) {
        let buffered_writes::WriteEvent::ModeChanged { to, .. } = event else {
            return;
        };
        let writer = self.0.lock().unwrap().as_ref().unwrap().clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let reader = std::thread::spawn(move || {
            let _ = sender.send(writer.mode_and_health());
        });
        let state = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("observer callbacks must run outside engine state ownership");
        assert_eq!(state.0, to);
        reader.join().unwrap();
    }
}

#[tokio::test]
async fn given_observer_that_reads_writer_state_when_shutdown_changes_mode_then_callbacks_do_not_hold_state_ownership()
 {
    let reference = Arc::new(std::sync::Mutex::new(None));
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("observer-state-reading", sink)
        .with_observer(StateReadingObserver(reference.clone()))
        .build()
        .unwrap();
    *reference.lock().unwrap() = Some(writer.clone());
    writer.add_write_item(1).await.unwrap();
    assert!(writer.shutdown(Duration::from_secs(2)).await.is_clean());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    reference.lock().unwrap().take();
}

#[tokio::test]
async fn given_response_bound_host_when_capacity_is_reached_then_wait_for_completion_event() {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("response-window/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let (host, events) = Lifecycle::channel();
    let guard = writer.start(events).await.unwrap();
    for item in 0..25 {
        assert!(writer.add_write_item(item).await.unwrap().is_buffered());
    }
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        writer.add_write_item(25).await,
        Err(WriteError::Full)
    ));
    host.send(LifecycleTrigger::ResponseCompleted);
    wait_until(|| calls.load(Ordering::SeqCst) == 25).await;
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_persistent_host_when_sink_hangs_then_admission_returns_without_waiting_for_delivery()
{
    let entered = Arc::new(tokio::sync::Notify::new());
    let observed = entered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.notify_one();
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("background-window/v1", sink)
        .build()
        .unwrap();
    let lifecycle = Lifecycle::tokio();
    let guard = writer.start(lifecycle).await.unwrap();
    tokio::time::timeout(Duration::from_millis(100), async {
        for item in 0..25 {
            assert!(writer.add_write_item(item).await.unwrap().is_buffered());
        }
    })
    .await
    .expect("buffered admission cannot await the hung sink");
    tokio::time::timeout(Duration::from_secs(1), entered.notified())
        .await
        .unwrap();
    assert!(matches!(
        writer.add_write_item(25).await,
        Err(WriteError::Full)
    ));
    let report = writer.shutdown(Duration::from_millis(30)).await;
    assert_eq!(report.unresolved_items, 25);
    assert!(!report.is_clean());
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_active_sink_when_shutdown_events_arrive_then_close_admission_and_shorten_deadline() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let observed = entered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.notify_one();
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("event-drain/v1", sink)
        .delivery_policy(DeliveryPolicy {
            lease_duration: Duration::from_secs(30),
            attempt_timeout: Duration::from_secs(10),
            flush_budget: Duration::from_secs(10),
            ..DeliveryPolicy::default()
        })
        .build()
        .unwrap();
    let (host, events) = Lifecycle::channel();
    let guard = writer.start(events).await.unwrap();
    writer.add_write_item(1).await.unwrap();
    host.send(LifecycleTrigger::ExplicitFlush);
    entered.notified().await;
    host.send(LifecycleTrigger::Shutdown {
        deadline: Duration::from_secs(5).into(),
    });
    wait_until(|| writer.mode_and_health().0 == DeliveryMode::Draining).await;
    assert!(matches!(
        writer.add_write_item(2).await,
        Err(WriteError::Closed)
    ));
    host.send(LifecycleTrigger::Shutdown {
        deadline: Duration::from_millis(30).into(),
    });
    tokio::time::timeout(Duration::from_millis(200), async {
        while guard.is_active() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("earlier shutdown event must bound active I/O");
    let report = writer.shutdown(Duration::from_secs(1)).await;
    assert_eq!(report.unresolved_items, 1);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_closed_lifecycle_when_driver_exits_then_guard_reports_inactive() {
    let (sink, _) = counting_sink();
    let writer = BufferedWrites::builder("closed-lifecycle/v1", sink)
        .build()
        .unwrap();
    let (host, events) = Lifecycle::channel();
    let guard = writer.start(events).await.unwrap();
    host.close();
    wait_until(|| !guard.is_active()).await;
    assert!(matches!(
        writer.start(Lifecycle::tokio()).await,
        Err(LifecycleError::DriverAlreadyStarted)
    ));
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
}

#[tokio::test]
async fn given_many_pending_events_when_shutdown_arrives_then_coalesce_and_prioritize_earliest_deadline()
 {
    let (host, events) = Lifecycle::channel();
    for _ in 0..10_000 {
        host.send(LifecycleTrigger::ResponseCompleted);
        host.send(LifecycleTrigger::PeriodicTick);
    }
    host.send(LifecycleTrigger::ExplicitFlush);
    host.send(LifecycleTrigger::ResponseCompleted);
    assert_eq!(
        events.next_event().await,
        Some(LifecycleTrigger::ExplicitFlush)
    );
    let earlier = buffered_writes::Deadline::after(Duration::from_millis(50));
    host.send(LifecycleTrigger::ResponseCompleted);
    host.send(LifecycleTrigger::Shutdown { deadline: earlier });
    host.send(LifecycleTrigger::Shutdown {
        deadline: Duration::from_secs(5).into(),
    });
    host.send(LifecycleTrigger::ExplicitFlush);
    host.close();
    assert_eq!(
        events.next_event().await,
        Some(LifecycleTrigger::Shutdown { deadline: earlier })
    );
    assert_eq!(events.next_event().await, None);
}

#[tokio::test]
async fn given_periodic_configuration_when_event_bound_host_starts_then_reject_without_claiming_driver()
 {
    let (sink, _) = counting_sink();
    let writer = BufferedWrites::builder("periodic-permission/v1", sink)
        .periodic_flush(Duration::from_millis(10))
        .build()
        .unwrap();
    let (_, events) = Lifecycle::channel();
    assert!(matches!(
        writer.start(events).await,
        Err(LifecycleError::InvalidConfiguration { .. })
    ));
    let guard = writer.start(Lifecycle::tokio()).await.unwrap();
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_periodic_driver_when_age_reaches_override_then_flush_without_response() {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("periodic-age/v1", sink)
        .flush_policy(FlushThresholds::default().max_age(Duration::from_millis(30)))
        .periodic_flush(Duration::from_millis(5))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "build cannot create a timer"
    );
    let guard = writer.start(Lifecycle::tokio()).await.unwrap();
    wait_until(|| calls.load(Ordering::SeqCst) == 1).await;
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_periodic_driver_when_custom_predicate_is_false_then_only_explicit_flush_overrides_it()
 {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("periodic-predicate/v1", sink)
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .periodic_flush(Duration::from_millis(5))
        .build()
        .unwrap();
    let lifecycle = Lifecycle::tokio();
    let guard = writer.start(lifecycle.clone()).await.unwrap();
    writer.add_write_item(1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    lifecycle.notify_explicit_flush();
    wait_until(|| calls.load(Ordering::SeqCst) == 1).await;
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert!(!guard.is_active());
}

#[cfg(feature = "lambda")]
#[tokio::test]
async fn given_lambda_ipc_when_25_items_arrive_then_deliver_only_after_completion_marker() {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("lambda-window/v1", sink)
        .with_clock(TestClock::new())
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
        .begin_invocation(
            "event-invocation-25",
            "invocation-25",
            Duration::from_secs(2),
        )
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
        .begin_invocation("invocation-25", "attempt-invocation-25")
        .await
        .unwrap()
        .clone();
    for item in 0..25 {
        assert!(client.add_write_item(item).await.unwrap().is_buffered());
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(client.after_response().await.unwrap().items_settled, 25);
    assert_eq!(calls.load(Ordering::SeqCst), 25);
    assert_eq!(client.after_response().await.unwrap().items_settled, 25);
    assert_eq!(calls.load(Ordering::SeqCst), 25);
    server.shutdown(Duration::from_secs(1)).await.unwrap();
    assert!(serving.await.unwrap().is_ok());
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
}

#[tokio::test]
async fn given_cancelled_driver_when_more_items_arrive_then_keep_ownership_for_explicit_drain() {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("guard-cancel/v1", sink)
        .with_clock(TestClock::new())
        .build()
        .unwrap();
    let lifecycle = Lifecycle::tokio();
    let guard = writer.start(lifecycle.clone()).await.unwrap();
    guard.cancel();
    for item in 0..25 {
        writer.add_write_item(item).await.unwrap();
    }
    lifecycle.notify_explicit_flush();
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!guard.is_active());
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert_eq!(calls.load(Ordering::SeqCst), 25);
}

#[tokio::test]
async fn given_young_item_when_periodic_ticks_reach_age_then_deliver_without_new_admission() {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("periodic-young/v1", sink)
        .flush_policy(FlushThresholds::default().max_age(Duration::from_millis(50)))
        .periodic_flush(Duration::from_millis(5))
        .build()
        .unwrap();
    let guard = writer.start(Lifecycle::tokio()).await.unwrap();
    writer.add_write_item(1).await.unwrap();
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    wait_until(|| calls.load(Ordering::SeqCst) == 1).await;
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_cancelled_active_flush_when_lease_expires_then_retry_same_sealed_identity() {
    let clock = TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let buffer = buffered_writes::MemoryBuffer::new("cancelled-lease/v1".try_into().unwrap());
    let identities = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = identities.clone();
    let entered = Arc::new(tokio::sync::Notify::new());
    let observed = entered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        captured.lock().unwrap().push(attempt.batch_id());
        observed.notify_one();
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("cancelled-lease/v1", sink)
        .with_buffer_provider(buffer.clone())
        .with_clock(clock.clone())
        .build()
        .unwrap();
    writer.add_write_item(7).await.unwrap();
    let lifecycle = Lifecycle::tokio();
    let guard = writer.start(lifecycle.clone()).await.unwrap();
    lifecycle.notify_explicit_flush();
    entered.notified().await;
    guard.cancel();
    tokio::task::yield_now().await;
    clock.advance(Duration::from_secs(6));
    let captured = identities.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        captured.lock().unwrap().push(attempt.batch_id());
        assert_eq!(attempt.items(), [7]);
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let recovered = BufferedWrites::builder("cancelled-lease/v1", sink)
        .with_buffer_provider(buffer)
        .with_clock(clock.clone())
        .build()
        .unwrap();
    assert_eq!(recovered.flush_writes().await.items_settled, 1);
    let ids = identities.lock().unwrap().clone();
    assert_eq!(ids.len(), 2);
    assert_eq!(ids[0], ids[1]);
    assert!(
        recovered
            .shutdown(buffered_writes::Deadline::from_anchor(
                buffered_writes::Clock::now_instant(&clock),
                Duration::from_secs(1)
            ))
            .await
            .is_clean()
    );
    assert!(
        writer
            .shutdown(buffered_writes::Deadline::from_anchor(
                buffered_writes::Clock::now_instant(&clock),
                Duration::from_secs(1)
            ))
            .await
            .is_clean()
    );
}

#[test]
fn given_no_tokio_runtime_when_start_is_polled_then_return_configuration_error_without_panicking() {
    let (sink, _) = counting_sink();
    let writer = BufferedWrites::builder("missing-runtime/v1", sink)
        .build()
        .unwrap();
    let mut start = Box::pin(writer.start(Lifecycle::tokio()));
    let waker = futures_util::task::noop_waker();
    let mut context = std::task::Context::from_waker(&waker);
    assert!(matches!(
        std::future::Future::poll(start.as_mut(), &mut context),
        std::task::Poll::Ready(Err(LifecycleError::InvalidConfiguration { .. }))
    ));
}

struct HungSpotSource(Arc<tokio::sync::Notify>);
impl buffered_writes::SpotActionSource for HungSpotSource {
    fn poll_spot_action(
        &self,
    ) -> futures_util::future::BoxFuture<
        'static,
        Result<Option<buffered_writes::SpotInstanceAction>, buffered_writes::LifecycleError>,
    > {
        self.0.notify_one();
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn given_hung_spot_source_when_host_shutdown_arrives_then_deliver_host_event_without_waiting()
{
    let entered = Arc::new(tokio::sync::Notify::new());
    let lifecycle = buffered_writes::SpotLifecycle::new(HungSpotSource(entered.clone()));
    let event = tokio::spawn(lifecycle.next_event());
    entered.notified().await;
    let deadline = buffered_writes::Deadline::after(Duration::from_secs(1));
    lifecycle.notify_shutdown(deadline);
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), event)
            .await
            .unwrap()
            .unwrap(),
        Some(LifecycleTrigger::Shutdown { deadline })
    );
    lifecycle.close();
    assert_eq!(lifecycle.next_event().await, None);
}

#[tokio::test]
async fn given_waiting_response_bound_host_when_no_completion_arrives_then_timeout_without_sink_effects()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        observed.fetch_add(1, Ordering::SeqCst);
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("waiting-response/v1", sink)
        .buffer_capacity(
            buffered_writes::BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    let (_, events) = Lifecycle::channel();
    let guard = writer.start(events).await.unwrap();
    writer.add_write_item(1).await.unwrap();
    let factory = AtomicUsize::new(0);
    let result = writer
        .add_write_item_with_and_options(
            || {
                factory.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            },
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(30)),
        )
        .await;
    assert!(result.unwrap_err().is_definitely_rejected());
    assert_eq!(factory.load(Ordering::SeqCst), 0);
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "waiting cannot grant a lifecycle execution window"
    );
    guard.cancel();
}

#[tokio::test]
async fn given_waiting_response_bound_host_when_completion_arrives_then_release_capacity_before_factory()
 {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("waiting-window/v1", sink)
        .buffer_capacity(
            buffered_writes::BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    let (host, events) = Lifecycle::channel();
    let guard = writer.start(events).await.unwrap();
    writer.add_write_item(1).await.unwrap();
    let pending_writer = writer.clone();
    let observed = calls.clone();
    let admission = tokio::spawn(async move {
        pending_writer
            .add_write_item_with(|| {
                assert_eq!(observed.load(Ordering::SeqCst), 1);
                Ok(2)
            })
            .await
    });
    tokio::task::yield_now().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    host.send(LifecycleTrigger::ResponseCompleted);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), admission)
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .is_buffered()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_waiting_persistent_host_when_full_then_driver_releases_capacity_despite_false_predicate()
 {
    let (sink, calls) = counting_sink();
    let writer = BufferedWrites::builder("waiting-persistent/v1", sink)
        .buffer_capacity(
            buffered_writes::BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    let guard = writer.start(Lifecycle::tokio()).await.unwrap();
    writer.add_write_item(1).await.unwrap();
    assert!(writer.add_write_item(2).await.unwrap().is_buffered());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_empty_or_full_writer_when_guard_drops_then_report_lifecycle_fact_without_inventing_count()
 {
    for items in [0, 25] {
        let (sink, calls) = counting_sink();
        let observer = buffered_writes::RecordingWriteObserver::default();
        let writer = BufferedWrites::builder("guard-observation/v1", sink)
            .with_observer(observer.clone())
            .with_clock(TestClock::new())
            .build()
            .unwrap();
        let (_, events) = Lifecycle::channel();
        let guard = writer.start(events).await.unwrap();
        for item in 0..items {
            writer.add_write_item(item).await.unwrap();
        }
        drop(guard);
        assert_eq!(
            observer
                .events()
                .iter()
                .filter(|event| matches!(
                    event,
                    buffered_writes::WriteEvent::GuardDroppedBeforeShutdown
                ))
                .count(),
            1
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let report = writer.shutdown(Duration::from_secs(1)).await;
        assert_eq!(report.items_settled, items as usize);
        assert!(report.is_clean());
    }
}

#[tokio::test]
async fn given_multiple_channel_waiters_when_closed_then_all_return_without_another_event() {
    let (controller, events) = Lifecycle::channel();
    let mut first = Box::pin(events.next_event());
    let mut second = Box::pin(events.next_event());
    assert!(futures_util::poll!(&mut first).is_pending());
    assert!(futures_util::poll!(&mut second).is_pending());
    controller.close();
    assert_eq!(
        tokio::time::timeout(Duration::from_millis(100), async {
            tokio::join!(first, second)
        })
        .await
        .expect("close is terminal for every channel waiter"),
        (None, None)
    );
}
