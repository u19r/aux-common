use std::{
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    AtomicSink, BufferAppendRequest, BufferAppendResult, BufferClaimRequest, BufferError,
    BufferInspectRequest, BufferRenewRequest, BufferSealRequest, BufferSettleRequest,
    BufferSnapshot, BufferedWrites, ClaimedWork, DurabilityClass, LeasedSealedBatch, MemoryBuffer,
    SinkError, SinkLimits, WriteAttempt, WriteBuffer,
};
use futures_util::future::BoxFuture;

#[derive(Clone)]
struct InspectFault {
    inner: MemoryBuffer,
    fault: Arc<AtomicU8>,
    appends: Arc<std::sync::atomic::AtomicUsize>,
    settlements: Arc<std::sync::atomic::AtomicUsize>,
    entered: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}
impl Default for InspectFault {
    fn default() -> Self {
        Self {
            inner: MemoryBuffer::new(
                buffered_writes::Namespace::try_from("provider-errors/v1").unwrap(),
            ),
            fault: Arc::default(),
            appends: Arc::default(),
            settlements: Arc::default(),
            entered: Arc::default(),
            resume: Arc::default(),
        }
    }
}
impl WriteBuffer for InspectFault {
    fn namespace(&self) -> &buffered_writes::Namespace {
        self.inner.namespace()
    }

    fn durability_class(&self) -> DurabilityClass {
        self.inner.durability_class()
    }
    fn append(
        &self,
        r: BufferAppendRequest,
    ) -> BoxFuture<'static, Result<BufferAppendResult, BufferError>> {
        self.appends.fetch_add(1, Ordering::SeqCst);
        if self
            .fault
            .compare_exchange(9, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return Box::pin(async { Err(BufferError::Full) });
        }
        match self.fault.load(Ordering::SeqCst) {
            7 => {
                self.entered.notify_one();
                Box::pin(std::future::pending())
            }
            8 => {
                let result = self.inner.append(r);
                self.entered.notify_one();
                Box::pin(async move {
                    let _lost_response = result.await;
                    std::future::pending().await
                })
            }
            _ => self.inner.append(r),
        }
    }
    fn claim(&self, r: BufferClaimRequest) -> BoxFuture<'static, Result<ClaimedWork, BufferError>> {
        if self.fault.load(Ordering::SeqCst) == 3 {
            return Box::pin(async {
                Err(BufferError::StorageUnavailable {
                    reason: "injected claim failure",
                })
            });
        }
        self.inner.claim(r)
    }
    fn seal(
        &self,
        r: BufferSealRequest,
    ) -> BoxFuture<'static, Result<Option<LeasedSealedBatch>, BufferError>> {
        if self.fault.load(Ordering::SeqCst) == 4 {
            return Box::pin(async {
                Err(BufferError::StorageUnavailable {
                    reason: "injected seal failure",
                })
            });
        }
        self.inner.seal(r)
    }
    fn renew(&self, r: BufferRenewRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        self.inner.renew(r)
    }
    fn settle(&self, r: BufferSettleRequest) -> BoxFuture<'static, Result<(), BufferError>> {
        self.settlements.fetch_add(1, Ordering::SeqCst);
        if self.fault.load(Ordering::SeqCst) == 10 {
            let result = self.inner.settle(r);
            return Box::pin(async move {
                result.await?;
                Err(BufferError::StorageUnavailable {
                    reason: "settlement committed but acknowledgement lost",
                })
            });
        }
        if self.fault.load(Ordering::SeqCst) == 5 {
            return Box::pin(async {
                Err(BufferError::StorageUnavailable {
                    reason: "injected settlement failure",
                })
            });
        }
        self.inner.settle(r)
    }
    fn inspect(
        &self,
        r: BufferInspectRequest,
    ) -> BoxFuture<'static, Result<BufferSnapshot, BufferError>> {
        if self
            .fault
            .compare_exchange(6, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let snapshot = self.inner.inspect(r);
            let entered = self.entered.clone();
            let resume = self.resume.clone();
            return Box::pin(async move {
                let snapshot = snapshot.await?;
                entered.notify_one();
                resume.notified().await;
                Ok(snapshot)
            });
        }
        match self.fault.load(Ordering::SeqCst) {
            0 | 3..=5 | 7..=10 => self.inner.inspect(r),
            1 => Box::pin(async {
                Err(BufferError::StorageUnavailable {
                    reason: "injected inspection failure",
                })
            }),
            _ => Box::pin(std::future::pending()),
        }
    }
}
fn writer(buffer: InspectFault) -> BufferedWrites<u32> {
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer)
        .build()
        .unwrap()
}

#[tokio::test]
async fn given_known_backlog_when_drain_inspection_expires_then_preserve_count_and_report_unknown()
{
    let clock = buffered_writes::TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let elapsed_clock = clock.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |_: WriteAttempt<u32>| {
        elapsed_clock.advance(Duration::from_secs(1));
        std::future::pending::<Result<(), SinkError>>()
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_clock(clock)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    let report = writer.shutdown(Duration::from_millis(100)).await;
    assert!(report.state_unknown);
    assert_eq!(report.unresolved_items, 1);
    assert_eq!(report.volatile_unresolved_items, 1);
    assert!(!report.completed_before_deadline);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_inspection_failure_when_shutdown_runs_then_never_report_clean_shutdown() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    writer.add_write_item(1).await.unwrap();
    buffer.fault.store(1, Ordering::SeqCst);
    let report = writer.shutdown(Duration::from_millis(30)).await;
    assert!(
        !report.is_clean(),
        "failed inspection cannot prove the buffer is empty: {report:?}"
    );
}

#[tokio::test]
async fn given_hung_inspection_when_shutdown_runs_then_return_before_host_deadline() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    writer.add_write_item(1).await.unwrap();
    buffer.fault.store(2, Ordering::SeqCst);
    let report = tokio::time::timeout(
        Duration::from_millis(100),
        writer.shutdown(Duration::from_millis(30)),
    )
    .await
    .expect("shutdown must bound provider inspection");
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_inspection_failure_when_flush_hooks_run_then_report_failure() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    writer.add_write_item(1).await.unwrap();
    buffer.fault.store(1, Ordering::SeqCst);
    assert!(writer.after_response().await.has_failures());
    assert!(writer.flush_writes().await.has_failures());
}

#[tokio::test]
async fn given_provider_mutation_failure_when_flushed_then_report_error_and_preserve_ownership() {
    for fault in 3..=5 {
        let buffer = InspectFault::default();
        let writer = writer(buffer.clone());
        writer.add_write_item(1).await.unwrap();
        buffer.fault.store(fault, Ordering::SeqCst);
        let report = writer.flush_writes().await;
        assert!(
            report.has_failures(),
            "provider mutation {fault} was hidden"
        );
        assert_eq!(report.items_settled, 0);
        assert_eq!(report.batches_flushed, 0);
        assert!(report.buffer_error.is_some());
    }
}

#[tokio::test]
async fn given_partial_completion_when_settlement_fails_then_never_report_delivery() {
    let buffer = InspectFault::default();
    let sink = buffered_writes::PartialSink::try_new(
        SinkLimits::default(),
        |attempt: WriteAttempt<u32>| async move {
            Ok::<_, SinkError>(buffered_writes::WriteOutcome::Partial(
                attempt
                    .pending_operation_ids()
                    .iter()
                    .cloned()
                    .map(|id| (id, buffered_writes::OperationStatus::Completed))
                    .collect(),
            ))
        },
    )
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer.clone())
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    buffer.fault.store(5, Ordering::SeqCst);
    let report = writer.flush_writes().await;
    assert!(report.has_failures());
    assert_eq!(report.batches_flushed, 0);
    assert_eq!(report.items_settled, 0);
}

#[tokio::test]
async fn given_pending_admission_when_shutdown_runs_then_never_construct_after_clean_drain() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    buffer.fault.store(6, Ordering::SeqCst);
    let admitted = writer.clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let admission = tokio::spawn(async move {
        admitted
            .add_write_item_with(|| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(1)
            })
            .await
    });
    buffer.entered.notified().await;
    let report = writer.shutdown(Duration::from_millis(30)).await;
    buffer.resume.notify_one();
    let admission = admission.await.unwrap();
    assert!(
        admission.is_err(),
        "admission completed after shutdown: {admission:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        !report.is_clean(),
        "pending admission was omitted from drain ownership"
    );
}

#[tokio::test]
async fn given_unknown_append_when_empty_buffer_drains_then_report_unknown_ownership() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    buffer.fault.store(7, Ordering::SeqCst);
    let result = writer
        .add_write_item_with_options(
            1,
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(20)),
        )
        .await;
    assert!(matches!(
        result,
        Err(buffered_writes::WriteError::Ambiguous { .. })
    ));
    buffer.fault.store(0, Ordering::SeqCst);
    let report = writer.shutdown(Duration::from_millis(100)).await;
    assert!(report.state_unknown);
    assert_eq!(report.unresolved_admissions.len(), 1);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_cancelled_append_when_shutdown_runs_then_keep_unknown_ownership() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    buffer.fault.store(7, Ordering::SeqCst);
    let admitted = writer.clone();
    let admission = tokio::spawn(async move { admitted.add_write_item(1).await });
    buffer.entered.notified().await;
    admission.abort();
    assert!(admission.await.unwrap_err().is_cancelled());
    buffer.fault.store(0, Ordering::SeqCst);
    let report = writer.shutdown(Duration::from_millis(100)).await;
    assert!(report.state_unknown);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_committed_append_with_lost_ack_when_shutdown_reconciles_then_drain_and_report_clean()
{
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    buffer.fault.store(8, Ordering::SeqCst);
    let result = writer
        .add_write_item_with_options(
            1,
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(20)),
        )
        .await;
    assert!(matches!(
        result,
        Err(buffered_writes::WriteError::Ambiguous { .. })
    ));
    buffer.fault.store(0, Ordering::SeqCst);
    let report = writer.shutdown(Duration::from_millis(100)).await;
    assert!(!report.state_unknown);
    assert_eq!(report.items_settled, 1);
    assert!(report.is_clean());
}

#[tokio::test]
async fn given_unknown_append_at_capacity_when_retried_then_reserve_identity_and_reconcile() {
    let buffer = InspectFault::default();
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(buffered_writes::BufferCapacity::default().max_items(1))
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    buffer.fault.store(7, Ordering::SeqCst);
    let error = writer
        .add_write_item_with_options(
            1,
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(20)),
        )
        .await
        .unwrap_err();
    let id = error.operation_id().unwrap().clone();
    buffer.fault.store(0, Ordering::SeqCst);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let rejected = writer
        .add_write_item_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(2)
        })
        .await;
    assert!(matches!(rejected, Err(buffered_writes::WriteError::Full)));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    writer
        .add_write_item_with_options(
            1,
            buffered_writes::WriteOptions::new().with_operation_id(id),
        )
        .await
        .unwrap();
    assert!(writer.shutdown(Duration::from_millis(100)).await.is_clean());
}

#[tokio::test]
async fn given_unknown_append_at_byte_capacity_when_retried_then_reuse_credit_and_skip_new_factory()
{
    let buffer = InspectFault::default();
    let sink = AtomicSink::try_new(
        SinkLimits::try_new(1, 1000).unwrap(),
        |_: WriteAttempt<u32>| async { Ok::<(), SinkError>(()) },
    )
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(buffered_writes::BufferCapacity::default().max_bytes(1800))
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .prepare_with("packed/v1", |batch| {
            buffered_writes::PreparedWrites::packed(&batch, &"x".repeat(400))
        })
        .build()
        .unwrap();
    buffer.fault.store(7, Ordering::SeqCst);
    let error = writer
        .add_write_item_with_options(
            1,
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(20)),
        )
        .await
        .unwrap_err();
    let id = error.operation_id().unwrap().clone();
    assert!(matches!(
        error,
        buffered_writes::WriteError::Ambiguous { .. }
    ));
    buffer.fault.store(0, Ordering::SeqCst);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let rejected = writer
        .add_write_item_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(2)
        })
        .await;
    assert!(
        matches!(rejected, Err(buffered_writes::WriteError::Full)),
        "{rejected:?}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let options = buffered_writes::WriteOptions::new().with_operation_id(id);
    assert!(matches!(
        writer.add_write_item_with_options(2, options.clone()).await,
        Err(buffered_writes::WriteError::IdentityConflict { .. })
    ));
    let other_scope = options
        .clone()
        .with_scope(buffered_writes::TenantScope::try_from("other").unwrap());
    assert!(matches!(
        writer.add_write_item_with_options(1, other_scope).await,
        Err(buffered_writes::WriteError::IdentityConflict { .. })
    ));
    assert_eq!(buffer.appends.load(Ordering::SeqCst), 1);
    writer
        .add_write_item_with_options(1, options)
        .await
        .unwrap();
    let report = writer.shutdown(Duration::from_millis(100)).await;
    assert!(!report.state_unknown);
    assert!(report.is_clean());
}

#[tokio::test]
async fn given_busy_staging_when_waiters_expire_or_cancel_then_skip_factories_and_release_permits()
{
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    buffer.fault.store(7, Ordering::SeqCst);
    let id = buffered_writes::OperationId::generate_v7();
    let options = buffered_writes::WriteOptions::new().with_operation_id(id);
    let admitted = writer.clone();
    let original = options.clone();
    let first =
        tokio::spawn(async move { admitted.add_write_item_with_options(1, original).await });
    buffer.entered.notified().await;
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let expired = writer
        .add_write_item_with_and_options(
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            },
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(20)),
        )
        .await;
    assert!(matches!(
        expired,
        Err(buffered_writes::WriteError::DeadlineExceeded {
            accepted: false,
            ..
        })
    ));
    let cancelled = tokio::time::timeout(
        Duration::from_millis(20),
        writer.add_write_item_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(3)
        }),
    )
    .await;
    assert!(cancelled.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(buffer.appends.load(Ordering::SeqCst), 1);
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    buffer.fault.store(0, Ordering::SeqCst);
    writer
        .add_write_item_with_options(1, options)
        .await
        .unwrap();
    writer.add_write_item(4).await.unwrap();
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
}

#[tokio::test]
async fn given_pending_inspection_when_admission_deadline_expires_then_report_known_rejection() {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    buffer.fault.store(2, Ordering::SeqCst);
    let result = writer
        .add_write_item_with_options(
            1,
            buffered_writes::WriteOptions::new().with_deadline(Duration::from_millis(20)),
        )
        .await;
    assert!(
        matches!(
            result,
            Err(buffered_writes::WriteError::DeadlineExceeded {
                accepted: false,
                ..
            })
        ),
        "{result:?}"
    );
    buffer.fault.store(0, Ordering::SeqCst);
    assert!(writer.shutdown(Duration::from_millis(100)).await.is_clean());
}

#[tokio::test]
async fn given_stale_empty_inspection_when_another_admission_fills_capacity_then_skip_unreserved_factory()
 {
    let buffer = InspectFault::default();
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(buffered_writes::BufferCapacity::default().max_items(1))
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    buffer.fault.store(6, Ordering::SeqCst);
    let paused_writer = writer.clone();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = calls.clone();
    let paused = tokio::spawn(async move {
        paused_writer
            .add_write_item_with(|| {
                observed.fetch_add(1, Ordering::SeqCst);
                Ok(2)
            })
            .await
    });
    buffer.entered.notified().await;
    let competing = writer.add_write_item(1).await;
    buffer.resume.notify_one();
    let paused = paused.await.unwrap();
    if competing.is_ok() {
        assert!(matches!(paused, Err(buffered_writes::WriteError::Full)));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "stale inspection allowed construction above capacity"
        );
    } else {
        assert!(matches!(competing, Err(buffered_writes::WriteError::Full)));
        assert!(paused.is_ok());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn given_backend_full_after_preflight_when_waiting_then_retry_without_recreating_item() {
    let buffer = InspectFault::default();
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer.clone())
        .buffer_capacity(
            buffered_writes::BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .flush_policy(|_: &buffered_writes::BufferStats| false)
        .build()
        .unwrap();
    buffer.fault.store(9, Ordering::SeqCst);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    writer
        .add_write_item_with(|| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(1)
        })
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(buffer.appends.load(Ordering::SeqCst), 2);
    assert!(writer.shutdown(Duration::from_millis(100)).await.is_clean());
}

#[tokio::test]
async fn given_admission_slots_are_busy_when_another_waiter_arrives_then_reject_without_queueing() {
    let provider = InspectFault::default();
    provider.fault.store(6, Ordering::SeqCst);
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Ok::<(), SinkError>(())
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(provider.clone())
        .buffer_capacity(
            buffered_writes::BufferCapacity::default()
                .max_items(1)
                .backpressure(buffered_writes::BackpressurePolicy::WaitUntilDeadline),
        )
        .build()
        .unwrap();
    let first_writer = writer.clone();
    let first = tokio::spawn(async move { first_writer.add_write_item(1).await });
    provider.entered.notified().await;
    let extra = tokio::time::timeout(Duration::from_millis(20), writer.add_write_item(2)).await;
    assert!(
        matches!(extra, Ok(Err(buffered_writes::WriteError::Full))),
        "excess admission allocated a waiter"
    );
    provider.resume.notify_one();
    first.await.unwrap().unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    writer.add_write_item(3).await.unwrap();
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
}

#[tokio::test]
async fn given_lost_conflict_response_when_an_old_receipt_exists_then_never_confirm_different_bytes()
 {
    let buffer = InspectFault::default();
    let writer = writer(buffer.clone());
    let id = buffered_writes::OperationId::generate_v7();
    let options = buffered_writes::WriteOptions::new().with_operation_id(id.clone());
    writer
        .add_write_item_with_options(0, options.clone())
        .await
        .unwrap();
    assert_eq!(writer.flush_writes().await.items_settled, 1);
    buffer.fault.store(8, Ordering::SeqCst);
    let result = writer
        .add_write_item_with_options(1, options.with_deadline(Duration::from_millis(20)))
        .await;
    assert!(matches!(
        result,
        Err(buffered_writes::WriteError::Ambiguous { .. })
    ));
    buffer.fault.store(0, Ordering::SeqCst);
    let report = writer.shutdown(Duration::from_millis(100)).await;
    assert!(
        report.state_unknown,
        "an ID-only receipt does not confirm different data: {report:?}"
    );
    assert_eq!(report.unresolved_admissions, vec![id]);
    assert!(!report.is_clean());
}

#[tokio::test]
async fn given_response_snapshot_when_new_item_arrives_then_do_not_extend_response_watermark() {
    let provider = InspectFault::default();
    let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = delivered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        observed.lock().unwrap().extend_from_slice(attempt.items());
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(provider.clone())
        .flush_policy(|_: &buffered_writes::BufferStats| true)
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    provider.fault.store(6, Ordering::SeqCst);
    let response_writer = writer.clone();
    let response = tokio::spawn(async move { response_writer.after_response().await });
    provider.entered.notified().await;
    writer.add_write_item(2).await.unwrap();
    provider.resume.notify_one();
    assert_eq!(response.await.unwrap().items_settled, 1);
    assert_eq!(*delivered.lock().unwrap(), [1]);
    assert_eq!(writer.after_response().await.items_settled, 1);
    assert_eq!(*delivered.lock().unwrap(), [1, 2]);
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn given_background_snapshot_when_threshold_arrivals_race_then_deliver_all_without_another_event()
 {
    let provider = InspectFault::default();
    let clock = buffered_writes::TestClock::new();
    clock.set_auto_advance_on_sleep(false);
    let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = delivered.clone();
    let sink = AtomicSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u32>| {
        observed.lock().unwrap().extend_from_slice(attempt.items());
        async { Ok::<(), SinkError>(()) }
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_clock(clock.clone())
        .with_buffer_provider(provider.clone())
        .build()
        .unwrap();
    writer.add_write_item(0).await.unwrap();
    provider.fault.store(6, Ordering::SeqCst);
    let guard = writer
        .start(buffered_writes::Lifecycle::tokio())
        .await
        .unwrap();
    provider.entered.notified().await;
    for item in 1..25 {
        writer.add_write_item(item).await.unwrap();
    }
    provider.resume.notify_one();
    tokio::time::timeout(Duration::from_millis(100), async {
        while delivered.lock().unwrap().len() < 25 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a threshold notification cannot strand young writes above a response watermark");
    assert_eq!(*delivered.lock().unwrap(), (0..25).collect::<Vec<_>>());
    assert!(writer.shutdown(Duration::from_secs(1)).await.is_clean());
    assert!(!guard.is_active());
}

#[tokio::test]
async fn given_confirmed_queue_publish_when_buffer_settlement_ack_is_lost_then_never_issue_another_mutation()
 {
    let buffer = InspectFault::default();
    let clock = buffered_writes::TestClock::new();
    let queue = buffered_writes::InMemoryQueue::default();
    let sink = AtomicSink::try_new(SinkLimits::default(), |_: WriteAttempt<u32>| async {
        Err::<(), _>(SinkError::retryable("outage"))
    })
    .unwrap();
    let writer = BufferedWrites::builder("provider-errors/v1", sink)
        .with_buffer_provider(buffer.clone())
        .with_clock(clock.clone())
        .fallback(buffered_writes::QueueConfig::custom(queue.clone()))
        .build()
        .unwrap();
    writer.add_write_item(1).await.unwrap();
    clock.advance(Duration::from_secs(31));
    buffer.fault.store(10, Ordering::SeqCst);
    let report = writer.flush_writes().await;
    assert!(report.has_failures());
    assert!(report.buffer_error.is_some());
    assert_eq!(report.items_settled, 0);
    assert_eq!(report.batches_queued, 0);
    assert_eq!(queue.queued_len(), 1);
    assert_eq!(
        buffer.settlements.load(Ordering::SeqCst),
        1,
        "unknown settlement forbids a follow-up release mutation"
    );
    let deadline = buffered_writes::Deadline::from_anchor(
        buffered_writes::Clock::now_instant(&clock),
        Duration::from_secs(1),
    );
    assert!(
        writer.shutdown(deadline).await.is_clean(),
        "inspection can reconcile the committed handoff"
    );
    assert_eq!(buffer.settlements.load(Ordering::SeqCst), 1);
}
