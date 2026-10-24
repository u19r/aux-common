use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::{
    budget::{DriveRequestInput, QueueSelection},
    model::{ExecutionContext, HandlerDefinition, HandlerFuture},
    test_helper::{block_on, low_volume_job, one},
    *,
};

struct FailsAfterEffect {
    calls: Arc<AtomicUsize>,
}

impl JobHandler for FailsAfterEffect {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async { Err("effect committed, completion lost".into()) })
    }
}

fn handler_system(
    store: FakeStore,
    handler: impl JobHandler + 'static,
    policy: FairnessPolicy,
) -> JobSystem<FakeStore> {
    handler_system_with_scheduler(store, handler, policy, crate::test_helper::wake_scheduler())
}

fn handler_system_with_scheduler(
    store: FakeStore,
    handler: impl JobHandler + 'static,
    policy: FairnessPolicy,
    scheduler: Arc<dyn WakeScheduler>,
) -> JobSystem<FakeStore> {
    let mut registry = HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind: JobKind::try_new("email").expect("kind is valid"),
            schema_version: std::num::NonZeroU16::new(1).expect("schema is non-zero"),
            queue: QueueName::try_new("default").expect("queue is valid"),
            effect_mode: EffectMode::AtLeastOnce,
            cost_units: std::num::NonZeroU16::new(1).expect("cost is non-zero"),
            fairness_policy: policy,
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout: Duration::from_secs(1),
            handler,
        })
        .expect("registration is valid");
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").expect("namespace is valid"),
        OwnerId::from([1; 16]),
        scheduler,
    )
}

fn drive_request() -> DriveRequest {
    drive_request_with_store_operations(64)
}

fn drive_request_with_store_operations(max_store_operations: u32) -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: std::num::NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).expect("payload budget"),
        max_completion_details: 1,
        max_store_operations: one(max_store_operations),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid")
}

#[test]
fn given_a_crash_after_the_effect_when_drive_reconciles_then_the_effect_is_not_replayed_in_this_attempt()
 {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = handler_system(
        store,
        FailsAfterEffect {
            calls: calls.clone(),
        },
        FairnessPolicy::low_volume(),
    );
    block_on(system.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let report =
        block_on(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive succeeds");
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert_eq!(report.counts.retried, 1);
}

struct CompletesAfterLeaseExpiry {
    nanos: Arc<AtomicU64>,
}

impl JobHandler for CompletesAfterLeaseExpiry {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async {
            self.nanos.store(2_000_000_000, Ordering::SeqCst);
            Ok(JobOutcome::Complete(OutcomeCode::try_new("completed")?))
        })
    }
}

#[test]
fn given_a_handler_that_outlives_its_lease_when_drive_finishes_then_completion_is_not_committed() {
    let store = FakeStore::local();
    let nanos = Arc::new(AtomicU64::new(0));
    let system = handler_system(
        store.clone(),
        CompletesAfterLeaseExpiry {
            nanos: Arc::clone(&nanos),
        },
        FairnessPolicy::low_volume(),
    );
    block_on(system.enqueue_raw(low_volume_job(96, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let report = block_on(system.drive(drive_request(), Timestamp::ZERO, move || {
        MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
    }))
    .expect("drive finishes at the lease deadline");
    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
    assert_eq!(report.counts.succeeded, 0);
    assert!(report.completions.is_empty());
    let encoded =
        block_on(store.get(
            crate::keys::job_key(system.namespace(), &JobId::from([96; 16])).expect("job key"),
        ))
        .expect("job read succeeds")
        .expect("job remains available for lease recovery");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert!(matches!(record.state, JobState::Leased(_)));
}

struct AdvancesWallClock {
    nanos: Arc<AtomicU64>,
    calls: Arc<AtomicUsize>,
}

impl JobHandler for AdvancesWallClock {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.nanos.store(10_000_000, Ordering::SeqCst);
            Ok(JobOutcome::Complete(OutcomeCode::try_new("completed")?))
        })
    }
}

fn advancing_fixture() -> (JobSystem<FakeStore>, Arc<AtomicU64>, Arc<AtomicUsize>) {
    let nanos = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let system = handler_system(
        FakeStore::local(),
        AdvancesWallClock {
            nanos: Arc::clone(&nanos),
            calls: Arc::clone(&calls),
        },
        FairnessPolicy::from(std::num::NonZeroU16::new(1).expect("cost")),
    );
    for (index, due) in [(101, Timestamp::ZERO), (102, Timestamp::from_millis(5))] {
        let mut job = low_volume_job(index, due);
        job.fairness = FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new([index]).expect("scope"),
            None,
        ));
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue commits");
    }
    (system, nanos, calls)
}

fn advancing_request(claims: u32) -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(claims),
        max_concurrency: std::num::NonZeroU16::new(1).expect("concurrency"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).expect("payload"),
        max_completion_details: claims,
        max_store_operations: one(128),
        stop_claiming_at: MonotonicDeadline::from_nanos(100_000_000),
        finish_by: MonotonicDeadline::from_nanos(200_000_000),
    })
    .expect("bounded request")
}

#[test]
fn given_work_becomes_due_during_a_handler_when_driving_then_the_same_drive_executes_it() {
    let (system, nanos, calls) = advancing_fixture();
    let report = block_on(
        system.drive(advancing_request(2), Timestamp::ZERO, move || {
            MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
        }),
    )
    .expect("drive succeeds");
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(report.counts.succeeded, 2);
    assert_eq!(report.next_wake, WakeHint::None);
    assert!(!report.has_immediately_visible_work);
    assert!(
        report
            .completions
            .iter()
            .all(|completion| completion.completed_at == Timestamp::from_millis(10))
    );
}

#[test]
fn given_work_becomes_due_at_the_claim_limit_when_driving_then_the_wake_is_immediate() {
    let (system, nanos, calls) = advancing_fixture();
    let report = block_on(
        system.drive(advancing_request(1), Timestamp::ZERO, move || {
            MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
        }),
    )
    .expect("drive succeeds");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(report.next_wake, WakeHint::Now);
    assert!(report.has_immediately_visible_work);
}

#[test]
fn given_a_handler_exceeds_the_drive_deadline_when_driving_again_then_the_live_lease_sets_the_wake()
{
    let nanos = Arc::new(AtomicU64::new(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let system = handler_system(
        FakeStore::local(),
        AdvancesWallClock {
            nanos: Arc::clone(&nanos),
            calls: Arc::clone(&calls),
        },
        FairnessPolicy::low_volume(),
    );
    block_on(system.enqueue_raw(low_volume_job(103, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: std::num::NonZeroU16::MIN,
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).expect("payload"),
        max_completion_details: 1,
        max_store_operations: one(128),
        stop_claiming_at: MonotonicDeadline::from_nanos(3_000_000),
        finish_by: MonotonicDeadline::from_nanos(5_000_000),
    })
    .expect("bounded request");
    let first = block_on(system.drive(request, Timestamp::ZERO, || {
        MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
    }))
    .expect("drive stops at its deadline");
    assert_eq!(first.stop_reason, DriveStopReason::Deadline);
    let second = block_on(
        system.drive(advancing_request(1), Timestamp::from_millis(10), || {
            MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
        }),
    )
    .expect("drive observes the live lease");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.counts.claimed, 0);
    assert_eq!(second.next_wake, WakeHint::At(Timestamp::from_millis(1000)));
    assert!(!second.has_immediately_visible_work);
}

#[test]
fn given_a_cancelled_worker_disappears_when_driving_after_expiry_then_no_effect_is_replayed() {
    let calls = Arc::new(AtomicUsize::new(0));
    let system = handler_system(
        FakeStore::local(),
        AdvancesWallClock {
            nanos: Arc::new(AtomicU64::new(0)),
            calls: Arc::clone(&calls),
        },
        FairnessPolicy::low_volume(),
    );
    let id = JobId::from([104; 16]);
    block_on(system.enqueue_raw(low_volume_job(104, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancellation commits");
    drop(claim);
    let report = block_on(
        system.drive(advancing_request(1), Timestamp::from_millis(1001), || {
            MonotonicDeadline::ZERO
        }),
    )
    .expect("drive recovers the expired lease");
    assert_eq!(report.counts.cancelled, 1);
    assert_eq!(report.next_wake, WakeHint::None);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn given_exhausted_expired_lease_when_driving_then_terminal_recovery_unblocks_waiting_work() {
    for (fairness, policy) in [
        (FairnessClass::low_volume(), FairnessPolicy::low_volume()),
        (
            crate::test_helper::scoped_fairness(),
            FairnessPolicy::from(std::num::NonZeroU16::MIN),
        ),
    ] {
        let store = FakeStore::distributed();
        let system = crate::test_helper::system(store.clone(), policy, 1);
        let mut exhausted = crate::test_helper::job(
            71,
            bytes::Bytes::from_static(b"exhausted"),
            fairness.clone(),
            Timestamp::ZERO,
            None,
            None,
        );
        exhausted.retry_override = Some(RetrySelection::Custom(
            RetryPolicy::try_from(RetryPolicyInput {
                maximum_attempts: std::num::NonZeroU16::MIN,
                maximum_age: Duration::from_secs(60),
                minimum_backoff: Duration::from_millis(1),
                maximum_backoff: Duration::from_millis(1),
                multiplier: BackoffMultiplier::try_from(2).unwrap(),
            })
            .unwrap(),
        ));
        let exhausted_id = exhausted.job_id;
        block_on(system.enqueue_raw(exhausted, Timestamp::ZERO)).expect("enqueue exhausted job");
        let stale =
            block_on(system.claim(exhausted_id, Timestamp::ZERO)).expect("last allowed attempt");
        let waiting = crate::test_helper::job(
            72,
            bytes::Bytes::from_static(b"waiting"),
            fairness,
            Timestamp::ZERO,
            None,
            None,
        );
        block_on(system.enqueue_raw(waiting, Timestamp::ZERO)).expect("enqueue waiting job");
        let now = Timestamp::from_millis(1_000);
        let live = block_on(
            system.drive(drive_request(), Timestamp::from_millis(999), || {
                MonotonicDeadline::ZERO
            }),
        )
        .unwrap();
        assert_eq!(
            live.counts.dead_lettered, 0,
            "last attempt retains authority until expiry"
        );
        let recovered =
            block_on(system.drive(drive_request(), now, || MonotonicDeadline::ZERO)).unwrap();
        assert_eq!(
            recovered.counts.dead_lettered, 1,
            "exhaustion must terminate rather than conflict: {recovered:?}"
        );
        assert_eq!(recovered.counts.lease_conflicts, 0);
        assert!(matches!(
            block_on(system.complete(stale, crate::test_helper::completion(), now)),
            Err(JobSystemError::LeaseLost)
        ));
        let key = crate::keys::job_key(system.namespace(), &exhausted_id).unwrap();
        let record =
            crate::codec::decode_job_record(&block_on(store.get(key)).unwrap().unwrap()).unwrap();
        assert!(matches!(record.state, JobState::DeadLettered));
        assert_eq!(
            record.attempts.unwrap().last_outcome.unwrap().as_str(),
            "attempts_exhausted"
        );
        // Low-volume work can run concurrently with a live lease, while scoped
        // work waits.
        if live.counts.succeeded == 0 {
            let resumed =
                block_on(system.drive(drive_request(), now, || MonotonicDeadline::ZERO)).unwrap();
            assert_eq!(
                resumed.counts.succeeded, 1,
                "terminal recovery releases capacity"
            );
        }
    }
}

#[derive(Default)]
struct DiagnosticCollector(std::sync::Mutex<Vec<JobEvent>>);

impl JobObserver for DiagnosticCollector {
    fn observe(&self, event: JobEvent) {
        self.0.lock().expect("event lock").push(event);
    }
}

struct MeasuredContinuation(Arc<AtomicU64>);

impl JobHandler for MeasuredContinuation {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async {
            self.0.store(10_000_000, Ordering::SeqCst);
            Ok(JobOutcome::Continue {
                not_before: Timestamp::from_millis(1000),
                checkpoint: bytes::Bytes::new(),
            })
        })
    }
}

#[test]
fn given_an_overdue_job_when_continued_then_delay_duration_and_store_accounting_are_observed() {
    let nanos = Arc::new(AtomicU64::new(0));
    let collector = Arc::new(DiagnosticCollector::default());
    let system = handler_system(
        FakeStore::local(),
        MeasuredContinuation(nanos.clone()),
        FairnessPolicy::low_volume(),
    )
    .with_observer(collector.clone());
    block_on(system.enqueue_raw(low_volume_job(221, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue");
    collector.0.lock().expect("lock").clear();
    let report = block_on(
        system.drive(drive_request(), Timestamp::from_millis(500), || {
            MonotonicDeadline::from_nanos(nanos.load(Ordering::SeqCst))
        }),
    )
    .expect("drive");
    assert_eq!(report.counts.continued, 1);
    let events = collector.0.lock().expect("lock");
    assert!(events.iter().any(|event| matches!(event, JobEvent::AttemptStarted { kind, due_delay, .. } if kind.as_str() == "email" && *due_delay == Duration::from_millis(500))));
    assert!(events.iter().any(|event| matches!(event, JobEvent::AttemptFinished { kind, duration, .. } if kind.as_str() == "email" && *duration == Duration::from_millis(10))));
    assert!(events.iter().any(
        |event| matches!(event, JobEvent::Continued { kind, .. } if kind.as_str() == "email")
    ));
    let reserved: u32 = events
        .iter()
        .filter_map(|event| match event {
            JobEvent::StoreOperationsReserved { operations } => Some(*operations),
            _ => None,
        })
        .sum();
    let actual = events
        .iter()
        .filter(|event| matches!(event, JobEvent::StoreOperation { .. }))
        .count();
    assert!(actual > 0);
    assert!(
        reserved >= actual as u32,
        "worst-case reservations bound actual calls"
    );
}

#[test]
fn given_a_future_job_when_driven_then_no_attempt_is_observed() {
    let collector = Arc::new(DiagnosticCollector::default());
    let system = handler_system(
        FakeStore::local(),
        MeasuredContinuation(Arc::new(AtomicU64::new(0))),
        FairnessPolicy::low_volume(),
    )
    .with_observer(collector.clone());
    block_on(system.enqueue_raw(
        low_volume_job(222, Timestamp::from_millis(1000)),
        Timestamp::ZERO,
    ))
    .expect("enqueue");
    let report =
        block_on(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive");
    assert_eq!(report.counts.claimed, 0);
    assert!(
        !collector
            .0
            .lock()
            .expect("lock")
            .iter()
            .any(|event| matches!(
                event,
                JobEvent::AttemptStarted { .. } | JobEvent::AttemptFinished { .. }
            ))
    );
}

#[test]
fn given_a_store_budget_too_small_for_claims_when_driven_then_binding_resource_is_observed() {
    let collector = Arc::new(DiagnosticCollector::default());
    let system = handler_system(
        FakeStore::local(),
        MeasuredContinuation(Arc::new(AtomicU64::new(0))),
        FairnessPolicy::low_volume(),
    )
    .with_observer(collector.clone());
    block_on(system.enqueue_raw(low_volume_job(223, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue");
    let report = block_on(system.drive(
        drive_request_with_store_operations(1),
        Timestamp::ZERO,
        || MonotonicDeadline::ZERO,
    ))
    .expect("drive");
    assert_eq!(report.counts.claimed, 0);
    assert!(
        collector
            .0
            .lock()
            .expect("lock")
            .iter()
            .any(|event| matches!(
                event,
                JobEvent::CapacityLimited {
                    resource: crate::observer::CapacityResource::StoreOperations
                }
            ))
    );
}

struct PendingDiagnosticHandler;

impl JobHandler for PendingDiagnosticHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(std::future::pending())
    }
}

struct PendingDiagnosticScheduler;

impl WakeScheduler for PendingDiagnosticScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        Ok(Box::pin(std::future::pending()))
    }
}

#[test]
fn given_a_pending_attempt_when_drive_is_dropped_then_attempt_observations_remain_balanced() {
    let collector = Arc::new(DiagnosticCollector::default());
    let system = handler_system_with_scheduler(
        FakeStore::local(),
        PendingDiagnosticHandler,
        FairnessPolicy::low_volume(),
        Arc::new(PendingDiagnosticScheduler),
    )
    .with_observer(collector.clone());
    block_on(system.enqueue_raw(low_volume_job(224, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue");
    let mut drive =
        Box::pin(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(drive.as_mut(), &mut context).is_pending());
    assert_eq!(
        collector
            .0
            .lock()
            .expect("lock")
            .iter()
            .filter(|event| matches!(event, JobEvent::AttemptStarted { .. }))
            .count(),
        1
    );
    drop(drive);
    let events = collector.0.lock().expect("lock");
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, JobEvent::AttemptFinished { .. }))
            .count(),
        1
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, JobEvent::Completed { .. }))
    );
}
