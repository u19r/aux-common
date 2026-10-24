use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bg_jobs::{
    DriveBudget, DriveBudgetInput, DriveReport, DriveStopReason, EffectMode, EnqueueOptions,
    ExecutionContext, FairnessClass, FairnessPolicy, HandlerFuture, JobCatalog, JobHandler, JobId,
    JobKind, JobOutcome, JobSpec, JobSystemError, Namespace, OwnerId, QueueName, QueueSelection,
    RetryPreset, RetrySelection, Timestamp, ValidationError,
    runtime::{MonotonicDeadline, WakeFuture, WakeScheduler, WakeSchedulerError},
    test_support::FakeStore,
};

use crate::{
    JobRuntime, WaitOutcome,
    test_support::{JobClock, TestClock, TestProfile},
};

fn profile() -> DriveBudget {
    DriveBudget::try_from(DriveBudgetInput {
        queues: QueueSelection::all(),
        max_claims: 1,
        max_concurrency: 1,
        max_store_operations: 8,
        stop_claiming_after: Duration::from_millis(1),
        finish_after: Duration::from_millis(2),
    })
    .expect("profile is valid")
}

#[tokio::test]
async fn given_runtime_inputs_when_building_then_scheduler_and_clock_are_hidden() {
    let scheduler = TestProfile::new();
    let runtime =
        crate::test_support::runtime_builder(FakeStore::local(), JobCatalog::new(), profile())
            .namespace(Namespace::try_new(b"jobs").expect("namespace"))
            .owner(OwnerId::from([1; OwnerId::BYTE_LENGTH]))
            .scheduler(Arc::new(scheduler))
            .clock(Arc::new(TestClock::new(
                Timestamp::ZERO,
                MonotonicDeadline::ZERO,
            )))
            .build()
            .expect("runtime builds");

    assert_eq!(runtime.wall_now(), Timestamp::ZERO);
}

#[tokio::test]
async fn given_virtual_time_when_driving_then_deadlines_are_derived_inside_runtime() {
    let scheduler = TestProfile::new();
    let runtime =
        crate::test_support::runtime_builder(FakeStore::local(), JobCatalog::new(), profile())
            .namespace(Namespace::try_new(b"jobs").expect("namespace"))
            .owner(OwnerId::from([2; OwnerId::BYTE_LENGTH]))
            .scheduler(Arc::new(scheduler))
            .clock(Arc::new(TestClock::new(
                Timestamp::from_millis(10),
                MonotonicDeadline::from_nanos(10),
            )))
            .build()
            .expect("runtime builds");

    let report = runtime.drive_once().await.expect("drive succeeds");

    assert!(!report.has_immediately_visible_work);
}

#[derive(Clone, Default)]
struct RecordingScheduler {
    delays: Arc<Mutex<Vec<Duration>>>,
}

impl WakeScheduler for RecordingScheduler {
    fn sleep(&self, delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        self.delays
            .lock()
            .expect("recording scheduler lock")
            .push(delay);
        Ok(Box::pin(std::future::ready(())))
    }
}

struct ErrorScheduler;

impl WakeScheduler for ErrorScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        Err(WakeSchedulerError::Unavailable)
    }
}

#[derive(Clone, Default)]
struct PendingScheduler {
    entered: Arc<tokio::sync::Notify>,
}

impl WakeScheduler for PendingScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        self.entered.notify_one();
        Ok(Box::pin(std::future::pending()))
    }
}

fn runtime_with(
    scheduler: Arc<dyn WakeScheduler>,
    clock: Arc<dyn JobClock>,
) -> JobRuntime<FakeStore> {
    crate::test_support::runtime_builder(FakeStore::local(), JobCatalog::new(), profile())
        .namespace(Namespace::try_new(b"jobs").expect("namespace"))
        .owner(OwnerId::from([9; OwnerId::BYTE_LENGTH]))
        .scheduler(scheduler)
        .clock(clock)
        .build()
        .expect("runtime builds")
}

fn report(next_wake: bg_jobs::WakeHint) -> DriveReport {
    DriveReport {
        counts: Default::default(),
        completions: Vec::new(),
        completions_omitted: 0,
        has_immediately_visible_work: false,
        next_wake,
        stop_reason: DriveStopReason::NoVisibleWork,
    }
}

#[tokio::test]
async fn given_wake_hints_when_waiting_then_the_earliest_hint_is_scheduled() {
    let scheduler = RecordingScheduler::default();
    let delays = Arc::clone(&scheduler.delays);
    let runtime = runtime_with(
        Arc::new(scheduler),
        Arc::new(TestClock::new(
            Timestamp::from_millis(1_000),
            MonotonicDeadline::ZERO,
        )),
    );

    assert_eq!(
        runtime.wake_delay(&report(bg_jobs::WakeHint::Now), bg_jobs::WakeHint::None),
        Duration::from_millis(1)
    );
    assert_eq!(
        runtime.wake_delay(&report(bg_jobs::WakeHint::None), bg_jobs::WakeHint::None,),
        Duration::from_millis(500)
    );
    assert_eq!(
        runtime.wake_delay(
            &report(bg_jobs::WakeHint::At(Timestamp::from_millis(5_000))),
            bg_jobs::WakeHint::At(Timestamp::from_millis(2_500)),
        ),
        Duration::from_millis(500)
    );
    assert_eq!(
        runtime.wake_delay(
            &report(bg_jobs::WakeHint::At(Timestamp::from_millis(1_100))),
            bg_jobs::WakeHint::None,
        ),
        Duration::from_millis(100)
    );

    runtime
        .wait_for(
            &report(bg_jobs::WakeHint::At(Timestamp::from_millis(5_000))),
            bg_jobs::WakeHint::At(Timestamp::from_millis(2_500)),
        )
        .await
        .expect("recording scheduler wakes");
    assert_eq!(
        delays.lock().expect("recording scheduler lock").as_slice(),
        [Duration::from_millis(500)]
    );
}

#[tokio::test]
async fn given_a_distant_durable_wake_when_waiting_then_external_enqueue_poll_is_bounded() {
    let scheduler = RecordingScheduler::default();
    let delays = Arc::clone(&scheduler.delays);
    let runtime = runtime_with(
        Arc::new(scheduler),
        Arc::new(TestClock::new(
            Timestamp::from_millis(1_000),
            MonotonicDeadline::ZERO,
        )),
    );

    runtime
        .wait_for(
            &report(bg_jobs::WakeHint::At(Timestamp::from_millis(60_000))),
            bg_jobs::WakeHint::None,
        )
        .await
        .expect("recording scheduler wakes");

    assert_eq!(
        delays.lock().expect("recording scheduler lock").as_slice(),
        [Duration::from_millis(500)]
    );
}

#[tokio::test]
async fn given_scheduler_failure_when_waiting_then_the_failure_is_typed() {
    let runtime = runtime_with(
        Arc::new(ErrorScheduler),
        Arc::new(TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO)),
    );

    let error = runtime
        .wait_for(&report(bg_jobs::WakeHint::None), bg_jobs::WakeHint::None)
        .await
        .expect_err("scheduler failure must be returned");
    assert!(matches!(
        error,
        JobSystemError::WakeScheduler(WakeSchedulerError::Unavailable)
    ));
}

#[tokio::test]
async fn given_deadline_overflow_when_driving_then_validation_is_returned() {
    let runtime = runtime_with(
        Arc::new(TestProfile::new()),
        Arc::new(TestClock::new(
            Timestamp::ZERO,
            MonotonicDeadline::from_nanos(u64::MAX),
        )),
    );

    let error = runtime
        .drive_once()
        .await
        .expect_err("overflow must be rejected before driving");
    assert!(matches!(
        error,
        JobSystemError::Validation(ValidationError::Overflow {
            field: "drive deadline"
        })
    ));
}

#[tokio::test]
async fn given_shutdown_during_resident_wait_then_the_runtime_returns() {
    let scheduler = PendingScheduler::default();
    let entered = Arc::clone(&scheduler.entered);
    let runtime = Arc::new(runtime_with(
        Arc::new(scheduler),
        Arc::new(TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO)),
    ));
    let entered_wait = entered.notified();
    let running = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.run_until_shutdown().await })
    };
    entered_wait.await;

    runtime.request_shutdown();
    running
        .await
        .expect("resident task joins")
        .expect("shutdown is not an error");
}

#[tokio::test]
async fn given_a_pending_scheduler_when_shutdown_is_requested_then_wait_reports_shutdown() {
    let scheduler = PendingScheduler::default();
    let entered = Arc::clone(&scheduler.entered);
    let runtime = Arc::new(runtime_with(
        Arc::new(scheduler),
        Arc::new(TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO)),
    ));
    let waiting = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            runtime
                .wait_for(&report(bg_jobs::WakeHint::None), bg_jobs::WakeHint::None)
                .await
        })
    };
    entered.notified().await;

    runtime.request_shutdown();
    let outcome = waiting
        .await
        .expect("wait task joins")
        .expect("shutdown wake is not an error");
    assert_eq!(outcome, WaitOutcome::Shutdown);
}

struct CountingHandler(Arc<AtomicUsize>);

struct ConflictingSettlementHandler(FakeStore);

struct RejectedPublicationHandler;

impl JobHandler for RejectedPublicationHandler {
    fn claim_lease_policy(&self) -> bg_jobs::ClaimLeasePolicy {
        // This test handler rejects locally and publishes no remote authority.
        bg_jobs::ClaimLeasePolicy::DriveBoundedNative
    }

    fn publish_claim<'a>(
        &'a self,
        _context: &ExecutionContext<'_>,
    ) -> Option<bg_jobs::ClaimPublicationFuture<'a>> {
        Some(Box::pin(async {
            Err(std::io::Error::other("publication acknowledgement unavailable").into())
        }))
    }

    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        panic!("unacknowledged publication must not execute")
    }
}

impl JobHandler for ConflictingSettlementHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.0
            .queue_commit_outcome(bg_jobs::store::CommitOutcome::Conflict)
            .expect("inject a lost settlement claim");
        Box::pin(async {
            Ok(JobOutcome::Complete(
                bg_jobs::OutcomeCode::try_new("finished").expect("outcome code"),
            ))
        })
    }
}

#[tokio::test]
async fn given_lost_settlement_claim_when_running_resident_then_discovery_waits_and_shutdown_succeeds()
 {
    let store = FakeStore::local();
    assert_interrupted_claim_recovery(store.clone(), ConflictingSettlementHandler(store)).await;
}

#[tokio::test]
async fn given_rejected_claim_publication_when_running_resident_then_discovery_waits_and_shutdown_succeeds()
 {
    assert_interrupted_claim_recovery(FakeStore::local(), RejectedPublicationHandler).await;
}

async fn assert_interrupted_claim_recovery(store: FakeStore, handler: impl JobHandler) {
    let scheduler = PendingScheduler::default();
    let entered = Arc::clone(&scheduler.entered);
    let id = JobId::from([96; JobId::BYTE_LENGTH]);
    let mut catalog = JobCatalog::new();
    catalog
        .register_seeded(
            JobSpec::unit(
                JobKind::try_new("interrupted-claim").expect("job kind"),
                std::num::NonZeroU16::MIN,
                QueueName::try_new("default").expect("queue"),
                handler,
            )
            .policy(
                EffectMode::Fenced,
                FairnessPolicy::low_volume(),
                RetrySelection::Preset(RetryPreset::Network),
                Duration::from_secs(30),
            ),
            (),
            EnqueueOptions::new(FairnessClass::LowVolume).job_id(id),
            Timestamp::ZERO,
        )
        .expect("register seed");
    let budget = DriveBudget::try_from(DriveBudgetInput {
        queues: QueueSelection::all(),
        max_claims: 1,
        max_concurrency: 1,
        max_store_operations: 1_024,
        stop_claiming_after: Duration::from_secs(1),
        finish_after: Duration::from_secs(2),
    })
    .expect("drive budget");
    let runtime = Arc::new(
        crate::test_support::runtime_builder(store.clone(), catalog, budget)
            .namespace(Namespace::try_new("interrupted-claim").expect("namespace"))
            .owner(OwnerId::from([97; OwnerId::BYTE_LENGTH]))
            .scheduler(Arc::new(scheduler))
            .clock(Arc::new(TestClock::new(
                Timestamp::ZERO,
                MonotonicDeadline::ZERO,
            )))
            .build()
            .expect("build runtime"),
    );
    runtime.ensure_seeds().await.expect("persist seed");
    let entered_wait = entered.notified();
    let mut running = {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move { runtime.run_until_shutdown().await })
    };
    tokio::select! {
        _ = entered_wait => {},
        result = &mut running => panic!("interrupted claim terminated resident discovery: {result:?}"),
    }
    assert!(matches!(
        runtime
            .observe_queue_outcome(id)
            .await
            .expect("observe unfinished job"),
        crate::QueueOutcome::RetryAfter(_)
    ));
    runtime.request_shutdown();
    running
        .await
        .expect("resident joins")
        .expect("shutdown succeeds");
}

impl JobHandler for CountingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(JobOutcome::Cancelled) })
    }
}

#[tokio::test]
async fn given_shutdown_before_drive_then_no_handler_is_started() {
    let executions = Arc::new(AtomicUsize::new(0));
    let mut catalog = JobCatalog::new();
    catalog
        .register_seeded(
            JobSpec::unit(
                JobKind::try_new("shutdown-test").expect("job kind"),
                std::num::NonZeroU16::MIN,
                QueueName::try_new("default").expect("queue"),
                CountingHandler(Arc::clone(&executions)),
            )
            .policy(
                EffectMode::Fenced,
                FairnessPolicy::low_volume(),
                RetrySelection::Preset(RetryPreset::Network),
                Duration::from_secs(1),
            ),
            (),
            EnqueueOptions::new(FairnessClass::low_volume())
                .job_id(JobId::from([7; JobId::BYTE_LENGTH])),
            Timestamp::ZERO,
        )
        .expect("seed registration");
    let runtime = crate::test_support::runtime_builder(FakeStore::local(), catalog, profile())
        .namespace(Namespace::try_new(b"jobs").expect("namespace"))
        .owner(OwnerId::from([8; OwnerId::BYTE_LENGTH]))
        .scheduler(Arc::new(TestProfile::new()))
        .clock(Arc::new(TestClock::new(
            Timestamp::ZERO,
            MonotonicDeadline::ZERO,
        )))
        .build()
        .expect("runtime builds");
    runtime.ensure_seeds().await.expect("seed persists");
    runtime.request_shutdown();

    let report = runtime.drive_once().await.expect("shutdown drive report");
    assert_eq!(report.stop_reason, DriveStopReason::Shutdown);
    assert_eq!(report.counts.claimed, 0);
    assert_eq!(executions.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn given_unfinished_and_closed_jobs_when_observing_queue_outcomes_then_only_closed_jobs_complete()
 {
    let id = JobId::from([93; JobId::BYTE_LENGTH]);
    let mut catalog = JobCatalog::new();
    catalog
        .register_seeded(
            JobSpec::unit(
                JobKind::try_new("queue-observation").unwrap(),
                std::num::NonZeroU16::MIN,
                QueueName::try_new("queue").unwrap(),
                CountingHandler(Arc::new(AtomicUsize::new(0))),
            )
            .policy(
                EffectMode::Fenced,
                FairnessPolicy::low_volume(),
                RetrySelection::Preset(RetryPreset::Maintenance),
                Duration::from_secs(30),
            ),
            (),
            EnqueueOptions::new(FairnessClass::LowVolume).job_id(id),
            Timestamp::from_millis(100),
        )
        .unwrap();
    let clock = Arc::new(TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO));
    let runtime = crate::test_support::runtime_builder(FakeStore::local(), catalog, profile())
        .namespace(Namespace::try_new("queue-observation").unwrap())
        .owner(OwnerId::from([94; 16]))
        .scheduler(Arc::new(TestProfile::new()))
        .clock(clock.clone())
        .build()
        .unwrap();
    assert!(matches!(
        runtime.observe_queue_outcome(id).await,
        Err(JobSystemError::NotFound)
    ));
    runtime.ensure_seeds().await.unwrap();
    assert_eq!(
        runtime.observe_queue_outcome(id).await.unwrap(),
        crate::QueueOutcome::RetryAfter(Duration::from_millis(100))
    );
    clock.advance(Duration::from_millis(100));
    assert_eq!(
        runtime.observe_queue_outcome(id).await.unwrap(),
        crate::QueueOutcome::RetryAfter(Duration::from_millis(1))
    );
    let system = runtime.test_system();
    let _claim = system.claim(id, runtime.wall_now()).await.unwrap();
    assert_eq!(
        runtime.observe_queue_outcome(id).await.unwrap(),
        crate::QueueOutcome::RetryAfter(Duration::from_secs(30))
    );
    system.cancel_job(id, runtime.wall_now()).await.unwrap();
    assert_eq!(
        runtime.observe_queue_outcome(id).await.unwrap(),
        crate::QueueOutcome::RetryAfter(Duration::from_secs(30))
    );
    let closed = JobId::from([95; JobId::BYTE_LENGTH]);
    let seed = bg_jobs::JobSeed::new(
        JobKind::try_new("queue-observation").unwrap(),
        std::num::NonZeroU16::MIN,
        Vec::new().into(),
        EnqueueOptions::new(FairnessClass::LowVolume).job_id(closed),
        runtime.wall_now(),
    )
    .unwrap();
    runtime.ensure_seed(seed).await.unwrap();
    system.cancel_job(closed, runtime.wall_now()).await.unwrap();
    assert_eq!(
        runtime.observe_queue_outcome(closed).await.unwrap(),
        crate::QueueOutcome::Complete
    );
}

#[tokio::test]
async fn given_long_seed_timeout_when_short_drive_loses_publication_then_restart_preserves_seed_and_recovers_at_drive_bound()
 {
    let id = JobId::from([98; JobId::BYTE_LENGTH]);
    let store = FakeStore::local();
    let clock = Arc::new(TestClock::new(Timestamp::ZERO, MonotonicDeadline::ZERO));
    let mut catalog = JobCatalog::new();
    catalog
        .register_seeded(
            JobSpec::unit(
                JobKind::try_new("bounded-maintenance").unwrap(),
                std::num::NonZeroU16::MIN,
                QueueName::try_new("default").unwrap(),
                RejectedPublicationHandler,
            )
            .policy(
                EffectMode::Fenced,
                FairnessPolicy::low_volume(),
                RetrySelection::Preset(RetryPreset::Maintenance),
                Duration::from_secs(300),
            ),
            (),
            EnqueueOptions::new(FairnessClass::LowVolume).job_id(id),
            Timestamp::ZERO,
        )
        .unwrap();
    let budget = DriveBudget::try_from(DriveBudgetInput {
        queues: QueueSelection::all(),
        max_claims: 1,
        max_concurrency: 1,
        max_store_operations: 1024,
        stop_claiming_after: Duration::from_secs(1),
        finish_after: Duration::from_secs(2),
    })
    .unwrap();
    let build = |owner, catalog| {
        crate::test_support::runtime_builder(store.clone(), catalog, budget.clone())
            .namespace(Namespace::try_new("bounded-maintenance").unwrap())
            .owner(OwnerId::from([owner; OwnerId::BYTE_LENGTH]))
            .scheduler(Arc::new(TestProfile::new()))
            .clock(clock.clone())
            .build()
            .unwrap()
    };
    let runtime = build(98, catalog.clone());
    runtime.ensure_seeds().await.unwrap();
    assert!(matches!(
        runtime.drive_once().await,
        Err(JobSystemError::ClaimPublicationUnacknowledged)
    ));
    let bg_jobs::LifecycleObservation::Current { record, .. } =
        runtime.observe_lifecycle(id).await.unwrap()
    else {
        panic!("unacknowledged job must retain its durable lease")
    };
    assert_eq!(
        record.policy.execution_timeout,
        Some(Duration::from_secs(300))
    );
    let bg_jobs::JobState::Leased(original_lease) = record.state else {
        panic!("job must remain leased")
    };
    assert_eq!(
        original_lease.expires_at,
        Timestamp::from_millis(2000),
        "new claim authority must end with its drive, without changing the saved seed policy"
    );
    drop(runtime);
    let restarted = build(99, catalog);
    let seeds = restarted
        .ensure_seeds()
        .await
        .expect("original 300-second seed remains compatible");
    assert_eq!(
        seeds[0].disposition,
        bg_jobs::EnqueueDisposition::AlreadyPresent
    );
    clock.advance(Duration::from_millis(1000));
    assert!(
        matches!(
            restarted
                .test_system()
                .claim(id, restarted.wall_now())
                .await,
            Err(JobSystemError::LeaseConflict)
        ),
        "an existing unexpired lease remains authoritative"
    );
    clock.advance(Duration::from_millis(1001));
    assert!(matches!(
        restarted
            .test_system()
            .claim(id, restarted.wall_now())
            .await,
        Err(JobSystemError::ClaimPublicationUnacknowledged)
    ));
    let bg_jobs::LifecycleObservation::Current { record, .. } =
        restarted.observe_lifecycle(id).await.unwrap()
    else {
        panic!("replacement claim must remain durable")
    };
    let bg_jobs::JobState::Leased(replacement) = record.state else {
        panic!("replacement must be leased")
    };
    assert!(replacement.fence > original_lease.fence);
    assert_eq!(
        replacement.expires_at,
        Timestamp::from_millis(302001),
        "direct claims preserve the registered timeout"
    );
}
