use std::{
    future::Future,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use super::shutdown_tests::{never_waking_system, never_waking_system_with_scheduler};
use crate::{
    budget::{DriveRequestInput, QueueSelection},
    test_helper::{block_on, low_volume_job, one, system},
    *,
};

fn drive_request() -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: std::num::NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).expect("payload budget"),
        max_completion_details: 1,
        max_store_operations: one(64),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid")
}

struct CountingScheduler {
    sleeps: Arc<AtomicUsize>,
}

impl WakeScheduler for CountingScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        self.sleeps.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(std::future::ready(())))
    }
}

struct FailingScheduler;

impl WakeScheduler for FailingScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        Err(WakeSchedulerError::Unavailable)
    }
}

fn completing_system_with_scheduler(
    store: FakeStore,
    scheduler: Arc<dyn WakeScheduler>,
) -> JobSystem<FakeStore> {
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(
            crate::test_helper::registry(FairnessPolicy::low_volume()),
        ),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([23; 16]),
        scheduler,
    )
}

#[test]
fn given_zero_completion_detail_budget_when_driving_then_success_is_counted_and_detail_is_omitted()
{
    let store = FakeStore::new();
    let engine = system(store.clone(), FairnessPolicy::low_volume(), 1);
    block_on(engine.enqueue_raw(low_volume_job(1, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: std::num::NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(384 * 1024)
            .expect("payload budget is non-zero"),
        max_completion_details: 0,
        max_store_operations: one(32),
        stop_claiming_at: MonotonicDeadline::from_nanos(1),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("drive request is valid");

    let report = block_on(engine.drive(request, Timestamp::ZERO, || MonotonicDeadline::ZERO))
        .expect("drive succeeds");
    assert_eq!(report.counts.succeeded, 1);
    assert!(report.completions.is_empty());
    assert_eq!(report.completions_omitted, 1);
}

#[test]
fn given_an_immediate_handler_when_driving_then_no_deadline_sleep_is_scheduled() {
    let sleeps = Arc::new(AtomicUsize::new(0));
    let system = completing_system_with_scheduler(
        FakeStore::distributed(),
        Arc::new(CountingScheduler {
            sleeps: Arc::clone(&sleeps),
        }),
    );
    block_on(system.enqueue_raw(low_volume_job(23, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let report =
        block_on(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive reports");

    assert_eq!(report.counts.succeeded, 1);
    assert_eq!(sleeps.load(Ordering::SeqCst), 0);
}

#[test]
fn given_a_scheduler_failure_when_handler_pending_then_error_is_not_deadline() {
    let (started, started_rx) = mpsc::channel();
    let system = never_waking_system_with_scheduler(
        FakeStore::distributed(),
        started,
        Duration::from_secs(1),
        Arc::new(FailingScheduler),
    );
    block_on(system.enqueue_raw(low_volume_job(24, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let result =
        block_on(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO));

    started_rx
        .recv()
        .expect("handler starts before scheduler failure");
    assert!(matches!(
        result,
        Err(JobSystemError::WakeScheduler(
            WakeSchedulerError::Unavailable
        ))
    ));
    assert_eq!(system.active_attempt_count(), 0);
}

#[test]
fn given_a_pending_drive_when_dropped_then_attempt_registration_is_removed() {
    let (started, started_rx) = mpsc::channel();
    let system = never_waking_system(FakeStore::distributed(), started);
    block_on(system.enqueue_raw(low_volume_job(25, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let mut drive =
        Box::pin(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    assert!(matches!(drive.as_mut().poll(&mut context), Poll::Pending));
    started_rx.recv().expect("handler starts before drop");
    assert_eq!(system.active_attempt_count(), 1);

    drop(drive);
    assert_eq!(system.active_attempt_count(), 0);
}

struct CompletionFailureHandler {
    store: FakeStore,
    fail_first: bool,
    started: Arc<AtomicUsize>,
    release_pending: Arc<AtomicBool>,
    pending_job: Arc<Mutex<Option<JobId>>>,
}

impl JobHandler for CompletionFailureHandler {
    fn execute<'a>(
        &'a self,
        context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let is_failure = (self.started.fetch_add(1, Ordering::SeqCst) == 0) == self.fail_first;
        if !is_failure {
            *self.pending_job.lock().expect("pending job lock") = Some(context.job_id());
        }
        Box::pin(std::future::poll_fn(move |_| {
            if self.started.load(Ordering::SeqCst) < 2
                || (!is_failure && !self.release_pending.load(Ordering::SeqCst))
            {
                return Poll::Pending;
            }
            if is_failure {
                for _ in 0..2 {
                    self.store
                        .queue_unknown_before_commit()
                        .expect("inject unacknowledged completion");
                }
            }
            Poll::Ready(Ok(JobOutcome::Complete(
                OutcomeCode::try_new("completed").expect("test outcome"),
            )))
        }))
    }
}

#[test]
fn given_one_completion_failure_when_another_handler_is_active_then_drive_settles_it_before_returning_error()
 {
    for fail_first in [true, false] {
        assert_completion_error_settles_active_handler(fail_first);
    }
}

fn assert_completion_error_settles_active_handler(fail_first: bool) {
    let store = FakeStore::distributed();
    let started = Arc::new(AtomicUsize::new(0));
    let release_pending = Arc::new(AtomicBool::new(false));
    let pending_job = Arc::new(Mutex::new(None));
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind: JobKind::try_new("email").expect("test kind"),
                schema_version: std::num::NonZeroU16::MIN,
                queue: QueueName::try_new("default").expect("test queue"),
                effect_mode: EffectMode::Idempotent,
                cost_units: std::num::NonZeroU16::MIN,
                fairness_policy: FairnessPolicy::from(std::num::NonZeroU16::MIN),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(30),
                handler: CompletionFailureHandler {
                    store: store.clone(),
                    fail_first,
                    started: Arc::clone(&started),
                    release_pending: Arc::clone(&release_pending),
                    pending_job: Arc::clone(&pending_job),
                },
            },
            None,
        )
        .expect("test catalog");
    let profile = Arc::new(crate::test_helper::TestProfile::new());
    let system = JobSystem::new(
        store,
        catalog,
        Namespace::try_new("jobs").expect("test namespace"),
        OwnerId::from([31; 16]),
        profile.clone(),
    );
    for id in [31, 32, 33] {
        let fairness = FairnessClass::from(FairnessPath::new(
            FairnessKey::try_new([id]).expect("test scope"),
            None,
        ));
        let job = crate::test_helper::job(
            id,
            bytes::Bytes::new(),
            fairness,
            Timestamp::ZERO,
            None,
            None,
        );
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("enqueue test job");
    }
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(3),
        max_concurrency: std::num::NonZeroU16::new(2).expect("two handlers"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).expect("payload budget"),
        max_completion_details: 2,
        max_store_operations: one(256),
        stop_claiming_at: MonotonicDeadline::from_nanos(1_000_000_000),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("test drive budget");
    let mut drive = Box::pin(system.drive(request, Timestamp::ZERO, || profile.now()));
    let mut context = Context::from_waker(Waker::noop());
    let first_poll = drive.as_mut().poll(&mut context);
    assert!(first_poll.is_pending(), "first drive poll: {first_poll:?}");
    assert!(
        drive.as_mut().poll(&mut context).is_pending(),
        "one failed completion must not cancel an independent active handler"
    );
    assert_eq!(system.active_attempt_count(), 1);
    assert_eq!(
        started.load(Ordering::SeqCst),
        2,
        "failure stops new intake"
    );

    release_pending.store(true, Ordering::SeqCst);
    assert!(matches!(
        block_on(drive),
        Err(JobSystemError::UnknownCommit)
    ));
    assert_eq!(system.active_attempt_count(), 0);
    let completed_job = pending_job
        .lock()
        .expect("pending job lock")
        .expect("second handler ran");
    assert!(matches!(
        block_on(system.claim(completed_job, Timestamp::ZERO)),
        Err(JobSystemError::NotFound)
    ));
    assert!(block_on(system.claim(JobId::from([33; 16]), Timestamp::ZERO)).is_ok());
}
