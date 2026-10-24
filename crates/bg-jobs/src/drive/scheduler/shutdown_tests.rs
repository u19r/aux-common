use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll, Wake, Waker},
    thread,
    time::Duration,
};

use crate::{
    budget::{DriveRequestInput, QueueSelection},
    test_helper::{TestProfile, block_on, low_volume_job, one, system},
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

struct NeverWakingHandler {
    started: mpsc::Sender<()>,
}

struct CancellationAwareHandler {
    started: mpsc::Sender<()>,
    observed: mpsc::Sender<()>,
}

struct CancellationAwareFuture<'a> {
    context: ExecutionContext<'a>,
    observed: mpsc::Sender<()>,
}

impl JobHandler for NeverWakingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let _ = self.started.send(());
        Box::pin(std::future::pending())
    }
}

impl Future for CancellationAwareFuture<'_> {
    type Output = Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        let future = self.get_mut();
        if !future.context.is_cancelled() {
            return Poll::Pending;
        }
        let _ = future.observed.send(());
        Poll::Ready(Ok(JobOutcome::Cancelled))
    }
}

impl JobHandler for CancellationAwareHandler {
    fn execute<'a>(
        &'a self,
        context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let _ = self.started.send(());
        Box::pin(CancellationAwareFuture {
            context,
            observed: self.observed.clone(),
        })
    }
}

pub(super) fn never_waking_system(
    store: FakeStore,
    started: mpsc::Sender<()>,
) -> JobSystem<FakeStore> {
    system_with_handler(
        store,
        NeverWakingHandler { started },
        Duration::from_secs(1),
        Arc::new(TestProfile::new()),
    )
}

fn never_waking_system_with_profile(
    store: FakeStore,
    started: mpsc::Sender<()>,
    default_timeout: Duration,
) -> (JobSystem<FakeStore>, TestProfile, mpsc::Receiver<Duration>) {
    let profile = TestProfile::new();
    let (sleep_sender, sleep_receiver) = mpsc::channel();
    let system = system_with_handler(
        store,
        NeverWakingHandler { started },
        default_timeout,
        Arc::new(RecordingScheduler {
            profile: profile.clone(),
            sleep_sender,
        }),
    );
    (system, profile, sleep_receiver)
}

pub(super) fn never_waking_system_with_scheduler(
    store: FakeStore,
    started: mpsc::Sender<()>,
    default_timeout: Duration,
    scheduler: Arc<dyn WakeScheduler>,
) -> JobSystem<FakeStore> {
    system_with_handler(
        store,
        NeverWakingHandler { started },
        default_timeout,
        scheduler,
    )
}

fn cancellation_aware_system(
    store: FakeStore,
    started: mpsc::Sender<()>,
    observed: mpsc::Sender<()>,
) -> JobSystem<FakeStore> {
    system_with_handler(
        store,
        CancellationAwareHandler { started, observed },
        Duration::from_secs(1),
        Arc::new(TestProfile::new()),
    )
}

fn system_with_handler<H: JobHandler>(
    store: FakeStore,
    handler: H,
    default_timeout: Duration,
    scheduler: Arc<dyn WakeScheduler>,
) -> JobSystem<FakeStore> {
    let kind = JobKind::try_new("email").expect("test kind is valid");
    let queue = QueueName::try_new("default").expect("test queue is valid");
    let mut registry = HandlerRegistry::new();
    registry
        .register(HandlerDefinition {
            kind,
            schema_version: std::num::NonZeroU16::MIN,
            queue,
            effect_mode: EffectMode::Idempotent,
            cost_units: std::num::NonZeroU16::MIN,
            fairness_policy: FairnessPolicy::low_volume(),
            default_retry: RetrySelection::Preset(RetryPreset::Interactive),
            default_timeout,
            handler,
        })
        .expect("test registration is valid");
    JobSystem::new(
        store,
        crate::JobCatalog::from_registry(registry),
        Namespace::try_new(b"jobs").expect("test namespace is valid"),
        OwnerId::from([19; 16]),
        scheduler,
    )
}

struct RecordingScheduler {
    profile: TestProfile,
    sleep_sender: mpsc::Sender<Duration>,
}

impl WakeScheduler for RecordingScheduler {
    fn sleep(&self, delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        let future = self.profile.sleep(delay)?;
        let _ = self.sleep_sender.send(delay);
        Ok(future)
    }
}

struct WakeDrivenSignal {
    thread: thread::Thread,
    wake_sender: mpsc::Sender<()>,
    pending_sender: mpsc::Sender<()>,
    pending_receiver: Mutex<mpsc::Receiver<()>>,
}

impl WakeDrivenSignal {
    fn notify(&self) {
        let _ = self.wake_sender.send(());
        self.thread.unpark();
    }

    fn wait_pending(&self) {
        self.pending_receiver
            .lock()
            .expect("pending receiver")
            .recv_timeout(Duration::from_secs(2))
            .expect("drive becomes pending");
    }

    fn wake_executor(&self) {
        self.thread.unpark();
    }
}

impl Wake for WakeDrivenSignal {
    fn wake(self: Arc<Self>) {
        self.notify();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.notify();
    }
}

fn wake_driven_block_on<F: Future>(
    future: F,
    signal_sender: mpsc::Sender<Arc<WakeDrivenSignal>>,
    wake_sender: mpsc::Sender<()>,
) -> F::Output {
    let (pending_sender, pending_receiver) = mpsc::channel();
    let signal = Arc::new(WakeDrivenSignal {
        pending_sender,
        pending_receiver: Mutex::new(pending_receiver),
        thread: thread::current(),
        wake_sender,
    });
    signal_sender
        .send(Arc::clone(&signal))
        .expect("signal receiver");
    let waker = Waker::from(Arc::clone(&signal));
    let mut context = Context::from_waker(&waker);
    let mut future = Box::pin(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
            return output;
        }
        let _ = signal.pending_sender.send(());
        thread::park();
    }
}

struct CountingWake(Arc<AtomicUsize>);

impl Wake for CountingWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn given_shutdown_when_drive_starts_then_no_new_claim_is_taken_until_shutdown_clears() {
    let store = FakeStore::new();
    let system = system(store, FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(low_volume_job(3, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    system.request_shutdown();
    let stopped =
        block_on(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive reports");
    assert_eq!(stopped.stop_reason, DriveStopReason::Shutdown);
    assert_eq!(stopped.counts.claimed, 0);
    system.clear_shutdown();
    let resumed =
        block_on(system.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
            .expect("drive resumes");
    assert_eq!(resumed.counts.claimed, 1);
}

#[test]
fn given_a_never_waking_handler_when_shutdown_is_requested_then_grace_expiry_leaves_claim_recoverable()
 {
    let store = FakeStore::distributed();
    let (started, started_rx) = mpsc::channel();
    let (system, profile, sleep_receiver) =
        never_waking_system_with_profile(store, started, Duration::from_secs(1));
    let system = Arc::new(system);
    block_on(system.enqueue_raw(low_volume_job(20, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let runner = Arc::clone(&system);
    let drive = std::thread::spawn(move || {
        block_on(runner.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
    });
    started_rx.recv().expect("handler starts before shutdown");
    sleep_receiver
        .recv()
        .expect("handler deadline is scheduled");
    system.request_shutdown();
    sleep_receiver.recv().expect("shutdown grace is scheduled");
    profile.advance(Duration::from_millis(50));

    let report = drive
        .join()
        .expect("shutdown drive joins")
        .expect("drive reports");
    assert_eq!(report.stop_reason, DriveStopReason::Shutdown);
    assert_eq!(report.counts.claimed, 0);
    let encoded = block_on(system.store().get(
        crate::keys::job_key(system.namespace(), &JobId::from([20; 16])).expect("job key is valid"),
    ))
    .expect("job read succeeds")
    .expect("leased job remains recoverable");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert!(matches!(record.state, JobState::Leased(_)));
}

#[test]
fn given_two_drives_on_one_system_when_one_shutdown_drain_finishes_then_the_other_registration_remains()
 {
    let store = FakeStore::distributed();
    let (started, started_rx) = mpsc::channel();
    let (system, profile, sleep_receiver) =
        never_waking_system_with_profile(store, started, Duration::from_secs(1));
    let system = Arc::new(system);
    block_on(system.enqueue_raw(low_volume_job(26, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let runner = Arc::clone(&system);
    let drive = thread::spawn(move || {
        block_on(runner.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO))
    });
    started_rx.recv().expect("first drive handler starts");
    sleep_receiver
        .recv()
        .expect("handler deadline is scheduled");

    let second_token = CancellationToken::new();
    let second_registration = system.register_attempt_guard(
        crate::engine::AttemptAuthority::new(
            JobId::from([27; 16]),
            OperationId::from([27; 16]),
            1,
            AttemptId::from([27; 16]),
        ),
        second_token.clone(),
    );
    assert_eq!(system.active_attempt_count(), 2);

    system.request_shutdown();
    sleep_receiver.recv().expect("shutdown grace is scheduled");
    profile.advance(Duration::from_millis(50));
    let report = drive
        .join()
        .expect("first drive joins")
        .expect("first drive reports");
    assert_eq!(report.stop_reason, DriveStopReason::Shutdown);
    assert_eq!(system.active_attempt_count(), 1);
    assert!(second_token.is_cancelled(), "shutdown signals both drives");

    drop(second_registration);
    assert_eq!(system.active_attempt_count(), 0);
}

#[test]
fn given_a_wake_driven_executor_when_shutdown_is_requested_then_drive_is_woken() {
    let store = FakeStore::distributed();
    let (started, started_rx) = mpsc::channel();
    let (system, profile, sleep_receiver) =
        never_waking_system_with_profile(store, started, Duration::from_secs(1));
    let system = Arc::new(system);
    block_on(system.enqueue_raw(low_volume_job(21, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let (signal_sender, signal_receiver) = mpsc::channel();
    let (wake_sender, wake_receiver) = mpsc::channel();
    let runner = Arc::clone(&system);
    let drive = thread::spawn(move || {
        wake_driven_block_on(
            runner.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO),
            signal_sender,
            wake_sender,
        )
    });
    let signal = signal_receiver.recv().expect("wake-driven executor starts");
    started_rx.recv().expect("handler starts before shutdown");
    sleep_receiver
        .recv()
        .expect("handler deadline is scheduled");
    while wake_receiver.try_recv().is_ok() {}

    system.request_shutdown();
    sleep_receiver.recv().expect("shutdown grace is scheduled");
    profile.advance(Duration::from_millis(50));
    let woke = wake_receiver.recv().is_ok();
    signal.wake_executor();
    let report = drive
        .join()
        .expect("wake-driven shutdown drive joins")
        .expect("drive reports");

    assert!(woke, "shutdown must wake a pending drive future");
    assert_eq!(report.stop_reason, DriveStopReason::Shutdown);
    assert_eq!(report.counts.claimed, 0);
}

#[test]
fn given_a_public_cancel_when_handler_ignores_it_then_shutdown_grace_is_bounded() {
    let store = FakeStore::distributed();
    let (started, started_rx) = mpsc::channel();
    let (system, profile, sleep_receiver) =
        never_waking_system_with_profile(store, started, Duration::from_secs(1));
    let system = Arc::new(system);
    let id = JobId::from([28; 16]);
    block_on(system.enqueue_raw(low_volume_job(28, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let (signal_sender, signal_receiver) = mpsc::channel();
    let (wake_sender, wake_receiver) = mpsc::channel();
    let runner = Arc::clone(&system);
    let drive = thread::spawn(move || {
        wake_driven_block_on(
            runner.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO),
            signal_sender,
            wake_sender,
        )
    });
    let signal = signal_receiver.recv().expect("wake-driven executor starts");
    started_rx
        .recv()
        .expect("handler starts before cancellation");
    sleep_receiver
        .recv()
        .expect("handler deadline is scheduled");
    signal.wait_pending();
    while wake_receiver.try_recv().is_ok() {}

    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancel commits"),
        CancellationResult::Requested
    );
    let woke = wake_receiver.recv_timeout(Duration::from_secs(2)).is_ok();
    signal.wait_pending();

    system.request_shutdown();
    sleep_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("shutdown grace is scheduled after cancellation was observed");
    profile.advance(Duration::from_millis(50));
    signal.wake_executor();
    let report = drive
        .join()
        .expect("cancelled drive joins")
        .expect("drive reports");

    assert!(
        woke,
        "public cancellation must wake the local handler drive"
    );
    assert_eq!(report.stop_reason, DriveStopReason::Shutdown);
}

#[test]
fn given_a_public_cancel_when_handler_checks_context_then_it_observes_cancellation() {
    let store = FakeStore::distributed();
    let (started, started_rx) = mpsc::channel();
    let (observed, observed_rx) = mpsc::channel();
    let system = Arc::new(cancellation_aware_system(store, started, observed));
    let id = JobId::from([33; 16]);
    block_on(system.enqueue_raw(low_volume_job(33, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let (signal_sender, signal_receiver) = mpsc::channel();
    let (wake_sender, wake_receiver) = mpsc::channel();
    let runner = Arc::clone(&system);
    let drive = thread::spawn(move || {
        wake_driven_block_on(
            runner.drive(drive_request(), Timestamp::ZERO, || MonotonicDeadline::ZERO),
            signal_sender,
            wake_sender,
        )
    });
    let signal = signal_receiver.recv().expect("wake-driven executor starts");
    started_rx
        .recv()
        .expect("handler starts before cancellation");
    while wake_receiver.try_recv().is_ok() {}

    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancel commits"),
        CancellationResult::Requested
    );
    let observed = observed_rx.recv().is_ok();

    system.request_shutdown();
    signal.wake_executor();
    let report = drive
        .join()
        .expect("cancelled drive joins")
        .expect("drive reports");

    assert!(
        observed,
        "handler must observe cancellation through its context"
    );
    assert_eq!(report.counts.cancelled, 1);
}

#[test]
fn given_cancel_before_registration_when_attempt_registers_then_marker_check_signals_it() {
    let store = FakeStore::distributed();
    let system = system(store, FairnessPolicy::low_volume(), 29);
    let id = JobId::from([29; 16]);
    block_on(system.enqueue_raw(low_volume_job(29, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let cancellation = claim.cancellation();
    let authority = crate::engine::AttemptAuthority::new(
        id,
        claim.operation_id(),
        claim.fence_high_water(),
        claim.attempt_id(),
    );

    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancel commits"),
        CancellationResult::Requested
    );
    assert!(!cancellation.is_cancelled());

    let registration = system.register_attempt_guard(authority, cancellation.clone());
    block_on(system.refresh_attempt_cancellation(authority)).expect("marker check succeeds");

    assert!(cancellation.is_cancelled());
    drop(registration);
    drop(claim);
}

#[test]
fn given_two_registered_jobs_when_one_is_cancelled_then_only_matching_attempt_is_signalled() {
    let store = FakeStore::distributed();
    let system = system(store, FairnessPolicy::low_volume(), 30);
    let id = JobId::from([30; 16]);
    block_on(system.enqueue_raw(low_volume_job(30, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");
    let claim = block_on(system.claim(id, Timestamp::ZERO)).expect("claim commits");
    let matching = claim.cancellation();
    let matching_authority = crate::engine::AttemptAuthority::new(
        id,
        claim.operation_id(),
        claim.fence_high_water(),
        claim.attempt_id(),
    );
    let unrelated = CancellationToken::new();
    let unrelated_authority = crate::engine::AttemptAuthority::new(
        JobId::from([31; 16]),
        OperationId::from([31; 16]),
        1,
        AttemptId::from([31; 16]),
    );
    let stale = CancellationToken::new();
    let stale_authority = crate::engine::AttemptAuthority::new(
        id,
        OperationId::from([32; 16]),
        2,
        AttemptId::from([32; 16]),
    );
    let matching_registration = system.register_attempt_guard(matching_authority, matching.clone());
    let unrelated_registration =
        system.register_attempt_guard(unrelated_authority, unrelated.clone());
    let stale_registration = system.register_attempt_guard(stale_authority, stale.clone());

    assert_eq!(
        block_on(system.cancel_job(id, Timestamp::from_millis(1))).expect("cancel commits"),
        CancellationResult::Requested
    );

    assert!(matching.is_cancelled());
    assert!(!unrelated.is_cancelled());
    assert!(!stale.is_cancelled());
    drop(stale_registration);
    drop(unrelated_registration);
    drop(matching_registration);
    drop(claim);
}

#[test]
fn given_a_wake_driven_executor_when_handler_deadline_expires_then_drive_is_woken() {
    let store = FakeStore::distributed();
    let (started, started_rx) = mpsc::channel();
    let (system, profile, sleep_receiver) =
        never_waking_system_with_profile(store, started, Duration::from_millis(1));
    let system = Arc::new(system);
    block_on(system.enqueue_raw(low_volume_job(22, Timestamp::ZERO), Timestamp::ZERO))
        .expect("enqueue commits");

    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: one(1),
        max_concurrency: std::num::NonZeroU16::new(1).expect("concurrency is non-zero"),
        max_payload_bytes_in_flight: std::num::NonZeroUsize::new(1024).expect("payload budget"),
        max_completion_details: 1,
        max_store_operations: one(64),
        stop_claiming_at: MonotonicDeadline::from_nanos(200_000_000),
        finish_by: MonotonicDeadline::from_nanos(250_000_000),
    })
    .expect("drive request is valid");
    let clock_profile = profile.clone();
    let clock = move || clock_profile.now();

    let (signal_sender, signal_receiver) = mpsc::channel();
    let (wake_sender, wake_receiver) = mpsc::channel();
    let runner = Arc::clone(&system);
    let drive = thread::spawn(move || {
        wake_driven_block_on(
            runner.drive(request, Timestamp::ZERO, clock),
            signal_sender,
            wake_sender,
        )
    });
    let signal = signal_receiver.recv().expect("wake-driven executor starts");
    started_rx.recv().expect("handler starts before deadline");
    sleep_receiver
        .recv()
        .expect("handler deadline is scheduled");
    while wake_receiver.try_recv().is_ok() {}

    profile.advance(Duration::from_millis(250));
    let woke = wake_receiver.recv().is_ok();
    signal.wake_executor();
    let report = drive
        .join()
        .expect("wake-driven deadline drive joins")
        .expect("drive reports");

    assert!(woke, "handler deadline must wake a pending drive future");
    assert_eq!(report.stop_reason, DriveStopReason::Deadline);
    assert_eq!(report.counts.claimed, 0);
    let encoded = block_on(system.store().get(
        crate::keys::job_key(system.namespace(), &JobId::from([22; 16])).expect("job key is valid"),
    ))
    .expect("job read succeeds")
    .expect("leased job remains recoverable");
    let record = crate::codec::decode_job_record(&encoded).expect("record decodes");
    assert!(matches!(record.state, JobState::Leased(_)));
}

#[test]
fn given_repeated_shutdown_requests_when_token_is_cancelled_then_only_one_wake_is_sent() {
    let wakes = Arc::new(AtomicUsize::new(0));
    let token = CancellationToken::new();
    let waker = Waker::from(Arc::new(CountingWake(Arc::clone(&wakes))));
    let mut context = Context::from_waker(&waker);

    assert!(token.poll_cancelled(&mut context).is_pending());
    token.cancel();
    token.cancel();

    assert_eq!(wakes.load(Ordering::SeqCst), 1);
}
