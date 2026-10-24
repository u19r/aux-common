use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bg_jobs::{
    EffectMode, ExecutionContext, FairnessClass, FairnessKey, FairnessPath, FairnessPolicy,
    HandlerFuture, JobCatalog, JobHandler, JobId, JobKind, JobOutcome, JobSystemError,
    LifecycleObservation, MAX_INLINE_PAYLOAD_BYTES, Namespace, OutcomeCode, OwnerId, Priority,
    QueueName, QueueSelection, RetryPreset, RetrySelection, Timestamp, WakeHint,
    runtime::{JobSystem, MonotonicDeadline},
    store::{StoreCapabilities, StoreCapabilitiesInput, StoreLevel},
    test_support::{
        FakeStore,
        codec::{KeyCodec, KeyTag},
        raw::{DriveRequest, DriveRequestInput, HandlerDefinition, NewJob, TerminalDisposition},
    },
};
use bytes::Bytes;
use cucumber::{given, then, when};

use crate::BddWorld;

#[derive(Clone)]
struct CountingHandler {
    calls: Arc<AtomicUsize>,
}

impl JobHandler for CountingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            let code = OutcomeCode::try_new("completed")
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(JobOutcome::Complete(code))
        })
    }
}

#[given("a registered scoped job with an opaque primary key")]
async fn given_registered_scoped_job(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = build_system(store.clone(), calls.clone())?;
    let now = Timestamp::from_millis(1_000);
    let job = new_job(1, Bytes::from_static(b"hello"), scoped_fairness(), now)?;
    save_system(world, store, system, calls, job, now);
    Ok(())
}

#[when("it is enqueued and driven")]
async fn when_enqueued_and_driven(world: &mut BddWorld) -> Result<(), String> {
    let system = take_system(world)?;
    let job = world.job.clone().ok_or("job was not configured")?;
    let enqueue = system
        .enqueue_raw(job, world.now)
        .await
        .map_err(display_error)?;
    let report = system
        .drive(drive_request(), world.now, || MonotonicDeadline::ZERO)
        .await
        .map_err(display_error)?;
    world.first_enqueue = Some(enqueue);
    world.completion = report.completions.first().cloned();
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("it executes once in the healthy case")]
async fn then_executes_once(world: &mut BddWorld) -> Result<(), String> {
    let calls = world
        .handler_calls
        .as_ref()
        .ok_or("handler was not configured")?;
    if calls.load(Ordering::SeqCst) != 1 {
        return Err(format!(
            "expected one handler call, got {}",
            calls.load(Ordering::SeqCst)
        ));
    }
    Ok(())
}

#[then("its durable job and payload state are deleted")]
async fn then_durable_state_is_deleted(world: &mut BddWorld) -> Result<(), String> {
    assert_terminal_state_deleted(world, "completed job").await
}

#[then("bounded completion details are returned after commit")]
async fn then_completion_details_are_bounded(world: &mut BddWorld) -> Result<(), String> {
    let completion = world
        .completion
        .as_ref()
        .ok_or("completion receipt was missing")?;
    if completion.kind.as_str().len() > JobKind::MAX_BYTES
        || completion.queue.as_str().len() > QueueName::MAX_BYTES
    {
        return Err("completion receipt contains unbounded registration data".to_owned());
    }
    if completion.attempts.get() != 1 {
        return Err(format!("expected one attempt, got {}", completion.attempts));
    }
    Ok(())
}

#[given("an enqueue commit acknowledgement is lost")]
async fn given_lost_enqueue_ack(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    store
        .queue_commit_outcome(bg_jobs::store::CommitOutcome::Unknown)
        .map_err(display_error)?;
    let system = build_system(store.clone(), calls.clone())?;
    let now = Timestamp::from_millis(1_000);
    let job = new_job(
        2,
        Bytes::from_static(b"immutable"),
        scoped_fairness(),
        Timestamp::from_millis(2_000),
    )?;
    save_system(world, store, system, calls, job, now);
    Ok(())
}

#[when("the caller retries the identical job ID and bytes")]
async fn when_retry_identical_enqueue(world: &mut BddWorld) -> Result<(), String> {
    let system = take_system(world)?;
    let job = world.job.clone().ok_or("job was not configured")?;
    let first = system
        .enqueue_raw(job.clone(), world.now)
        .await
        .map_err(display_error)?;
    let retry = system
        .enqueue_raw(job, world.now)
        .await
        .map_err(display_error)?;
    world.first_enqueue = Some(first);
    world.retry_enqueue = Some(retry);
    world.system = Some(system);
    Ok(())
}

#[then("it receives AlreadyPresent and the same wake hint")]
async fn then_replay_is_already_present(world: &mut BddWorld) -> Result<(), String> {
    let first = world
        .first_enqueue
        .as_ref()
        .ok_or("first enqueue was missing")?;
    let retry = world
        .retry_enqueue
        .as_ref()
        .ok_or("retry enqueue was missing")?;
    if retry.disposition != bg_jobs::EnqueueDisposition::AlreadyPresent {
        return Err(format!(
            "expected AlreadyPresent, got {:?}",
            retry.disposition
        ));
    }
    if first.wake != retry.wake {
        return Err(format!(
            "wake changed from {:?} to {:?}",
            first.wake, retry.wake
        ));
    }
    Ok(())
}

#[then("different immutable bytes return JobIdConflict")]
async fn then_changed_bytes_conflict(world: &mut BddWorld) -> Result<(), String> {
    let system = world.system.as_ref().ok_or("system was not configured")?;
    let mut changed = world.job.clone().ok_or("job was not configured")?;
    changed.payload = Bytes::from_static(b"changed");
    let error = system
        .enqueue_raw(changed, world.now)
        .await
        .err()
        .ok_or("changed bytes unexpectedly enqueued")?;
    if !matches!(error, JobSystemError::JobIdConflict) {
        return Err(format!("changed bytes returned the wrong error: {error}"));
    }
    Ok(())
}

#[given("a store whose value limit is smaller than 950 KiB")]
async fn given_small_value_store(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::with_capabilities(test_capabilities(4_096, 64 * 1024)?);
    let system = build_system(store.clone(), calls.clone())?;
    let now = Timestamp::from_millis(1_000);
    let payload = Bytes::from(vec![b'x'; MAX_INLINE_PAYLOAD_BYTES]);
    let job = new_job(3, payload, scoped_fairness(), now)?;
    save_system(world, store, system, calls, job, now);
    Ok(())
}

#[when("a 950 KiB job is enqueued")]
async fn when_maximum_payload_is_enqueued(world: &mut BddWorld) -> Result<(), String> {
    let system = take_system(world)?;
    let job = world.job.clone().ok_or("job was not configured")?;
    let enqueue = system
        .enqueue_raw(job, world.now)
        .await
        .map_err(display_error)?;
    let report = system
        .drive(drive_request(), world.now, || MonotonicDeadline::ZERO)
        .await
        .map_err(display_error)?;
    world.first_enqueue = Some(enqueue);
    world.completion = report.completions.first().cloned();
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("bounded chunks commit atomically and execute correctly")]
async fn then_maximum_payload_succeeds(world: &mut BddWorld) -> Result<(), String> {
    let enqueue = world
        .first_enqueue
        .as_ref()
        .ok_or("enqueue result was missing")?;
    if enqueue.disposition != bg_jobs::EnqueueDisposition::Enqueued {
        return Err(format!("expected Enqueued, got {:?}", enqueue.disposition));
    }
    let report = world
        .drive_report
        .as_ref()
        .ok_or("drive report was missing")?;
    if report.counts.succeeded != 1 || report.completions.len() != 1 {
        return Err(format!("maximum payload did not complete: {report:?}"));
    }
    assert_terminal_state_deleted(world, "maximum payload").await
}

#[then("a payload above 950 KiB fails before storage I/O")]
async fn then_oversized_payload_rejects(world: &mut BddWorld) -> Result<(), String> {
    let mut oversized = world.job.clone().ok_or("job was not configured")?;
    oversized.job_id = JobId::from([33; 16]);
    oversized.payload = Bytes::from(vec![b'z'; MAX_INLINE_PAYLOAD_BYTES + 1]);
    let calls = world
        .handler_calls
        .as_ref()
        .ok_or("handler was not configured")?
        .clone();
    let probe_store = FakeStore::with_capabilities(test_capabilities(1, 64 * 1024)?);
    let probe_system = build_system(probe_store, calls)?;
    let error = probe_system
        .enqueue_raw(oversized, world.now)
        .await
        .err()
        .ok_or("oversized payload unexpectedly enqueued")?;
    if !error.to_string().contains("payload exceeds") {
        return Err(format!("unexpected oversized payload error: {error}"));
    }
    Ok(())
}

#[given("only a future job exists")]
async fn given_only_future_job(world: &mut BddWorld) -> Result<(), String> {
    let calls = Arc::new(AtomicUsize::new(0));
    let store = FakeStore::new();
    let system = build_system(store.clone(), calls.clone())?;
    let now = Timestamp::from_millis(1_000);
    let job = new_job(
        4,
        Bytes::from_static(b"future"),
        scoped_fairness(),
        Timestamp::from_millis(2_500),
    )?;
    let _ = system
        .enqueue_raw(job.clone(), now)
        .await
        .map_err(display_error)?;
    save_system(world, store, system, calls, job, now);
    Ok(())
}

#[when("one drive finds no immediately useful work")]
async fn when_drive_finds_future_only(world: &mut BddWorld) -> Result<(), String> {
    let system = take_system(world)?;
    let report = system
        .drive(drive_request(), world.now, || MonotonicDeadline::ZERO)
        .await
        .map_err(display_error)?;
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("it returns the future WakeHint and exits")]
async fn then_future_wake_hint(world: &mut BddWorld) -> Result<(), String> {
    let report = world
        .drive_report
        .as_ref()
        .ok_or("drive report was missing")?;
    if report.counts.claimed != 0
        || report.has_immediately_visible_work
        || report.stop_reason != bg_jobs::DriveStopReason::NoVisibleWork
    {
        return Err(format!(
            "future work was treated as immediately useful: {report:?}"
        ));
    }
    if report.next_wake != WakeHint::At(Timestamp::from_millis(2_500)) {
        return Err(format!("unexpected wake hint: {:?}", report.next_wake));
    }
    Ok(())
}

#[given("the engine returned completion details after deleting the job")]
async fn given_completion_details(world: &mut BddWorld) -> Result<(), String> {
    given_registered_scoped_job(world).await?;
    when_enqueued_and_driven(world).await?;
    if world.completion.is_none() {
        return Err("engine did not return completion details".to_owned());
    }
    Ok(())
}

#[when("caller-owned audit persistence fails or is omitted")]
async fn when_caller_audit_fails(world: &mut BddWorld) -> Result<(), String> {
    world.audit_failed = true;
    world.completion = None;
    Ok(())
}

#[then("aux-common does not recreate or retry the completed job")]
async fn then_completed_job_stays_deleted(world: &mut BddWorld) -> Result<(), String> {
    if !world.audit_failed {
        return Err("caller audit failure was not simulated".to_owned());
    }
    let calls = world
        .handler_calls
        .as_ref()
        .ok_or("handler was not configured")?;
    if calls.load(Ordering::SeqCst) != 1 {
        return Err("completed job was retried after caller audit failure".to_owned());
    }
    assert_terminal_state_deleted(world, "completed job after caller audit failure").await?;
    let system = world.system.as_ref().ok_or("system was not configured")?;
    let retry = system
        .drive(drive_request(), world.now, || MonotonicDeadline::ZERO)
        .await
        .map_err(display_error)?;
    if retry.counts.claimed != 0 || !retry.completions.is_empty() {
        return Err(format!("completed job was retried: {retry:?}"));
    }
    Ok(())
}

async fn assert_terminal_state_deleted(world: &BddWorld, context: &str) -> Result<(), String> {
    let store = world.store.as_ref().ok_or("store was not configured")?;
    let system = world.system.as_ref().ok_or("system was not configured")?;
    let job = world.job.as_ref().ok_or("job was not configured")?;
    let observation = system
        .observe_lifecycle(job.job_id)
        .await
        .map_err(display_error)?;
    let LifecycleObservation::Terminal(receipt) = observation else {
        return Err(format!("{context} lost its operation receipt authority"));
    };
    if receipt.job_id != job.job_id || receipt.terminal != TerminalDisposition::Completed {
        return Err(format!("{context} retained the wrong terminal receipt"));
    }
    let expected_dedupe = job
        .deduplication
        .as_ref()
        .map(|dedupe| dedupe.key().as_bytes());
    let mut unexpected = Vec::new();
    let mut dedupe_retained = false;
    for (key, _) in store.snapshot().map_err(display_error)? {
        let decoded = KeyCodec::decode(&test_namespace(), &key).map_err(display_error)?;
        let retained = match decoded.tag {
            KeyTag::Operation => {
                decoded.components.len() == 1
                    && decoded.components[0].as_slice() == job.job_id.as_bytes()
            }
            KeyTag::Dedupe => {
                let matches_key = expected_dedupe.is_some_and(|expected| {
                    decoded.components.len() == 1 && decoded.components[0].as_slice() == expected
                });
                dedupe_retained |= matches_key;
                matches_key
            }
            KeyTag::FairReady => {
                decoded.components.len() == 1
                    && decoded.components[0].as_slice() == b"dispatch-state"
            }
            _ => false,
        };
        if !retained {
            unexpected.push((decoded.tag, decoded.components.len()));
        }
    }
    if expected_dedupe.is_some() && !dedupe_retained {
        return Err(format!("{context} lost its retained dedupe identity"));
    }
    if !unexpected.is_empty() {
        return Err(format!(
            "{context} left executable durable state: {unexpected:?}"
        ));
    }
    Ok(())
}

pub(crate) fn build_system(
    store: FakeStore,
    calls: Arc<AtomicUsize>,
) -> Result<JobSystem<FakeStore>, String> {
    build_system_with_owner(store, calls, 7)
}

pub(crate) fn test_namespace() -> Namespace {
    Namespace::try_new(b"bdd-jobs").expect("test namespace is valid")
}

pub(crate) fn build_system_with_owner(
    store: FakeStore,
    calls: Arc<AtomicUsize>,
    owner: u8,
) -> Result<JobSystem<FakeStore>, String> {
    let kind = JobKind::try_new("email").map_err(display_error)?;
    let queue = QueueName::try_new("default").map_err(display_error)?;
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind,
                schema_version: nonzero_u16(1)?,
                queue,
                effect_mode: EffectMode::Idempotent,
                cost_units: nonzero_u16(1)?,
                fairness_policy: FairnessPolicy::from(nonzero_u16(1)?),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: CountingHandler { calls },
            },
            None,
        )
        .map_err(display_error)?;
    crate::build_system(store, catalog, OwnerId::from([owner; 16]), None)
}

pub(crate) fn test_capabilities(
    max_key_bytes: usize,
    max_value_bytes: usize,
) -> Result<StoreCapabilities, String> {
    StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: nonzero_usize(max_key_bytes)?,
        max_value_bytes: nonzero_usize(max_value_bytes)?,
        max_get_many_keys: nonzero_u32(1_024)?,
        max_get_many_key_bytes: nonzero_usize(2 * 1024 * 1024)?,
        max_transaction_bytes: nonzero_usize(2 * 1024 * 1024)?,
        max_transaction_keys: nonzero_u32(1_024)?,
        max_range_items: nonzero_u32(1_024)?,
        max_range_bytes: nonzero_usize(2 * 1024 * 1024)?,
        max_transaction_duration: Duration::from_secs(1),
    })
    .map_err(display_error)
}

pub(crate) fn new_job(
    id: u8,
    payload: Bytes,
    fairness: FairnessClass,
    scheduled_at: Timestamp,
) -> Result<NewJob, String> {
    Ok(NewJob {
        job_id: JobId::from([id; 16]),
        kind: JobKind::try_new("email").map_err(display_error)?,
        schema_version: nonzero_u16(1)?,
        payload,
        fairness,
        ordering_key: None,
        priority: Priority::Default,
        scheduled_at,
        expires_at: None,
        retry_override: None,
        deduplication: None,
    })
}

pub(crate) fn scoped_fairness() -> FairnessClass {
    let key = match FairnessKey::try_new(b"opaque-primary") {
        Ok(value) => value,
        Err(error) => panic!("fixed BDD fairness key is valid: {error}"),
    };
    let path = FairnessPath::new(key, None);
    FairnessClass::from(path)
}

pub(crate) fn drive_request() -> DriveRequest {
    match DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nonzero_u32(4).expect("fixed BDD claim bound is non-zero"),
        max_concurrency: nonzero_u16(1).expect("fixed BDD concurrency bound is non-zero"),
        max_payload_bytes_in_flight: nonzero_usize(MAX_INLINE_PAYLOAD_BYTES)
            .expect("fixed BDD payload bound is non-zero"),
        max_completion_details: 4,
        max_store_operations: nonzero_u32(64).expect("fixed BDD store bound is non-zero"),
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    }) {
        Ok(request) => request,
        Err(error) => panic!("fixed BDD drive request is valid: {error}"),
    }
}

pub(crate) fn save_system(
    world: &mut BddWorld,
    store: FakeStore,
    system: JobSystem<FakeStore>,
    calls: Arc<AtomicUsize>,
    job: NewJob,
    now: Timestamp,
) {
    world.store = Some(store);
    world.system = Some(system);
    world.handler_calls = Some(calls);
    world.job = Some(job);
    world.now = now;
}

pub(crate) fn take_system(world: &mut BddWorld) -> Result<JobSystem<FakeStore>, String> {
    world
        .system
        .take()
        .ok_or_else(|| "system was not configured".to_owned())
}

pub(crate) fn nonzero_u16(value: u16) -> Result<NonZeroU16, String> {
    NonZeroU16::new(value).ok_or_else(|| "expected non-zero u16".to_owned())
}

pub(crate) fn nonzero_u32(value: u32) -> Result<NonZeroU32, String> {
    NonZeroU32::new(value).ok_or_else(|| "expected non-zero u32".to_owned())
}

pub(crate) fn nonzero_usize(value: usize) -> Result<NonZeroUsize, String> {
    NonZeroUsize::new(value).ok_or_else(|| "expected non-zero usize".to_owned())
}

pub(crate) fn display_error<E: std::fmt::Display>(error: E) -> String {
    error.to_string()
}
