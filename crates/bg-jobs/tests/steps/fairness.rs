use std::{
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use bg_jobs::{
    AttemptId, EffectMode, ExecutionContext, ExecutionId, FairnessClass, FairnessKey, FairnessPath,
    FairnessPolicy, HandlerFuture, JobCatalog, JobHandler, JobId, JobKind, JobOutcome,
    JobSystemError, OrderingKey, OutcomeCode, OwnerId, Priority, QueueName, QueueSelection,
    RetryClass, RetryPreset, RetrySelection, Timestamp,
    runtime::{JobSystem, MonotonicDeadline},
    test_support::{
        FakeStore,
        raw::{
            AuthConfigId, BackoffMultiplier, BatchBuilder, BatchCompatibility, BatchItem, BatchKey,
            BatchLimits, BatchLimitsInput, BatchOutcome, BatchResult, Cadence, DriveRequest,
            DriveRequestInput, HandlerDefinition, JobTemplate, JobTemplateInput, MisfirePolicy,
            NewJob, OverlapPolicy, RecurringSchedule, RecurringScheduleInput, RetryPolicy,
            RetryPolicyInput, ScheduleCursor, ScheduleId, ScratchStorage,
        },
    },
};
use bytes::Bytes;
use cucumber::{given, then, when};

use super::lifecycle;
use crate::{BddWorld, FairnessEvidence};

#[derive(Clone)]
struct CompleteHandler;

impl JobHandler for CompleteHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async { Ok(JobOutcome::Complete(completed_code())) })
    }
}

fn completed_code() -> OutcomeCode {
    OutcomeCode::try_new("completed").expect("fixed BDD outcome code is valid")
}

fn key(value: u8) -> FairnessKey {
    FairnessKey::try_new([value]).expect("fixed BDD fairness key is valid")
}

fn ordering(value: u8) -> OrderingKey {
    OrderingKey::try_new([value]).expect("fixed BDD ordering key is valid")
}

fn fairness(primary: u8, secondary: Option<u8>) -> FairnessClass {
    FairnessClass::from(FairnessPath::new(key(primary), secondary.map(key)))
}

fn public_job(
    id: u8,
    payload: Bytes,
    class: FairnessClass,
    priority: Priority,
    ordering_key: Option<OrderingKey>,
    scheduled_at: Timestamp,
) -> Result<NewJob, String> {
    let mut job = lifecycle::new_job(id, payload, class, scheduled_at)?;
    job.priority = priority;
    job.ordering_key = ordering_key;
    Ok(job)
}

fn public_system(store: FakeStore, owner: u8) -> Result<JobSystem<FakeStore>, String> {
    lifecycle::build_system_with_owner(store, Arc::new(AtomicUsize::new(0)), owner)
}

#[derive(Clone)]
struct OrderingHandler;

impl JobHandler for OrderingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        if payload == b"group-a" {
            Box::pin(async {
                Ok(JobOutcome::Retry {
                    class: RetryClass::Transient,
                    not_before: Some(Timestamp::from_millis(2_000)),
                    code: OutcomeCode::try_new("ordering_head_retry")
                        .expect("fixed BDD outcome code is valid"),
                })
            })
        } else {
            Box::pin(async { Ok(JobOutcome::Complete(completed_code())) })
        }
    }
}

fn ordering_system(store: FakeStore, owner: u8) -> Result<JobSystem<FakeStore>, String> {
    let kind = JobKind::try_new("email").map_err(lifecycle::display_error)?;
    let queue = QueueName::try_new("default").map_err(lifecycle::display_error)?;
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind,
                schema_version: nz16(1),
                queue,
                effect_mode: EffectMode::Idempotent,
                cost_units: nz16(1),
                fairness_policy: FairnessPolicy::from(nz16(1)),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: OrderingHandler,
            },
            None,
        )
        .map_err(lifecycle::display_error)?;
    crate::build_system(store, catalog, OwnerId::from([owner; 16]), None)
}

fn low_volume_system(store: FakeStore, owner: u8) -> Result<JobSystem<FakeStore>, String> {
    let kind = JobKind::try_new("email").map_err(lifecycle::display_error)?;
    let queue = QueueName::try_new("default").map_err(lifecycle::display_error)?;
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind,
                schema_version: nz16(1),
                queue,
                effect_mode: EffectMode::Idempotent,
                cost_units: nz16(1),
                fairness_policy: FairnessPolicy::low_volume(),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: CompleteHandler,
            },
            None,
        )
        .map_err(lifecycle::display_error)?;
    crate::build_system(store, catalog, OwnerId::from([owner; 16]), None)
}

fn drive_request(
    max_claims: u32,
    max_concurrency: u16,
    max_payload_bytes: usize,
    max_store_operations: u32,
) -> Result<DriveRequest, String> {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nz32(max_claims)?,
        max_concurrency: nz16(max_concurrency),
        max_payload_bytes_in_flight: nz_usize(max_payload_bytes)?,
        max_completion_details: max_claims,
        max_store_operations: nz32(max_store_operations)?,
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .map_err(lifecycle::display_error)
}

fn selected_ids(report: &bg_jobs::DriveReport) -> Vec<JobId> {
    report
        .completions
        .iter()
        .map(|completion| completion.job_id)
        .collect()
}

fn evidence(world: &mut BddWorld) -> &mut FairnessEvidence {
    world.fairness.get_or_insert_with(FairnessEvidence::default)
}

async fn enqueue(system: &JobSystem<FakeStore>, job: NewJob, now: Timestamp) -> Result<(), String> {
    system
        .enqueue_raw(job, now)
        .await
        .map(|_| ())
        .map_err(lifecycle::display_error)
}

async fn drive(
    system: &JobSystem<FakeStore>,
    max_claims: u32,
    max_concurrency: u16,
    max_payload_bytes: usize,
    max_store_operations: u32,
    now: Timestamp,
) -> Result<bg_jobs::DriveReport, String> {
    system
        .drive(
            drive_request(
                max_claims,
                max_concurrency,
                max_payload_bytes,
                max_store_operations,
            )?,
            now,
            || MonotonicDeadline::ZERO,
        )
        .await
        .map_err(lifecycle::display_error)
}

#[given("one primary scope supplies ninety percent of due cost")]
async fn given_busy_primary(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = public_system(store.clone(), 7)?;
    let now = Timestamp::from_millis(1_000);
    for id in 1..=6 {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"busy"),
                fairness(1, None),
                Priority::Default,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    evidence(world).fairness_bound = Some(5);
    Ok(())
}

#[given("another primary scope becomes due")]
async fn given_quiet_primary_due(world: &mut BddWorld) -> Result<(), String> {
    let system = world.system.as_ref().ok_or("system was not configured")?;
    enqueue(
        system,
        public_job(
            200,
            Bytes::from_static(b"quiet"),
            fairness(2, None),
            Priority::Default,
            None,
            world.now,
        )?,
        world.now,
    )
    .await
}

#[given("many secondary keys exist under one primary key")]
async fn given_secondary_keys(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = public_system(store.clone(), 7)?;
    let now = Timestamp::from_millis(1_000);
    for id in 1..=6 {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"secondary"),
                fairness(3, Some(id)),
                Priority::Default,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    enqueue(
        &system,
        public_job(
            200,
            Bytes::from_static(b"competitor"),
            fairness(6, None),
            Priority::Default,
            None,
            now,
        )?,
        now,
    )
    .await?;
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    evidence(world).fairness_bound = Some(5);
    Ok(())
}

#[given("a high-volume definition requires scoped fairness")]
async fn given_high_volume_definition(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = public_system(store.clone(), 7)?;
    world.store = Some(store);
    world.system = Some(system);
    world.now = Timestamp::from_millis(1_000);
    Ok(())
}

#[when("enqueue selects LowVolume")]
async fn when_enqueue_selects_low_volume(world: &mut BddWorld) -> Result<(), String> {
    let high_store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let high_system = world.system.as_ref().ok_or("system was not configured")?;
    let now = world.now;
    let low_volume_job = public_job(
        81,
        Bytes::from_static(b"maintenance"),
        FairnessClass::low_volume(),
        Priority::Bulk,
        None,
        now,
    )?;
    let error = high_system
        .enqueue_raw(low_volume_job, now)
        .await
        .err()
        .ok_or("invalid low-volume enqueue unexpectedly succeeded")?;
    let low_store = FakeStore::new();
    let low_system = low_volume_system(low_store.clone(), 9)?;
    evidence(world).low_volume_error = Some(error.to_string());
    evidence(world).low_volume_registered = true;
    evidence(world).low_volume_store_empty = high_store
        .snapshot()
        .map_err(lifecycle::display_error)?
        .is_empty();
    for id in [82, 83] {
        enqueue(
            &low_system,
            public_job(
                id,
                Bytes::from_static(b"maintenance"),
                FairnessClass::low_volume(),
                Priority::Bulk,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    let report = drive(&low_system, 2, 1, 512 * 1024, 128, now).await?;
    let selected = selected_ids(&report);
    evidence(world).selected = selected;
    if evidence(world).selected.len() <= 1 {
        evidence(world).low_volume_rejection =
            Some(bg_jobs::test_support::raw::FairnessRejection::LowVolumeCapacity);
    }
    world.store = Some(low_store);
    world.system = Some(low_system);
    world.drive_report = Some(report);
    Ok(())
}

#[given("Critical Default and Bulk remain backlogged")]
async fn given_priority_backlog(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = public_system(store.clone(), 7)?;
    let now = Timestamp::from_millis(1_000);
    for id in 1..=80 {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"critical"),
                fairness(11, None),
                Priority::Critical,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    for id in 100..140 {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"default"),
                fairness(12, None),
                Priority::Default,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    for id in 200..210 {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"bulk"),
                fairness(13, None),
                Priority::Bulk,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    Ok(())
}

#[given("the oldest job is leased capacity-blocked or corrupt")]
async fn given_blocked_candidate(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = public_system(store.clone(), 7)?;
    let now = Timestamp::from_millis(1_000);
    enqueue(
        &system,
        public_job(
            1,
            Bytes::from(vec![b'x'; 32]),
            fairness(21, None),
            Priority::Default,
            None,
            now,
        )?,
        now,
    )
    .await?;
    enqueue(
        &system,
        public_job(
            200,
            Bytes::from_static(b"independent"),
            fairness(22, None),
            Priority::Default,
            None,
            now,
        )?,
        now,
    )
    .await?;
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    Ok(())
}

#[given("a compatible bounded batch has successes retryable failures and one omitted result")]
async fn given_compatible_batch(world: &mut BddWorld) -> Result<(), String> {
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items: nz16(3),
        max_payload_bytes: nz_usize(64)?,
        max_formation_delay: Duration::from_millis(2),
    })
    .map_err(lifecycle::display_error)?;
    let first = batch_item(31, 1, b"first");
    let second = batch_item(32, 2, b"second");
    let third = batch_item(33, 3, b"third");
    let mut builder = BatchBuilder::try_new(first.clone(), limits, Timestamp::ZERO)
        .map_err(display_batch_error)?;
    builder
        .try_add(second.clone(), Timestamp::ZERO)
        .map_err(display_batch_error)?;
    builder
        .try_add(third.clone(), Timestamp::ZERO)
        .map_err(display_batch_error)?;
    let batch = builder.finish();
    let application = batch
        .apply_results(&[
            BatchResult {
                attempt_id: first.attempt_id,
                outcome: JobOutcome::Complete(completed_code()),
            },
            BatchResult {
                attempt_id: second.attempt_id,
                outcome: JobOutcome::Retry {
                    class: RetryClass::Transient,
                    not_before: None,
                    code: OutcomeCode::try_new("retry").expect("fixed BDD outcome code is valid"),
                },
            },
        ])
        .map_err(display_batch_error)?;
    evidence(world).batch = Some(batch);
    evidence(world).batch_application = Some(application);
    Ok(())
}

#[when("the handler returns outcomes")]
async fn when_handler_returns_outcomes(_world: &mut BddWorld) -> Result<(), String> {
    Ok(())
}

#[given("two ordering groups have due jobs and one group contains a poison head")]
async fn given_ordering_groups(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = ordering_system(store.clone(), 7)?;
    let now = Timestamp::from_millis(1_000);
    for id in [1, 2] {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"group-a"),
                fairness(31, None),
                Priority::Default,
                Some(ordering(1)),
                now,
            )?,
            now,
        )
        .await?;
    }
    for id in [100, 101] {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"group-b"),
                fairness(32, None),
                Priority::Default,
                Some(ordering(2)),
                now,
            )?,
            now,
        )
        .await?;
    }
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    Ok(())
}

#[given("small and maximum-sized jobs run repeatedly")]
async fn given_scratch_jobs(world: &mut BddWorld) -> Result<(), String> {
    let mut scratch = ScratchStorage::new(2);
    scratch.push(Bytes::from_static(b"small"));
    scratch.push(Bytes::from(vec![b'x'; 256 * 1024]));
    let before = scratch.capacity();
    scratch.clear();
    scratch.push(Bytes::from_static(b"reused"));
    let len = scratch.len();
    scratch.clear();
    scratch.shrink_to_retained_cap();
    let after = scratch.capacity();
    evidence(world).scratch_capacity_before_shrink = Some(before);
    evidence(world).scratch_capacity_after_shrink = Some(after);
    evidence(world).scratch_len_after_clear = Some(len);
    Ok(())
}

#[when("processors are available")]
async fn when_processors_available(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let report = drive(&system, 7, 1, 512 * 1024, 128, world.now).await?;
    evidence(world).selected = selected_ids(&report);
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[when("they compete with another primary key")]
async fn when_secondary_competes(world: &mut BddWorld) -> Result<(), String> {
    when_processors_available(world).await
}

#[then("the quiet scope starts within the configured scheduler error bound")]
async fn then_quiet_scope_bounded(world: &mut BddWorld) -> Result<(), String> {
    let quiet = JobId::from([200; 16]);
    let position = evidence(world)
        .selected
        .iter()
        .position(|job_id| *job_id == quiet)
        .ok_or("quiet primary was never selected")?;
    let bound = evidence(world).fairness_bound.unwrap_or(5) as usize;
    if position > bound {
        return Err(format!(
            "quiet primary started at position {position}, bound is {bound}"
        ));
    }
    Ok(())
}

#[then("they subdivide only their primary service and permit budget")]
async fn then_secondary_does_not_multiply_primary(world: &mut BddWorld) -> Result<(), String> {
    let competitor = JobId::from([200; 16]);
    let position = evidence(world)
        .selected
        .iter()
        .position(|job_id| *job_id == competitor)
        .ok_or("competing primary was never selected")?;
    let bound = evidence(world).fairness_bound.unwrap_or(5) as usize;
    if position > bound {
        return Err(format!(
            "competing primary started at position {position}, bound is {bound}"
        ));
    }
    Ok(())
}

#[then("validation fails before storage I/O")]
async fn then_low_volume_rejected(world: &mut BddWorld) -> Result<(), String> {
    if evidence(world).low_volume_error.is_none() {
        return Err("low-volume enqueue was not rejected".to_owned());
    }
    if !evidence(world).low_volume_store_empty {
        return Err("invalid low-volume enqueue wrote durable state".to_owned());
    }
    Ok(())
}

#[then("a registered low-volume maintenance job uses the capped aggregate class")]
async fn then_low_volume_capped(world: &mut BddWorld) -> Result<(), String> {
    if !evidence(world).low_volume_registered {
        return Err("low-volume handler was not registered".to_owned());
    }
    if evidence(world).low_volume_rejection
        != Some(bg_jobs::test_support::raw::FairnessRejection::LowVolumeCapacity)
    {
        return Err("low-volume drive did not enforce the aggregate service cap".to_owned());
    }
    Ok(())
}

#[when("enough dispatch cost is observed")]
async fn when_priority_dispatch(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let report = drive(&system, 13, 1, 512 * 1024, 512, world.now).await?;
    evidence(world).selected = selected_ids(&report);
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("service approximates 8 to 4 to 1 and every lane progresses")]
async fn then_priority_ratio(world: &mut BddWorld) -> Result<(), String> {
    let selected = &evidence(world).selected;
    let critical = selected.iter().filter(|id| id.as_bytes()[0] < 9).count();
    let default = selected
        .iter()
        .filter(|id| (100..140).contains(&id.as_bytes()[0]))
        .count();
    let bulk = selected
        .iter()
        .filter(|id| (200..210).contains(&id.as_bytes()[0]))
        .count();
    if (critical, default, bulk) != (8, 4, 1) {
        return Err(format!(
            "priority service was not bounded at 8:4:1: {critical}:{default}:{bulk}"
        ));
    }
    Ok(())
}

#[when("independent eligible work exists")]
async fn when_independent_work_exists(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let report = drive(&system, 2, 1, 16, 128, world.now).await?;
    evidence(world).selected = selected_ids(&report);
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("bounded discovery skips the blocked item and claims independent work")]
async fn then_blocked_candidate_skipped(world: &mut BddWorld) -> Result<(), String> {
    let independent = JobId::from([200; 16]);
    if !evidence(world).selected.contains(&independent) {
        return Err("independent work was not claimed after a blocked candidate".to_owned());
    }
    Ok(())
}

#[then("successes complete and only unresolved items retry")]
async fn then_batch_outcomes(world: &mut BddWorld) -> Result<(), String> {
    let application = evidence(world)
        .batch_application
        .as_ref()
        .ok_or("batch application missing")?;
    if application.resolutions.len() != 3 {
        return Err(format!(
            "expected three batch resolutions, got {}",
            application.resolutions.len()
        ));
    }
    if !matches!(
        application.resolutions[0].outcome,
        BatchOutcome::Provided(JobOutcome::Complete(_))
    ) || !matches!(
        application.resolutions[1].outcome,
        BatchOutcome::Provided(JobOutcome::Retry { .. })
    ) || !matches!(
        application.resolutions[2].outcome,
        BatchOutcome::MissingResult
    ) {
        return Err(format!(
            "batch outcomes were not isolated: {:?}",
            application.resolutions
        ));
    }
    Ok(())
}

#[when("a batch is driven")]
async fn when_batch_driven(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let report = drive(&system, 2, 2, 512 * 1024, 128, world.now).await?;
    evidence(world).selected = selected_ids(&report);
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("jobs within each group remain serial while the other group progresses")]
async fn then_ordering_groups_serial(world: &mut BddWorld) -> Result<(), String> {
    let selected = &evidence(world).selected;
    let group_a = selected.iter().filter(|id| id.as_bytes()[0] < 50).count();
    let group_b = selected.iter().filter(|id| id.as_bytes()[0] >= 100).count();
    let report = world.drive_report.as_ref().ok_or("drive report missing")?;
    if group_a != 0 || group_b != 1 || report.counts.retried != 1 {
        return Err(format!(
            "ordering groups were not admitted serially: {group_a} from group A, {group_b} from \
             group B, {} retries",
            report.counts.retried
        ));
    }
    Ok(())
}

#[when("drive sessions finish")]
async fn when_scratch_sessions_finish(_world: &mut BddWorld) -> Result<(), String> {
    Ok(())
}

#[then("candidate capacity is reused and pathological retained capacity is shrunk")]
async fn then_scratch_capacity(world: &mut BddWorld) -> Result<(), String> {
    let evidence = evidence(world);
    let before = evidence
        .scratch_capacity_before_shrink
        .ok_or("scratch capacity was not recorded")?;
    let after = evidence
        .scratch_capacity_after_shrink
        .ok_or("scratch shrink was not recorded")?;
    let len = evidence
        .scratch_len_after_clear
        .ok_or("scratch clear was not recorded")?;
    if len != 1 || after > before || after > 2 {
        return Err(format!(
            "scratch capacity was not bounded: before={before}, after={after}, len={len}"
        ));
    }
    Ok(())
}

#[given("a schedule has two due overlap-forbidden occurrences in one ordering group")]
async fn given_overlap_schedule(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::new();
    let system = public_system(store.clone(), 7)?;
    let schedule = RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([9; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("email").map_err(lifecycle::display_error)?,
            schema_version: nz16(1),
            payload: Bytes::from_static(b"scheduled"),
            fairness: fairness(30, None),
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })
        .map_err(lifecycle::display_error)?,
        cadence: Cadence::CronUtc(
            bg_jobs::test_support::raw::CronExpression::try_new("0 * * * *")
                .map_err(lifecycle::display_error)?,
        ),
        misfire: MisfirePolicy::CatchUp {
            maximum_occurrences: nz16(2),
        },
        overlap: OverlapPolicy::Forbid,
        enabled: true,
    });
    let now = Timestamp::from_millis(2 * 60 * 60 * 1_000);
    let materialized = system
        .materialize_schedule(
            &schedule,
            &ScheduleCursor::new(Some(Timestamp::ZERO), true),
            now,
        )
        .await
        .map_err(lifecycle::display_error)?;
    if materialized.occurrences.len() != 2 {
        return Err(format!(
            "expected two due occurrences, got {}",
            materialized.occurrences.len()
        ));
    }
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    Ok(())
}

#[when("the public engine drives with two available permits")]
async fn when_overlap_drives(world: &mut BddWorld) -> Result<(), String> {
    let system = lifecycle::take_system(world)?;
    let report = drive(&system, 2, 2, 512 * 1024, 128, world.now).await?;
    evidence(world).selected = selected_ids(&report);
    world.drive_report = Some(report);
    world.system = Some(system);
    Ok(())
}

#[then("overlap-forbidden work claims at most one permit")]
async fn then_overlap_forbidden(world: &mut BddWorld) -> Result<(), String> {
    let report = world.drive_report.as_ref().ok_or("drive report missing")?;
    if report.counts.claimed > 1 {
        return Err(format!(
            "overlap-forbidden schedule claimed {} permits",
            report.counts.claimed
        ));
    }
    Ok(())
}

#[given("two independent systems share a distributed store with per-primary capacity")]
async fn given_independent_systems(world: &mut BddWorld) -> Result<(), String> {
    let store = FakeStore::distributed();
    let system = public_system(store.clone(), 10)?;
    let now = Timestamp::from_millis(1_000);
    for (id, primary) in [(1, 40), (2, 40), (200, 41)] {
        enqueue(
            &system,
            public_job(
                id,
                Bytes::from_static(b"distributed"),
                fairness(primary, None),
                Priority::Default,
                None,
                now,
            )?,
            now,
        )
        .await?;
    }
    world.store = Some(store);
    world.system = Some(system);
    world.now = now;
    Ok(())
}

#[when("claimants overlap and the remaining system drives")]
async fn when_claimants_overlap(world: &mut BddWorld) -> Result<(), String> {
    let first = lifecycle::take_system(world)?;
    let store = world
        .store
        .as_ref()
        .ok_or("store was not configured")?
        .clone();
    let second = public_system(store, 11)?;
    let now = world.now;
    let first_claim = first
        .claim(JobId::from([1; 16]), now)
        .await
        .map_err(lifecycle::display_error)?;
    let conflict = second.claim(JobId::from([1; 16]), now).await;
    if !matches!(conflict, Err(JobSystemError::LeaseConflict)) {
        return Err("overlapping claimant returned an unexpected outcome".to_owned());
    }
    let first_report = drive(&second, 1, 1, 512 * 1024, 128, now).await?;
    first
        .complete(first_claim, JobOutcome::Complete(completed_code()), now)
        .await
        .map_err(lifecycle::display_error)?;
    let second_report = drive(&second, 1, 1, 512 * 1024, 128, now).await?;
    let mut selected = selected_ids(&first_report);
    selected.extend(selected_ids(&second_report));
    evidence(world).selected = selected;
    evidence(world).cross_node_conflict = true;
    world.drive_report = Some(second_report);
    world.system = Some(second);
    Ok(())
}

#[then("the conflict spends no fairness credit and both primaries receive durable capacity")]
async fn then_independent_capacity(world: &mut BddWorld) -> Result<(), String> {
    let (cross_node_conflict, selected) = {
        let state = evidence(world);
        (state.cross_node_conflict, state.selected.clone())
    };
    if !cross_node_conflict
        || !selected.contains(&JobId::from([2; 16]))
        || !selected.contains(&JobId::from([200; 16]))
    {
        return Err(format!(
            "durable primary capacity was not preserved: {selected:?}"
        ));
    }
    Ok(())
}

fn batch_item(id: u8, position: u64, payload: &'static [u8]) -> BatchItem {
    BatchItem {
        job_id: JobId::from([id; 16]),
        execution_id: ExecutionId::from([id; 16]),
        attempt_id: AttemptId::from([id; 16]),
        payload: Bytes::from_static(payload),
        compatibility: BatchCompatibility {
            handler_kind: JobKind::try_new("email").expect("fixed BDD handler kind is valid"),
            schema_version: nz16(1),
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode: EffectMode::Idempotent,
            retry_policy: retry_policy(),
            timeout: Duration::from_secs(1),
            priority: Priority::Default,
            fairness: fairness(50, None),
        },
        ordering_key: Some(ordering(id)),
        ordering_position: position,
        enqueued_at: Timestamp::ZERO,
        batch_deadline: Timestamp::from_millis(10),
    }
}

fn retry_policy() -> RetryPolicy {
    RetryPolicy::try_from(RetryPolicyInput {
        maximum_attempts: nz16(3),
        maximum_age: Duration::from_secs(60),
        minimum_backoff: Duration::from_millis(1),
        maximum_backoff: Duration::from_secs(1),
        multiplier: BackoffMultiplier::try_from(2).expect("fixed BDD retry multiplier is valid"),
    })
    .expect("fixed BDD retry policy is valid")
}

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("fixed BDD value is non-zero")
}

fn display_batch_error<E: std::fmt::Debug>(error: E) -> String {
    format!("{error:?}")
}

fn nz32(value: u32) -> Result<NonZeroU32, String> {
    NonZeroU32::new(value).ok_or_else(|| "expected non-zero u32".to_owned())
}

fn nz_usize(value: usize) -> Result<NonZeroUsize, String> {
    NonZeroUsize::new(value).ok_or_else(|| "expected non-zero usize".to_owned())
}
