use std::{
    cell::Cell,
    future::Future,
    hint::black_box,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    pin::Pin,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use alloc_counter::AllocationGuard;
use bg_jobs::{
    AttemptId, DriveReport, DriveStopReason, EffectMode, ExecutionContext, ExecutionId,
    FairnessClass, FairnessKey, FairnessPath, FairnessPolicy, HandlerFuture, JobCatalog,
    JobHandler, JobId, JobKind, JobOutcome, Namespace, OutcomeCode, OwnerId, Priority, QueueName,
    QueueSelection, RetryClass, RetryPreset, RetrySelection, Timestamp, WakeHint,
    runtime::{JobSystem, JobSystemBuilder, MonotonicDeadline},
    store::{
        CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_support::{
        FakeStore, FakeStoreError,
        raw::{
            ActivePulseReport, ActivePulseRequest, ActivePulseStopReason, AuthConfigId, Batch,
            BatchBuilder, BatchCompatibility, BatchItem, BatchKey, BatchLimits, BatchLimitsInput,
            BatchOutcome, BatchResult, Cadence, CandidateBlock, CronExpression, DriveCounts,
            DriveRequest, DriveRequestInput, FairCandidateInput, FairCandidateState, FairRelease,
            FairScope, FairnessBudget, FairnessBudgetInput, FairnessLedger, FairnessRejection,
            HandlerDefinition, JobTemplate, JobTemplateInput, MisfirePolicy, NORMALIZATION_SCALE,
            OutcomeResult, OverlapPolicy, RecurringSchedule, RecurringScheduleInput, RenewalResult,
            RetryPolicy, ScheduleCursor, ScheduleId, ScopeSnapshot, ScratchStorage, WakeCandidates,
            WakeWatermark, normalized_service_error,
        },
    },
};
use bytes::Bytes;

mod common;

const SEED: u64 = 0x5eed_cafe_0123_4567;
const JOBS: usize = 48;
const ROUNDS: usize = 3;
const RECOVERY_JOBS: usize = 12;
const NOW: Timestamp = Timestamp::from_millis(1_700_000_000_000);
const PAYLOAD_MIX: [usize; 8] = [64, 512, 4_096, 32_768, 128, 1_024, 8_192, 65_536];
const RECOVERY_PAYLOAD_MIX: [usize; 4] = [64, 512, 4_096, 32_768];
const FAIR_NOISY_JOBS: usize = 40;
const FAIR_PRE_QUIET_JOBS: usize = 8;
const FAIR_QUIET_JOBS: usize = 4;
const FAIR_COST_MIX: [u16; 4] = [1, 2, 1, 3];
const FAIR_PAYLOAD_MIX: [usize; 4] = [64, 512, 4_096, 32_768];
const BATCH_ITEMS: usize = 6;
const BATCH_PAYLOAD_MIX: [usize; 6] = [64, 128, 256, 512, 1_024, 2_048];
const SCRATCH_PAYLOADS: usize = 12;
const SCRATCH_RETAINED_CAPACITY: usize = 4;
const NOISY_PRIMARY: u8 = 0x11;
const QUIET_PRIMARY: u8 = 0x22;
const CONFLICT_PRIMARY: u8 = 0x33;
const BLOCKED_PRIMARY: u8 = 0x44;
const P04_IDLE_DRIVES: usize = 8;
const P04_WAKE_EARLY_MILLIS: i64 = 5_000;
const P04_WAKE_REPAIRED_MILLIS: i64 = 30_000;
const P04_MATERIALIZATION_INTERVAL_MILLIS: i64 = 15 * 60 * 1_000;
const P04_MATERIALIZATION_BACKLOG: i64 = 8;
const P04_CATCH_UP_LIMIT: u16 = 4;

#[test]
#[ignore = "debug-only performance harness; run through just bg-jobs-perf"]
fn given_fixed_workload_when_running_lifecycle_then_reports_metrics() {
    let mode = std::env::var("BG_JOBS_PERF_MODE").unwrap_or_else(|_| "manual".to_owned());
    assert!(matches!(mode.as_str(), "baseline" | "candidate" | "manual"));
    for round in 0..ROUNDS {
        let (store, counters) = CountingStore::new();
        let system = build_system(store.clone());
        let jobs = workload(round);
        let guard = AllocationGuard::start(
            module_path!(),
            "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        let report = block_on(run_workload(&system, jobs));
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        let counts = counters.snapshot();
        println!(
            concat!(
                "bg_jobs_perf mode={} round={} seed={} jobs={} ",
                "payload_bytes={} gets={} ranges={} commits={} get_key_bytes={} ",
                "range_request_key_bytes={} range_result_bytes={} transaction_bytes={} ",
                "allocations={} allocated_bytes={} elapsed_nanos={} succeeded={}"
            ),
            mode,
            round,
            SEED,
            JOBS,
            report.payload_bytes,
            counts.gets,
            counts.ranges,
            counts.commits,
            counts.get_key_bytes,
            counts.range_request_key_bytes,
            counts.range_result_bytes,
            counts.transaction_bytes,
            allocations.allocation_count,
            allocations.allocated_bytes,
            elapsed_nanos,
            report.succeeded,
        );
        run_recovery_workload(&mode, round);
        run_fair_batch_workload(&mode, round);
        run_schedule_wake_workload(&mode, round);
    }
}

struct WorkloadReport {
    payload_bytes: usize,
    succeeded: u32,
}

async fn run_workload(
    system: &JobSystem<CountingStore>,
    jobs: Vec<bg_jobs::test_support::raw::NewJob>,
) -> WorkloadReport {
    let payload_bytes = jobs.iter().map(|job| job.payload.len()).sum();
    for job in jobs {
        let result = system.enqueue_raw(job, NOW).await;
        assert!(
            result.is_ok(),
            "deterministic enqueue must succeed: {result:?}"
        );
    }
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nonzero_u32(JOBS as u32),
        max_concurrency: nonzero_u16(1),
        max_payload_bytes_in_flight: nonzero_usize(384 * 1024),
        max_completion_details: JOBS as u32,
        max_store_operations: nonzero_u32((JOBS * 24) as u32),
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX / 2),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("fixed drive budget is valid");
    let report = system
        .drive(request, NOW, || MonotonicDeadline::ZERO)
        .await
        .expect("fixed lifecycle drive must succeed");
    assert_eq!(report.counts.claimed, JOBS as u32);
    assert_eq!(report.counts.succeeded, JOBS as u32);
    assert_eq!(report.completions.len(), JOBS);
    assert!(!report.has_immediately_visible_work);
    WorkloadReport {
        payload_bytes,
        succeeded: report.counts.succeeded,
    }
}

fn workload(round: usize) -> Vec<bg_jobs::test_support::raw::NewJob> {
    (0..JOBS)
        .map(|index| {
            let payload_size = PAYLOAD_MIX[(index + round) % PAYLOAD_MIX.len()];
            bg_jobs::test_support::raw::NewJob {
                job_id: JobId::from(job_id_bytes(index)),
                kind: JobKind::try_new("perf-job").expect("fixed kind is valid"),
                schema_version: nonzero_u16(1),
                payload: payload(index, payload_size),
                fairness: fairness(index),
                ordering_key: None,
                priority: Priority::Default,
                scheduled_at: NOW,
                expires_at: None,
                retry_override: None,
                deduplication: None,
            }
        })
        .collect()
}

fn payload(index: usize, length: usize) -> Bytes {
    let mut value = Vec::with_capacity(length);
    let mut state = SEED ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for _ in 0..length {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        value.push((state >> 32) as u8);
    }
    Bytes::from(value)
}

fn job_id_bytes(index: usize) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&SEED.wrapping_add(index as u64).to_be_bytes());
    bytes[8..].copy_from_slice(&(index as u64).to_be_bytes());
    bytes
}

fn fairness(index: usize) -> FairnessClass {
    let key = format!("scope-{}", index % 4);
    FairnessClass::from(FairnessPath::new(
        FairnessKey::try_new(key.as_bytes()).expect("fixed fairness key is valid"),
        None,
    ))
}

struct CompletingHandler {
    outcome: OutcomeCode,
}

impl JobHandler for CompletingHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let outcome = self.outcome.clone();
        Box::pin(async move { Ok(JobOutcome::Complete(outcome)) })
    }
}

fn build_system(store: CountingStore) -> JobSystem<CountingStore> {
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind: JobKind::try_new("perf-job").expect("fixed kind is valid"),
                schema_version: nonzero_u16(1),
                queue: QueueName::try_new("perf").expect("fixed queue is valid"),
                effect_mode: EffectMode::Idempotent,
                cost_units: nonzero_u16(1),
                fairness_policy: FairnessPolicy::from(nonzero_u16(1)),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: CompletingHandler {
                    outcome: OutcomeCode::try_new("completed").expect("fixed outcome is valid"),
                },
            },
            None,
        )
        .expect("fixed handler registration is valid");
    JobSystemBuilder::new(store)
        .catalog(catalog)
        .namespace(Namespace::try_new(b"perf").expect("fixed namespace is valid"))
        .owner(OwnerId::from([7; 16]))
        .scheduler(common::wake_scheduler())
        .build()
        .expect("fixed performance job system")
}

fn run_recovery_workload(mode: &str, round: usize) {
    run_retry_phase(mode, round);
    run_renewal_phase(mode, round);
    run_crash_phase(mode, round);
}

struct FairBatchMeasurement {
    e_bound: u64,
    e_scaled_bound: u128,
    max_error_scaled: u128,
    noisy_cost_before: u64,
    noisy_cost_after: u64,
    noisy_cost_after_insert: u64,
    quiet_cost: u64,
    quiet_dwell: u32,
    fair_attempts: u32,
    fair_selects: u32,
    fair_rejections: u32,
    conflicts: u32,
    failed_claims: u32,
    failed_credit_before: u64,
    failed_credit_after: u64,
    conflict_credit_before: u64,
    conflict_credit_after: u64,
    batch_items: u32,
    batch_results: u32,
    batch_provided: u32,
    batch_retry_invariants: u32,
    batch_missing: u32,
    scratch_capacity_expanded: usize,
    scratch_capacity_after_clear: usize,
    scratch_capacity_after_shrink: usize,
    payload_drops: u32,
    operations: u64,
}

struct FairnessMeasurement {
    e_bound: u64,
    e_scaled_bound: u128,
    max_error_scaled: u128,
    noisy_cost_before: u64,
    noisy_cost_after: u64,
    noisy_cost_after_insert: u64,
    quiet_cost: u64,
    quiet_dwell: u32,
    fair_attempts: u32,
    fair_selects: u32,
    fair_rejections: u32,
    conflicts: u32,
    failed_claims: u32,
    failed_credit_before: u64,
    failed_credit_after: u64,
    conflict_credit_before: u64,
    conflict_credit_after: u64,
}

struct FairTailMeasurement {
    noisy_cost_after: u64,
    noisy_cost_after_insert: u64,
    quiet_dwell: u32,
    fair_attempts: u32,
    fair_selects: u32,
    fair_rejections: u32,
    max_error_scaled: u128,
}

struct BatchMeasurement {
    items: u32,
    results: u32,
    provided: u32,
    retry_invariants: u32,
    missing: u32,
}

struct ScratchMeasurement {
    expanded_capacity: usize,
    after_clear_capacity: usize,
    after_shrink_capacity: usize,
    payload_drops: u32,
}

fn run_fair_batch_workload(mode: &str, round: usize) {
    let guard = AllocationGuard::start(
        module_path!(),
        "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
        file!(),
        line!(),
        Some(mode),
    );
    let started = Instant::now();
    let measurement = measure_fair_batch(round);
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    print_fair_batch_metrics(
        mode,
        round,
        measurement,
        allocations.allocation_count,
        allocations.allocated_bytes,
        elapsed_nanos,
    );
}

fn measure_fair_batch(round: usize) -> FairBatchMeasurement {
    let fairness = measure_fairness(round);
    let batch = measure_batch(round);
    let scratch = measure_scratch(round);
    let operations = u64::from(fairness.fair_attempts)
        + u64::from(fairness.fair_selects)
        + u64::from(batch.items)
        + u64::from(batch.results)
        + SCRATCH_PAYLOADS as u64;
    FairBatchMeasurement {
        e_bound: fairness.e_bound,
        e_scaled_bound: fairness.e_scaled_bound,
        max_error_scaled: fairness.max_error_scaled,
        noisy_cost_before: fairness.noisy_cost_before,
        noisy_cost_after: fairness.noisy_cost_after,
        noisy_cost_after_insert: fairness.noisy_cost_after_insert,
        quiet_cost: fairness.quiet_cost,
        quiet_dwell: fairness.quiet_dwell,
        fair_attempts: fairness.fair_attempts,
        fair_selects: fairness.fair_selects,
        fair_rejections: fairness.fair_rejections,
        conflicts: fairness.conflicts,
        failed_claims: fairness.failed_claims,
        failed_credit_before: fairness.failed_credit_before,
        failed_credit_after: fairness.failed_credit_after,
        conflict_credit_before: fairness.conflict_credit_before,
        conflict_credit_after: fairness.conflict_credit_after,
        batch_items: batch.items,
        batch_results: batch.results,
        batch_provided: batch.provided,
        batch_retry_invariants: batch.retry_invariants,
        batch_missing: batch.missing,
        scratch_capacity_expanded: scratch.expanded_capacity,
        scratch_capacity_after_clear: scratch.after_clear_capacity,
        scratch_capacity_after_shrink: scratch.after_shrink_capacity,
        payload_drops: scratch.payload_drops,
        operations,
    }
}

fn print_fair_batch_metrics(
    mode: &str,
    round: usize,
    metrics: FairBatchMeasurement,
    allocations: u64,
    allocated_bytes: u64,
    elapsed_nanos: u128,
) {
    let throughput_milli = metrics
        .operations
        .saturating_mul(1_000_000_000_000)
        .checked_div(elapsed_nanos.max(1) as u64)
        .unwrap_or(u64::MAX);
    println!(
        concat!(
            "bg_jobs_perf mode={} round={} phase=fair_batch seed={} time_millis={} ",
            "e_bound={} e_scaled_bound={} max_error_scaled={} noisy_cost_before={} ",
            "noisy_cost_after={} noisy_cost_after_insert={} quiet_cost={} quiet_dwell={} ",
            "fair_attempts={} fair_selects={} fair_rejections={} conflicts={} failed_claims={} ",
            "failed_credit_before={} failed_credit_after={} conflict_credit_before={} ",
            "conflict_credit_after={} batch_items={} batch_results={} ",
            "batch_provided={} batch_retry_invariants={} batch_missing={} ",
            "scratch_capacity_expanded={} scratch_capacity_after_clear={} ",
            "scratch_capacity_after_shrink={} payload_drops={} gets=0 ranges=0 commits=0 ",
            "transaction_bytes=0 operations={} throughput_milli={} allocations={} ",
            "allocated_bytes={} elapsed_nanos={}"
        ),
        mode,
        round,
        SEED,
        NOW.as_millis(),
        metrics.e_bound,
        metrics.e_scaled_bound,
        metrics.max_error_scaled,
        metrics.noisy_cost_before,
        metrics.noisy_cost_after,
        metrics.noisy_cost_after_insert,
        metrics.quiet_cost,
        metrics.quiet_dwell,
        metrics.fair_attempts,
        metrics.fair_selects,
        metrics.fair_rejections,
        metrics.conflicts,
        metrics.failed_claims,
        metrics.failed_credit_before,
        metrics.failed_credit_after,
        metrics.conflict_credit_before,
        metrics.conflict_credit_after,
        metrics.batch_items,
        metrics.batch_results,
        metrics.batch_provided,
        metrics.batch_retry_invariants,
        metrics.batch_missing,
        metrics.scratch_capacity_expanded,
        metrics.scratch_capacity_after_clear,
        metrics.scratch_capacity_after_shrink,
        metrics.payload_drops,
        metrics.operations,
        throughput_milli,
        allocations,
        allocated_bytes,
        elapsed_nanos,
    );
}

fn measure_fairness(round: usize) -> FairnessMeasurement {
    let budget = fair_batch_budget();
    let e_bound = budget.normalized_error_bound();
    let e_scaled_bound = u128::from(e_bound) * u128::from(NORMALIZATION_SCALE);
    let mut ledger = FairnessLedger::new(budget);
    let noise_ids = add_noise_candidates(&mut ledger, round);
    let (conflict_credit_before, conflict_credit_after) = measure_conflict(&mut ledger, round);
    let (failed_claims, failed_credit_before, failed_credit_after) =
        measure_failed_claim(&mut ledger, round);
    for job_id in noise_ids.iter().take(FAIR_PRE_QUIET_JOBS) {
        settle_fair_candidate(&mut ledger, *job_id);
    }
    let noisy_cost_before = scope_snapshot(&ledger, NOISY_PRIMARY).served_cost;
    let quiet_ids = add_quiet_candidates(&mut ledger, round);
    let tail = drain_fair_tail(
        &mut ledger,
        &noise_ids,
        &quiet_ids,
        noisy_cost_before,
        e_bound,
    );
    let quiet_cost = scope_snapshot(&ledger, QUIET_PRIMARY).served_cost;
    assert!(tail.max_error_scaled <= e_scaled_bound);
    assert!(tail.noisy_cost_after_insert <= e_bound);
    FairnessMeasurement {
        e_bound,
        e_scaled_bound,
        max_error_scaled: tail.max_error_scaled,
        noisy_cost_before,
        noisy_cost_after: tail.noisy_cost_after,
        noisy_cost_after_insert: tail.noisy_cost_after_insert,
        quiet_cost,
        quiet_dwell: tail.quiet_dwell,
        fair_attempts: tail.fair_attempts + FAIR_PRE_QUIET_JOBS as u32 + 3,
        fair_selects: tail.fair_selects + FAIR_PRE_QUIET_JOBS as u32 + 2,
        fair_rejections: tail.fair_rejections,
        conflicts: 1,
        failed_claims,
        failed_credit_before,
        failed_credit_after,
        conflict_credit_before,
        conflict_credit_after,
    }
}

fn fair_batch_budget() -> FairnessBudget {
    FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nonzero_u32(8),
        max_concurrency_per_scope: nonzero_u32(2),
        max_rate_per_scope: nonzero_u32(32),
        max_low_volume_service: nonzero_u32(1),
        max_payload_bytes: nonzero_usize(64 * 1024),
        max_cost_units: nonzero_u16(3),
    })
    .expect("fixed fair batch budget is valid")
}

fn add_noise_candidates(ledger: &mut FairnessLedger, round: usize) -> Vec<JobId> {
    (0..FAIR_NOISY_JOBS)
        .map(|index| {
            let job_id = fairness_job_id(round, 0, index);
            ledger
                .add_candidate(fair_candidate(job_id, NOISY_PRIMARY, index, None))
                .expect("fixed noisy candidate is valid");
            job_id
        })
        .collect()
}

fn add_quiet_candidates(ledger: &mut FairnessLedger, round: usize) -> Vec<JobId> {
    (0..FAIR_QUIET_JOBS)
        .map(|index| {
            let job_id = fairness_job_id(round, 1, index);
            ledger
                .add_candidate(fair_candidate(job_id, QUIET_PRIMARY, index, None))
                .expect("fixed quiet candidate is valid");
            job_id
        })
        .collect()
}

fn fair_candidate(
    job_id: JobId,
    primary: u8,
    index: usize,
    block: Option<CandidateBlock>,
) -> FairCandidateInput {
    FairCandidateInput {
        job_id,
        fairness: scoped_fairness(primary),
        priority: Priority::Default,
        cost_units: nonzero_u16(FAIR_COST_MIX[index % FAIR_COST_MIX.len()]),
        scheduled_at: NOW,
        payload_bytes: FAIR_PAYLOAD_MIX[index % FAIR_PAYLOAD_MIX.len()],
        ordering_key: None,
        ordering_position: 0,
        block,
    }
}

fn measure_conflict(ledger: &mut FairnessLedger, round: usize) -> (u64, u64) {
    let job_id = fairness_job_id(round, 2, 0);
    ledger
        .add_candidate(fair_candidate(job_id, CONFLICT_PRIMARY, 2, None))
        .expect("fixed conflict candidate is valid");
    ledger.reset_priority_window();
    let before = scope_snapshot(ledger, CONFLICT_PRIMARY).served_cost;
    let permit = ledger.select(job_id).expect("conflict candidate selects");
    ledger
        .release(permit, FairRelease::Conflict)
        .expect("conflict release is valid");
    let after = scope_snapshot(ledger, CONFLICT_PRIMARY).served_cost;
    assert_eq!(
        before, after,
        "conflicts must not spend fair service credit"
    );
    ledger.reset_priority_window();
    let permit = ledger.select(job_id).expect("retry candidate selects");
    ledger
        .release(permit, FairRelease::Complete)
        .expect("conflicted candidate completes");
    (before, after)
}

fn measure_failed_claim(ledger: &mut FairnessLedger, round: usize) -> (u32, u64, u64) {
    let job_id = fairness_job_id(round, 3, 0);
    let scope = scoped_scope(BLOCKED_PRIMARY);
    ledger
        .add_candidate(fair_candidate(
            job_id,
            BLOCKED_PRIMARY,
            3,
            Some(CandidateBlock::Leased),
        ))
        .expect("fixed blocked candidate is valid");
    let before = scope_snapshot(ledger, BLOCKED_PRIMARY).served_cost;
    ledger.reset_priority_window();
    assert_eq!(
        ledger.select(job_id),
        Err(FairnessRejection::Blocked(CandidateBlock::Leased))
    );
    let after = scope_snapshot(ledger, BLOCKED_PRIMARY).served_cost;
    assert_eq!(
        before, after,
        "failed claims must not spend fair service credit"
    );
    assert!(ledger.scope_snapshot(&scope).is_some());
    (1, before, after)
}

fn drain_fair_tail(
    ledger: &mut FairnessLedger,
    noise_ids: &[JobId],
    quiet_ids: &[JobId],
    noisy_cost_before: u64,
    e_bound: u64,
) -> FairTailMeasurement {
    let mut fair_attempts = 0;
    let mut fair_selects = 0;
    let mut fair_rejections = 0;
    let mut max_error_scaled = 0;
    let mut quiet_dwell = None;
    let mut noisy_cost_after_insert = None;
    let max_iterations = (noise_ids.len() + quiet_ids.len()) * 8;
    while fair_attempts < max_iterations as u32 {
        ledger.tick();
        fair_attempts += 1;
        let Some(noisy) = first_ready_candidate(ledger, noise_ids) else {
            let quiet = first_ready_candidate(ledger, quiet_ids).expect("quiet work remains");
            quiet_dwell.get_or_insert(scope_snapshot(ledger, QUIET_PRIMARY).quiet_dwell);
            noisy_cost_after_insert
                .get_or_insert(scope_snapshot(ledger, NOISY_PRIMARY).served_cost);
            fair_attempts += 1;
            settle_fair_candidate(ledger, quiet);
            fair_selects += 1;
            update_fair_error(ledger, &mut max_error_scaled);
            continue;
        };
        ledger.reset_priority_window();
        match ledger.select(noisy) {
            Ok(permit) => {
                ledger.release(permit, FairRelease::Complete).unwrap();
                fair_selects += 1;
            }
            Err(FairnessRejection::NormalizedServiceBound) => {
                fair_rejections += 1;
                let quiet = first_ready_candidate(ledger, quiet_ids)
                    .expect("fair bound rejection requires quiet work");
                quiet_dwell.get_or_insert(scope_snapshot(ledger, QUIET_PRIMARY).quiet_dwell);
                noisy_cost_after_insert
                    .get_or_insert(scope_snapshot(ledger, NOISY_PRIMARY).served_cost);
                fair_attempts += 1;
                settle_fair_candidate(ledger, quiet);
                fair_selects += 1;
            }
            Err(error) => panic!("unexpected fair candidate rejection: {error:?}"),
        }
        update_fair_error(ledger, &mut max_error_scaled);
        if first_ready_candidate(ledger, noise_ids).is_none()
            && first_ready_candidate(ledger, quiet_ids).is_none()
        {
            break;
        }
    }
    let noisy_cost_after = scope_snapshot(ledger, NOISY_PRIMARY).served_cost;
    let quiet_dwell = quiet_dwell.expect("quiet candidate must be selected");
    assert!(
        fair_attempts < max_iterations as u32,
        "fair workload must stay bounded"
    );
    assert!(first_ready_candidate(ledger, noise_ids).is_none());
    assert!(first_ready_candidate(ledger, quiet_ids).is_none());
    let noisy_cost_after_insert = noisy_cost_after_insert
        .expect("quiet selection records post-insertion noisy service")
        .saturating_sub(noisy_cost_before);
    assert!(noisy_cost_after_insert <= e_bound);
    FairTailMeasurement {
        noisy_cost_after,
        noisy_cost_after_insert,
        quiet_dwell,
        fair_attempts,
        fair_selects,
        fair_rejections,
        max_error_scaled,
    }
}

fn update_fair_error(ledger: &FairnessLedger, maximum: &mut u128) {
    if let Some(error) = current_fair_error(ledger) {
        *maximum = (*maximum).max(error);
    }
}

fn current_fair_error(ledger: &FairnessLedger) -> Option<u128> {
    let noisy = ledger.scope_snapshot(&scoped_scope(NOISY_PRIMARY))?;
    let quiet = ledger.scope_snapshot(&scoped_scope(QUIET_PRIMARY))?;
    if noisy.ready && quiet.ready {
        Some(normalized_service_error(
            noisy.served_cost,
            quiet.served_cost,
            noisy.weight,
        ))
    } else {
        None
    }
}

fn first_ready_candidate(ledger: &FairnessLedger, ids: &[JobId]) -> Option<JobId> {
    ids.iter().copied().find(|job_id| {
        ledger
            .candidate_state(*job_id)
            .is_some_and(FairCandidateState::has_ready_route)
    })
}

fn settle_fair_candidate(ledger: &mut FairnessLedger, job_id: JobId) -> u64 {
    ledger.reset_priority_window();
    let permit = ledger.select(job_id).expect("fair candidate selects");
    let cost = u64::from(permit.cost_units().get());
    ledger
        .release(permit, FairRelease::Complete)
        .expect("fair candidate completes");
    cost
}

fn scope_snapshot(ledger: &FairnessLedger, primary: u8) -> ScopeSnapshot {
    ledger
        .scope_snapshot(&scoped_scope(primary))
        .expect("fair primary scope exists")
}

fn scoped_scope(primary: u8) -> FairScope {
    FairScope::from(&scoped_fairness(primary))
}

fn scoped_fairness(primary: u8) -> FairnessClass {
    FairnessClass::from(FairnessPath::new(
        FairnessKey::try_new([primary]).expect("fixed fair primary key is valid"),
        None,
    ))
}

fn fairness_job_id(round: usize, lane: usize, index: usize) -> JobId {
    JobId::from(job_id_bytes(10_000 + round * 1_000 + lane * 100 + index))
}

fn measure_batch(round: usize) -> BatchMeasurement {
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items: nonzero_u16(BATCH_ITEMS as u16),
        max_payload_bytes: nonzero_usize(8 * 1024),
        max_formation_delay: Duration::from_millis(5),
    })
    .expect("fixed batch limits are valid");
    let mut builder = BatchBuilder::try_new(batch_item(round, 0), limits, NOW)
        .expect("first fixed batch item is valid");
    for index in 1..BATCH_ITEMS {
        builder
            .try_add(batch_item(round, index), NOW)
            .expect("fixed batch item is compatible");
    }
    let batch = builder.finish();
    let results = batch_results(&batch);
    let application = batch
        .apply_results(&results)
        .expect("fixed batch results are known");
    let mut provided = 0;
    let mut retry_invariants = 0;
    let mut missing = 0;
    for resolution in &application.resolutions {
        match resolution.outcome {
            BatchOutcome::Provided(_) => provided += 1,
            BatchOutcome::RetryInvariant => retry_invariants += 1,
            BatchOutcome::MissingResult => missing += 1,
            BatchOutcome::DeferredOrdering => panic!("unordered perf batch cannot defer"),
        }
    }
    black_box(&application);
    BatchMeasurement {
        items: batch.items().len() as u32,
        results: results.len() as u32,
        provided,
        retry_invariants,
        missing,
    }
}

fn batch_results(batch: &Batch) -> Vec<BatchResult> {
    let complete = OutcomeCode::try_new("batch-complete").expect("fixed batch outcome is valid");
    let retry = OutcomeCode::try_new("batch-retry").expect("fixed retry outcome is valid");
    let mut results = Vec::with_capacity(batch.items().len());
    for (index, item) in batch.items().iter().enumerate() {
        if index == batch.items().len() - 1 {
            continue;
        }
        let outcome = if index == 0 {
            JobOutcome::Complete(complete.clone())
        } else {
            JobOutcome::Retry {
                class: RetryClass::Transient,
                not_before: None,
                code: retry.clone(),
            }
        };
        results.push(BatchResult {
            attempt_id: item.attempt_id,
            outcome,
        });
        if index == 0 {
            results.push(BatchResult {
                attempt_id: item.attempt_id,
                outcome: JobOutcome::Complete(complete.clone()),
            });
        }
    }
    results
}

fn batch_item(round: usize, index: usize) -> BatchItem {
    let id = job_id_bytes(20_000 + round * 100 + index);
    BatchItem {
        job_id: JobId::from(id),
        execution_id: ExecutionId::from(id),
        attempt_id: AttemptId::from(id),
        payload: payload(index + round * BATCH_ITEMS, BATCH_PAYLOAD_MIX[index]),
        compatibility: BatchCompatibility {
            handler_kind: JobKind::try_new("batch-perf").expect("fixed batch kind is valid"),
            schema_version: nonzero_u16(1),
            batch_key: BatchKey::new(7),
            auth_config: AuthConfigId::new(9),
            effect_mode: EffectMode::Idempotent,
            retry_policy: RetryPolicy::preset(RetryPreset::Interactive),
            timeout: Duration::from_secs(1),
            priority: Priority::Default,
            fairness: scoped_fairness(NOISY_PRIMARY),
        },
        ordering_key: None,
        ordering_position: index as u64,
        enqueued_at: NOW,
        batch_deadline: Timestamp::from_millis(NOW.as_millis() + 100),
    }
}

fn measure_scratch(round: usize) -> ScratchMeasurement {
    let drops = Rc::new(Cell::new(0));
    let mut scratch = ScratchStorage::new(SCRATCH_RETAINED_CAPACITY);
    for index in 0..SCRATCH_PAYLOADS {
        scratch.push(TrackedPayload {
            payload: payload(index + round * SCRATCH_PAYLOADS, 512),
            drops: Rc::clone(&drops),
        });
    }
    let expanded_capacity = scratch.capacity();
    scratch.clear();
    let after_clear_capacity = scratch.capacity();
    assert_eq!(drops.get(), SCRATCH_PAYLOADS as u32);
    scratch.shrink_to_retained_cap();
    let after_shrink_capacity = scratch.capacity();
    assert!(after_shrink_capacity <= SCRATCH_RETAINED_CAPACITY);
    black_box(scratch.as_slice());
    ScratchMeasurement {
        expanded_capacity,
        after_clear_capacity,
        after_shrink_capacity,
        payload_drops: drops.get(),
    }
}

struct TrackedPayload {
    payload: Bytes,
    drops: Rc<Cell<u32>>,
}

impl Drop for TrackedPayload {
    fn drop(&mut self) {
        self.drops.set(self.drops.get().saturating_add(1));
        black_box(&self.payload);
    }
}

fn run_schedule_wake_workload(mode: &str, round: usize) {
    let idle = measure_idle_drives();
    println!(
        concat!(
            "bg_jobs_perf mode={} round={} phase=p04_idle seed={} drives={} ",
            "no_work={} gets={} ranges={} commits={} committed={} ",
            "get_key_bytes={} range_request_key_bytes={} range_result_bytes={} ",
            "transaction_bytes={} ranges_per_drive_milli={} allocations={} ",
            "allocated_bytes={} elapsed_nanos={}"
        ),
        mode,
        round,
        SEED,
        idle.drives,
        idle.no_work,
        idle.counts.gets,
        idle.counts.ranges,
        idle.counts.commits,
        idle.counts.committed,
        idle.counts.get_key_bytes,
        idle.counts.range_request_key_bytes,
        idle.counts.range_result_bytes,
        idle.counts.transaction_bytes,
        per_unit_milli(idle.counts.ranges, idle.drives),
        idle.allocations,
        idle.allocated_bytes,
        idle.elapsed_nanos,
    );

    let wake = measure_wake_path();
    println!(
        concat!(
            "bg_jobs_perf mode={} round={} phase=p04_wake seed={} ",
            "lower_accepts={} duplicate_ignores={} lost_wakes={} repairs={} ",
            "repair_ignores={} loss_step={} repair_step={} repair_lag_steps={} ",
            "wake_lag_millis={} merged_duplicate_hints={} merged_repair_hints={}"
        ),
        mode,
        round,
        SEED,
        wake.lower_accepts,
        wake.duplicate_ignores,
        wake.lost_wakes,
        wake.repairs,
        wake.repair_ignores,
        wake.loss_step,
        wake.repair_step,
        wake.repair_lag_steps,
        wake.wake_lag_millis,
        wake.merged_duplicate_hints,
        wake.merged_repair_hints,
    );

    let pulse = measure_active_pulse();
    println!(
        concat!(
            "bg_jobs_perf mode={} round={} phase=p04_pulse seed={} ",
            "burst_drives={} burst_jobs={} burst_jobs_per_drive_milli={} burst_stop={:?} ",
            "first_empty_drives={} first_empty_jobs={} first_empty_stop={:?} ",
            "max_drives={} max_jobs={} max_stop={:?} deadline_drives={} ",
            "deadline_jobs={} deadline_stop={:?}"
        ),
        mode,
        round,
        SEED,
        pulse.burst_drives,
        pulse.burst_jobs,
        per_unit_milli(pulse.burst_jobs as u64, pulse.burst_drives),
        pulse.burst_stop,
        pulse.first_empty_drives,
        pulse.first_empty_jobs,
        pulse.first_empty_stop,
        pulse.max_drives,
        pulse.max_jobs,
        pulse.max_stop,
        pulse.deadline_drives,
        pulse.deadline_jobs,
        pulse.deadline_stop,
    );

    for (index, (name, policy, expected)) in [
        ("skip", MisfirePolicy::Skip, 0usize),
        ("fire_once", MisfirePolicy::FireOnce, 1usize),
        (
            "catch_up",
            MisfirePolicy::CatchUp {
                maximum_occurrences: nonzero_u16(P04_CATCH_UP_LIMIT),
            },
            usize::from(P04_CATCH_UP_LIMIT),
        ),
    ]
    .into_iter()
    .enumerate()
    {
        measure_materialization(mode, round, index, name, policy, expected);
    }
}

struct IdleMeasurement {
    drives: usize,
    no_work: usize,
    counts: StoreSnapshot,
    allocations: u64,
    allocated_bytes: u64,
    elapsed_nanos: u128,
}

fn measure_idle_drives() -> IdleMeasurement {
    let (store, counters) = CountingStore::new();
    let system = build_system(store);
    let request = p04_drive_request();
    let guard = AllocationGuard::start(
        module_path!(),
        "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
        file!(),
        line!(),
        Some("p04_idle"),
    );
    let started = Instant::now();
    let mut no_work = 0;
    for _ in 0..P04_IDLE_DRIVES {
        let report = block_on(system.drive(request.clone(), NOW, || MonotonicDeadline::ZERO))
            .expect("idle drive succeeds");
        assert_eq!(report.stop_reason, DriveStopReason::NoVisibleWork);
        assert_eq!(report.next_wake, WakeHint::None);
        assert!(!report.has_immediately_visible_work);
        no_work += 1;
        black_box(report);
    }
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    IdleMeasurement {
        drives: P04_IDLE_DRIVES,
        no_work,
        counts: counters.snapshot(),
        allocations: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
        elapsed_nanos,
    }
}

fn p04_drive_request() -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nonzero_u32(1),
        max_concurrency: nonzero_u16(1),
        max_payload_bytes_in_flight: nonzero_usize(64 * 1024),
        max_completion_details: 1,
        max_store_operations: nonzero_u32(16),
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX / 2),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("fixed idle drive budget is valid")
}

struct WakeMeasurement {
    lower_accepts: u32,
    duplicate_ignores: u32,
    lost_wakes: u32,
    repairs: u32,
    repair_ignores: u32,
    loss_step: u32,
    repair_step: u32,
    repair_lag_steps: u32,
    wake_lag_millis: i64,
    merged_duplicate_hints: u32,
    merged_repair_hints: u32,
}

fn measure_wake_path() -> WakeMeasurement {
    let early = Timestamp::from_millis(NOW.as_millis() + P04_WAKE_EARLY_MILLIS);
    let repaired = Timestamp::from_millis(NOW.as_millis() + P04_WAKE_REPAIRED_MILLIS);
    let mut watermark = WakeWatermark::new();
    let mut step = 0;
    let mut lower_accepts = 0;
    let mut duplicate_ignores = 0;
    assert!(watermark.lower(early));
    lower_accepts += 1;
    step += 1;
    if !watermark.lower(early) {
        duplicate_ignores += 1;
    }
    step += 1;
    let duplicate_merge = WakeCandidates {
        watermarks: vec![WakeHint::At(early), WakeHint::At(early)],
        due_heads: Vec::new(),
        schedule_heads: Vec::new(),
    }
    .merge(nonzero_u32(4));
    assert_eq!(duplicate_merge, WakeHint::At(early));
    duplicate_ignores += 1;
    let loss_step = step + 1;
    let repair_merge = WakeCandidates {
        watermarks: Vec::new(),
        due_heads: vec![WakeHint::At(repaired)],
        schedule_heads: Vec::new(),
    }
    .merge(nonzero_u32(4));
    assert_eq!(repair_merge, WakeHint::At(repaired));
    let repair_step = loss_step + 3;
    let mut repairs = 0;
    if watermark.raise_stale(Some(repaired)) {
        repairs += 1;
    }
    let repair_ignores = u32::from(!watermark.raise_stale(Some(repaired)));
    assert_eq!(watermark.hint(), WakeHint::At(repaired));
    black_box(step);
    WakeMeasurement {
        lower_accepts,
        duplicate_ignores,
        lost_wakes: 1,
        repairs,
        repair_ignores,
        loss_step,
        repair_step,
        repair_lag_steps: repair_step - loss_step,
        wake_lag_millis: repaired.as_millis() - early.as_millis(),
        merged_duplicate_hints: 2,
        merged_repair_hints: 1,
    }
}

struct PulseMeasurement {
    burst_drives: usize,
    burst_jobs: u32,
    burst_stop: ActivePulseStopReason,
    first_empty_drives: usize,
    first_empty_jobs: u32,
    first_empty_stop: ActivePulseStopReason,
    max_drives: usize,
    max_jobs: u32,
    max_stop: ActivePulseStopReason,
    deadline_drives: usize,
    deadline_jobs: u32,
    deadline_stop: ActivePulseStopReason,
}

fn measure_active_pulse() -> PulseMeasurement {
    let burst = run_pulse(
        ActivePulseRequest::new(nonzero_u16(8), MonotonicDeadline::from_nanos(100)),
        vec![
            pulse_report(2, true, DriveStopReason::NoVisibleWork),
            pulse_report(3, true, DriveStopReason::NoVisibleWork),
            pulse_report(0, false, DriveStopReason::NoVisibleWork),
        ],
        MonotonicDeadline::ZERO,
    );
    let first_empty = run_pulse(
        ActivePulseRequest::new(nonzero_u16(8), MonotonicDeadline::from_nanos(100)),
        vec![
            pulse_report(1, true, DriveStopReason::NoVisibleWork),
            pulse_report(1, true, DriveStopReason::NoVisibleWork),
            pulse_report(0, false, DriveStopReason::NoVisibleWork),
        ],
        MonotonicDeadline::ZERO,
    );
    let maximum = run_pulse(
        ActivePulseRequest::new(nonzero_u16(2), MonotonicDeadline::from_nanos(100)),
        vec![
            pulse_report(2, true, DriveStopReason::NoVisibleWork),
            pulse_report(2, true, DriveStopReason::NoVisibleWork),
            pulse_report(2, true, DriveStopReason::NoVisibleWork),
        ],
        MonotonicDeadline::ZERO,
    );
    let deadline = run_pulse(
        ActivePulseRequest::new(nonzero_u16(8), MonotonicDeadline::from_nanos(1)),
        vec![pulse_report(1, true, DriveStopReason::NoVisibleWork)],
        MonotonicDeadline::from_nanos(2),
    );
    PulseMeasurement {
        burst_drives: burst.drives.len(),
        burst_jobs: pulse_jobs(&burst),
        burst_stop: burst.stop_reason,
        first_empty_drives: first_empty.drives.len(),
        first_empty_jobs: pulse_jobs(&first_empty),
        first_empty_stop: first_empty.stop_reason,
        max_drives: maximum.drives.len(),
        max_jobs: pulse_jobs(&maximum),
        max_stop: maximum.stop_reason,
        deadline_drives: deadline.drives.len(),
        deadline_jobs: pulse_jobs(&deadline),
        deadline_stop: deadline.stop_reason,
    }
}

fn pulse_report(claimed: u32, immediate: bool, stop_reason: DriveStopReason) -> DriveReport {
    DriveReport {
        counts: DriveCounts {
            claimed,
            succeeded: claimed,
            ..DriveCounts::default()
        },
        completions: Vec::new(),
        completions_omitted: 0,
        has_immediately_visible_work: immediate,
        next_wake: if immediate {
            WakeHint::Now
        } else {
            WakeHint::None
        },
        stop_reason,
    }
}

fn run_pulse(
    request: ActivePulseRequest,
    reports: Vec<DriveReport>,
    now: MonotonicDeadline,
) -> ActivePulseReport {
    let mut reports = reports.into_iter();
    block_on(request.drive(
        move || now,
        move || {
            let report = reports.next().expect("fixed pulse has enough reports");
            async move { Ok::<DriveReport, ()>(report) }
        },
    ))
    .expect("fixed active pulse succeeds")
}

fn pulse_jobs(report: &ActivePulseReport) -> u32 {
    report.drives.iter().map(|drive| drive.counts.claimed).sum()
}

fn measure_materialization(
    mode: &str,
    round: usize,
    index: usize,
    policy_name: &str,
    policy: MisfirePolicy,
    expected_occurrences: usize,
) {
    let (store, counters) = CountingStore::new();
    let system = build_system(store);
    let (schedule, cursor, now) = p04_schedule(round, index, policy);
    let guard = AllocationGuard::start(
        module_path!(),
        "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
        file!(),
        line!(),
        Some(policy_name),
    );
    let started = Instant::now();
    let result = block_on(system.materialize_schedule(&schedule, &cursor, now))
        .expect("fixed schedule materialization succeeds");
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    assert_eq!(result.occurrences.len(), expected_occurrences);
    assert_eq!(
        result.occurrences.len() + result.skipped as usize,
        P04_MATERIALIZATION_BACKLOG as usize
    );
    let counts = counters.snapshot();
    let payload_bytes = result.occurrences.len() * schedule.job_template.payload.len();
    println!(
        concat!(
            "bg_jobs_perf mode={} round={} phase=p04_materialize policy={} seed={} ",
            "backlog={} occurrences={} skipped={} payload_bytes={} gets={} ranges={} ",
            "commits={} committed={} conflicts={} transaction_bytes={} ",
            "allocations={} allocated_bytes={} elapsed_nanos={} ",
            "commits_per_occurrence_milli={} transaction_bytes_per_occurrence_milli={} ",
            "allocations_per_occurrence_milli={} allocated_bytes_per_occurrence_milli={} ",
            "elapsed_nanos_per_occurrence_milli={} cron_parses={}"
        ),
        mode,
        round,
        policy_name,
        SEED,
        P04_MATERIALIZATION_BACKLOG,
        result.occurrences.len(),
        result.skipped,
        payload_bytes,
        counts.gets,
        counts.ranges,
        counts.commits,
        counts.committed,
        counts.conflicts,
        counts.transaction_bytes,
        allocations.allocation_count,
        allocations.allocated_bytes,
        elapsed_nanos,
        per_unit_milli(counts.commits, result.occurrences.len()),
        per_unit_milli(counts.transaction_bytes, result.occurrences.len()),
        per_unit_milli(allocations.allocation_count, result.occurrences.len()),
        per_unit_milli(allocations.allocated_bytes, result.occurrences.len()),
        per_unit_milli_u128(elapsed_nanos, result.occurrences.len()),
        1,
    );
}

fn p04_schedule(
    round: usize,
    index: usize,
    misfire: MisfirePolicy,
) -> (RecurringSchedule, ScheduleCursor, Timestamp) {
    let cron = CronExpression::try_new("*/15 * * * *").expect("fixed schedule cron parses");
    let schedule = RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([
            90u8.saturating_add(index as u8),
            round as u8,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
        ]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("perf-job").expect("fixed schedule kind is valid"),
            schema_version: nonzero_u16(1),
            payload: payload(30_000 + round * 3 + index, 512),
            fairness: scoped_fairness(NOISY_PRIMARY),
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: Some(RetrySelection::Preset(RetryPreset::Network)),
            deduplication: None,
        })
        .expect("fixed schedule template is valid"),
        cadence: Cadence::CronUtc(cron),
        misfire,
        overlap: OverlapPolicy::Allow,
        enabled: true,
    });
    let before = Timestamp::from_millis(
        NOW.as_millis() - P04_MATERIALIZATION_INTERVAL_MILLIS * P04_MATERIALIZATION_BACKLOG,
    );
    let cursor = schedule
        .cursor_after(before)
        .expect("fixed schedule cursor computes");
    let first_due = cursor.next_due().expect("fixed schedule has a first due");
    let now = Timestamp::from_millis(
        first_due.as_millis()
            + P04_MATERIALIZATION_INTERVAL_MILLIS * (P04_MATERIALIZATION_BACKLOG - 1),
    );
    (schedule, cursor, now)
}

fn per_unit_milli(value: u64, units: usize) -> u64 {
    if units == 0 {
        return 0;
    }
    value.saturating_mul(1_000) / units as u64
}

fn per_unit_milli_u128(value: u128, units: usize) -> u128 {
    if units == 0 {
        return 0;
    }
    value.saturating_mul(1_000) / units as u128
}

fn run_retry_phase(mode: &str, round: usize) {
    let (store, counters) = CountingStore::new();
    let system = build_system(store);
    let jobs = recovery_jobs(round, 1);
    let payload_bytes = jobs.iter().map(|job| job.payload.len()).sum::<usize>();
    let guard = AllocationGuard::start(
        module_path!(),
        "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
        file!(),
        line!(),
        Some(mode),
    );
    let started = Instant::now();
    let transitions = block_on(run_retry_transitions(&system, jobs));
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    let counts = counters.snapshot();
    assert_eq!(transitions.retries, RECOVERY_JOBS as u32);
    assert_eq!(transitions.completions, RECOVERY_JOBS as u32);
    assert_eq!(transitions.attempts, (RECOVERY_JOBS * 2) as u32);
    assert_eq!(counts.unknown, 0);
    assert_eq!(counts.conflicts, 0);
    print_recovery_metrics(RecoveryMetrics {
        mode,
        round,
        phase: "retry",
        payload_bytes,
        counts,
        allocations: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
        elapsed_nanos,
        transitions,
    });
}

fn run_renewal_phase(mode: &str, round: usize) {
    let (store, counters) = CountingStore::new();
    let system = build_system(store);
    let jobs = recovery_jobs(round, 2);
    let payload_bytes = jobs.iter().map(|job| job.payload.len()).sum::<usize>();
    let guard = AllocationGuard::start(
        module_path!(),
        "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
        file!(),
        line!(),
        Some(mode),
    );
    let started = Instant::now();
    let transitions = block_on(run_renewal_transitions(&system, jobs));
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    let counts = counters.snapshot();
    assert_eq!(transitions.renewals, (RECOVERY_JOBS * 2) as u32);
    assert_eq!(transitions.coalesced, RECOVERY_JOBS as u32);
    assert_eq!(transitions.completions, RECOVERY_JOBS as u32);
    assert_eq!(transitions.attempts, RECOVERY_JOBS as u32);
    assert_eq!(counts.unknown, 0);
    assert_eq!(counts.conflicts, 0);
    print_recovery_metrics(RecoveryMetrics {
        mode,
        round,
        phase: "renewal",
        payload_bytes,
        counts,
        allocations: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
        elapsed_nanos,
        transitions,
    });
}

fn run_crash_phase(mode: &str, round: usize) {
    let (store, counters) = CountingStore::new();
    let fault_store = store.inner.clone();
    let system = build_system(store);
    let jobs = recovery_jobs(round, 3);
    let payload_bytes = jobs.iter().map(|job| job.payload.len()).sum::<usize>();
    let guard = AllocationGuard::start(
        module_path!(),
        "given_fixed_workload_when_running_lifecycle_then_reports_metrics",
        file!(),
        line!(),
        Some(mode),
    );
    let started = Instant::now();
    let transitions = block_on(run_crash_transitions(&system, &fault_store, jobs));
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    let counts = counters.snapshot();
    let half_jobs = (RECOVERY_JOBS / 2) as u32;
    assert_eq!(transitions.retries, half_jobs);
    assert_eq!(transitions.completions, RECOVERY_JOBS as u32);
    assert_eq!(transitions.attempts, RECOVERY_JOBS as u32 + half_jobs);
    assert_eq!(transitions.unknown_before, half_jobs);
    assert_eq!(transitions.unknown_after, half_jobs);
    assert_eq!(counts.unknown, RECOVERY_JOBS as u64);
    assert_eq!(counts.conflicts, 0);
    print_recovery_metrics(RecoveryMetrics {
        mode,
        round,
        phase: "crash",
        payload_bytes,
        counts,
        allocations: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
        elapsed_nanos,
        transitions,
    });
}

async fn run_retry_transitions(
    system: &JobSystem<CountingStore>,
    jobs: Vec<bg_jobs::test_support::raw::NewJob>,
) -> RecoveryTransitions {
    let retry_code = OutcomeCode::try_new("transient").expect("fixed retry code is valid");
    let completion_code =
        OutcomeCode::try_new("completed").expect("fixed completion code is valid");
    let mut transitions = RecoveryTransitions::default();
    for job in jobs {
        let job_id = job.job_id;
        system
            .enqueue_raw(job, NOW)
            .await
            .expect("deterministic retry enqueue must succeed");
        let claim = system
            .claim(job_id, NOW)
            .await
            .expect("deterministic retry claim must succeed");
        let retry = system
            .apply_outcome(
                claim,
                JobOutcome::Retry {
                    class: RetryClass::Transient,
                    not_before: None,
                    code: retry_code.clone(),
                },
                NOW,
            )
            .await
            .expect("deterministic retry transition must succeed");
        let not_before = match retry {
            OutcomeResult::Retried { not_before, .. } => not_before,
            other => panic!("expected retry transition, got {other:?}"),
        };
        let claim = system
            .claim(job_id, not_before)
            .await
            .expect("deterministic retry reclaim must succeed");
        system
            .complete(
                claim,
                JobOutcome::Complete(completion_code.clone()),
                not_before,
            )
            .await
            .expect("deterministic retry completion must succeed");
        transitions.retries += 1;
        transitions.completions += 1;
        transitions.attempts += 2;
    }
    transitions
}

async fn run_renewal_transitions(
    system: &JobSystem<CountingStore>,
    jobs: Vec<bg_jobs::test_support::raw::NewJob>,
) -> RecoveryTransitions {
    let completion_code =
        OutcomeCode::try_new("completed").expect("fixed completion code is valid");
    let mut transitions = RecoveryTransitions::default();
    for job in jobs {
        let job_id = job.job_id;
        system
            .enqueue_raw(job, NOW)
            .await
            .expect("deterministic renewal enqueue must succeed");
        let mut claim = system
            .claim(job_id, NOW)
            .await
            .expect("deterministic renewal claim must succeed");
        assert!(matches!(
            system.renew(&mut claim, NOW).await,
            Ok(RenewalResult::Renewed { .. })
        ));
        assert!(matches!(
            system
                .renew(&mut claim, Timestamp::from_millis(NOW.as_millis() + 50))
                .await,
            Ok(RenewalResult::Coalesced { .. })
        ));
        assert!(matches!(
            system
                .renew(&mut claim, Timestamp::from_millis(NOW.as_millis() + 100))
                .await,
            Ok(RenewalResult::Renewed { .. })
        ));
        system
            .complete(
                claim,
                JobOutcome::Complete(completion_code.clone()),
                Timestamp::from_millis(NOW.as_millis() + 100),
            )
            .await
            .expect("deterministic renewal completion must succeed");
        transitions.renewals += 2;
        transitions.coalesced += 1;
        transitions.completions += 1;
        transitions.attempts += 1;
    }
    transitions
}

async fn run_crash_transitions(
    system: &JobSystem<CountingStore>,
    fault_store: &FakeStore,
    jobs: Vec<bg_jobs::test_support::raw::NewJob>,
) -> RecoveryTransitions {
    let retry_code = OutcomeCode::try_new("transient").expect("fixed retry code is valid");
    let completion_code =
        OutcomeCode::try_new("completed").expect("fixed completion code is valid");
    let mut transitions = RecoveryTransitions::default();
    for (index, job) in jobs.into_iter().enumerate() {
        let job_id = job.job_id;
        system
            .enqueue_raw(job, NOW)
            .await
            .expect("deterministic crash enqueue must succeed");
        let claim = system
            .claim(job_id, NOW)
            .await
            .expect("deterministic crash claim must succeed");
        if index % 2 == 0 {
            fault_store
                .queue_unknown_before_commit()
                .expect("unknown-before fault must queue");
            let retry = system
                .apply_outcome(
                    claim,
                    JobOutcome::Retry {
                        class: RetryClass::AmbiguousEffect,
                        not_before: None,
                        code: retry_code.clone(),
                    },
                    NOW,
                )
                .await
                .expect("unknown-before retry must reconcile");
            let not_before = match retry {
                OutcomeResult::Retried { not_before, .. } => not_before,
                other => panic!("expected crash retry transition, got {other:?}"),
            };
            let claim = system
                .claim(job_id, not_before)
                .await
                .expect("reconciled retry reclaim must succeed");
            system
                .complete(
                    claim,
                    JobOutcome::Complete(completion_code.clone()),
                    not_before,
                )
                .await
                .expect("reconciled retry completion must succeed");
            transitions.retries += 1;
            transitions.completions += 1;
            transitions.attempts += 2;
            transitions.unknown_before += 1;
        } else {
            fault_store
                .queue_unknown_after_commit()
                .expect("unknown-after fault must queue");
            system
                .complete(claim, JobOutcome::Complete(completion_code.clone()), NOW)
                .await
                .expect("unknown-after completion must reconcile");
            transitions.completions += 1;
            transitions.attempts += 1;
            transitions.unknown_after += 1;
        }
    }
    transitions
}

fn recovery_jobs(round: usize, phase: usize) -> Vec<bg_jobs::test_support::raw::NewJob> {
    (0..RECOVERY_JOBS)
        .map(|index| {
            let payload_size =
                RECOVERY_PAYLOAD_MIX[(index + round + phase) % RECOVERY_PAYLOAD_MIX.len()];
            bg_jobs::test_support::raw::NewJob {
                job_id: JobId::from(job_id_bytes(100 + phase * 32 + index + round * 256)),
                kind: JobKind::try_new("perf-job").expect("fixed kind is valid"),
                schema_version: nonzero_u16(1),
                payload: payload(index + phase * 32 + round * 256, payload_size),
                fairness: fairness(index),
                ordering_key: None,
                priority: Priority::Default,
                scheduled_at: NOW,
                expires_at: None,
                retry_override: None,
                deduplication: None,
            }
        })
        .collect()
}

#[derive(Default)]
struct RecoveryTransitions {
    retries: u32,
    renewals: u32,
    coalesced: u32,
    completions: u32,
    attempts: u32,
    unknown_before: u32,
    unknown_after: u32,
}

struct RecoveryMetrics<'a> {
    mode: &'a str,
    round: usize,
    phase: &'a str,
    payload_bytes: usize,
    counts: StoreSnapshot,
    allocations: u64,
    allocated_bytes: u64,
    elapsed_nanos: u128,
    transitions: RecoveryTransitions,
}

fn print_recovery_metrics(metrics: RecoveryMetrics<'_>) {
    let RecoveryMetrics {
        mode,
        round,
        phase,
        payload_bytes,
        counts,
        allocations,
        allocated_bytes,
        elapsed_nanos,
        transitions,
    } = metrics;
    println!(
        concat!(
            "bg_jobs_perf mode={} round={} phase={} seed={} jobs={} payload_bytes={} ",
            "gets={} ranges={} commits={} committed={} conflicts={} unknown={} ",
            "get_key_bytes={} range_request_key_bytes={} range_result_bytes={} \
             transaction_bytes={} ",
            "store_amplification_milli={} allocations={} allocated_bytes={} elapsed_nanos={} ",
            "retries={} renewals={} coalesced={} completions={} attempts={} ",
            "unknown_before={} unknown_after={}"
        ),
        mode,
        round,
        phase,
        SEED,
        RECOVERY_JOBS,
        payload_bytes,
        counts.gets,
        counts.ranges,
        counts.commits,
        counts.committed,
        counts.conflicts,
        counts.unknown,
        counts.get_key_bytes,
        counts.range_request_key_bytes,
        counts.range_result_bytes,
        counts.transaction_bytes,
        store_amplification_milli(counts.transaction_bytes, payload_bytes),
        allocations,
        allocated_bytes,
        elapsed_nanos,
        transitions.retries,
        transitions.renewals,
        transitions.coalesced,
        transitions.completions,
        transitions.attempts,
        transitions.unknown_before,
        transitions.unknown_after,
    );
}

fn store_amplification_milli(transaction_bytes: u64, payload_bytes: usize) -> u64 {
    if payload_bytes == 0 {
        return 0;
    }
    transaction_bytes
        .saturating_mul(1_000)
        .checked_div(payload_bytes as u64)
        .unwrap_or(u64::MAX)
}

#[derive(Clone)]
struct CountingStore {
    inner: FakeStore,
    counters: Arc<StoreCounters>,
}

impl CountingStore {
    fn new() -> (Self, Arc<StoreCounters>) {
        let counters = Arc::new(StoreCounters::default());
        (
            Self {
                inner: FakeStore::new(),
                counters: Arc::clone(&counters),
            },
            counters,
        )
    }
}

impl JobStore for CountingStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
        self.counters.gets.fetch_add(1, Ordering::Relaxed);
        self.counters
            .get_key_bytes
            .fetch_add(key.as_bytes().len() as u64, Ordering::Relaxed);
        self.inner.get(key)
    }

    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a {
        self.counters.gets.fetch_add(1, Ordering::Relaxed);
        self.counters.get_key_bytes.fetch_add(
            keys.iter()
                .map(|key| key.as_bytes().len() as u64)
                .sum::<u64>(),
            Ordering::Relaxed,
        );
        self.inner.get_many(keys)
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        self.counters.ranges.fetch_add(1, Ordering::Relaxed);
        let request_key_bytes = request
            .start()
            .into_iter()
            .chain(request.end())
            .chain(request.continuation())
            .map(|key| key.as_bytes().len() as u64)
            .sum::<u64>();
        self.counters
            .range_request_key_bytes
            .fetch_add(request_key_bytes, Ordering::Relaxed);
        let future = self.inner.read_range(request);
        let counters = Arc::clone(&self.counters);
        async move {
            let page = future.await?;
            counters
                .range_result_bytes
                .fetch_add(page.total_bytes() as u64, Ordering::Relaxed);
            Ok(page)
        }
    }

    fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> impl Future<Output = Result<CommitOutcome, Self::Error>> + Send + 'a {
        self.counters.commits.fetch_add(1, Ordering::Relaxed);
        self.counters
            .transaction_bytes
            .fetch_add(transaction.encoded_bytes() as u64, Ordering::Relaxed);
        let future = self.inner.commit(transaction);
        let counters = Arc::clone(&self.counters);
        async move {
            let outcome = future.await?;
            match outcome {
                CommitOutcome::Committed => counters.committed.fetch_add(1, Ordering::Relaxed),
                CommitOutcome::Conflict => counters.conflicts.fetch_add(1, Ordering::Relaxed),
                CommitOutcome::Unknown => counters.unknown.fetch_add(1, Ordering::Relaxed),
            };
            Ok(outcome)
        }
    }
}

#[derive(Default)]
struct StoreCounters {
    gets: AtomicU64,
    ranges: AtomicU64,
    commits: AtomicU64,
    committed: AtomicU64,
    conflicts: AtomicU64,
    unknown: AtomicU64,
    get_key_bytes: AtomicU64,
    range_request_key_bytes: AtomicU64,
    range_result_bytes: AtomicU64,
    transaction_bytes: AtomicU64,
}

struct StoreSnapshot {
    gets: u64,
    ranges: u64,
    commits: u64,
    committed: u64,
    conflicts: u64,
    unknown: u64,
    get_key_bytes: u64,
    range_request_key_bytes: u64,
    range_result_bytes: u64,
    transaction_bytes: u64,
}

impl StoreCounters {
    fn snapshot(&self) -> StoreSnapshot {
        StoreSnapshot {
            gets: self.gets.load(Ordering::Relaxed),
            ranges: self.ranges.load(Ordering::Relaxed),
            commits: self.commits.load(Ordering::Relaxed),
            committed: self.committed.load(Ordering::Relaxed),
            conflicts: self.conflicts.load(Ordering::Relaxed),
            unknown: self.unknown.load(Ordering::Relaxed),
            get_key_bytes: self.get_key_bytes.load(Ordering::Relaxed),
            range_request_key_bytes: self.range_request_key_bytes.load(Ordering::Relaxed),
            range_result_bytes: self.range_result_bytes.load(Ordering::Relaxed),
            transaction_bytes: self.transaction_bytes.load(Ordering::Relaxed),
        }
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    let mut future = Box::pin(future);
    loop {
        match Pin::as_mut(&mut future).poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn nonzero_u16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("fixed value is non-zero")
}

fn nonzero_u32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("fixed value is non-zero")
}

fn nonzero_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("fixed value is non-zero")
}
