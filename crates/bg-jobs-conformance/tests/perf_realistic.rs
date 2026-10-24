//! Broad debug-only performance evidence for the realistic pre-merge loop.
//!
//! This test intentionally runs the reusable fake/fault/conformance utilities
//! and HTTP batch classification together.  It does not claim production
//! database latency; the reported one-millisecond adjustment is a labelled
//! serial-round-trip model only.

#![cfg(not(target_arch = "wasm32"))]

use std::{
    future::Future,
    hint::black_box,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};

use alloc_counter::AllocationGuard;
use bg_jobs::{
    AttemptId, EffectMode, ExecutionContext, ExecutionId, FairnessClass, FairnessKey, FairnessPath,
    FairnessPolicy, HandlerFuture, JobCatalog, JobHandler, JobId, JobKind, JobOutcome, Namespace,
    OutcomeCode, OwnerId, Priority, QueueName, RetryPreset, RetrySelection, Timestamp, WakeHint,
    runtime::{JobSystem, JobSystemBuilder, MonotonicDeadline},
    store::{
        CommitOutcome, JobStore, RangePage, RangeRequest, StoreCapabilities, StoreKey,
        StoreTransaction,
    },
    test_support::{
        FakeStore,
        raw::{
            AuthConfigId, BatchBuilder, BatchCompatibility, BatchItem, BatchKey, BatchLimits,
            BatchLimitsInput, Cadence, CronExpression, DriveRequest, DriveRequestInput,
            FairCandidateInput, FairRelease, FairnessBudget, FairnessBudgetInput, FairnessLedger,
            HandlerDefinition, JobTemplate, JobTemplateInput, MisfirePolicy, NewJob, OverlapPolicy,
            RecurringSchedule, RecurringScheduleInput, RetryPolicy, ScheduleCursor, ScheduleId,
            WakeCandidates, WakeWatermark,
        },
    },
};
use bg_jobs_conformance::{ConformanceConfig, FaultStore, run_basic, run_faults};
use bg_jobs_http::{
    ApprovedEndpoint, BatchClassificationLimits, BatchItemContext, BatchItemResponse,
    BatchResponse, BatchResultSet, HttpJob, HttpPolicyId, HttpRequest, HttpRequestInput,
};
use bytes::Bytes;

mod common;
use http::{HeaderMap, Method, StatusCode};
use http_request::Url;

const BASELINE_ID: &str = "u08-dynamo-shaped-v1";
const SEED: u64 = 0x8e57_0c2a_6d19_4b33;
const SAMPLES: usize = 3;
const WARMUPS: usize = 1;
const VALUE_SIZES: [usize; 3] = [800, 1_150, 1_500];
const LOGICAL_ATTRIBUTES: u8 = 10;
const ATTRIBUTE_NAMES: [&str; 10] = [
    "tenant",
    "job",
    "kind",
    "schema",
    "payload",
    "fairness",
    "priority",
    "retry",
    "scheduled_at",
    "ttl",
];
const INDEX_ENTRIES: [usize; 2] = [2, 3];
const KEY_BYTES: usize = 100;
const NOW: Timestamp = Timestamp::from_millis(1_740_000_000_000);
const LIFECYCLE_JOBS: usize = 24;

#[test]
#[ignore = "debug-only realistic broad performance harness; run through just bg-jobs-perf-realistic"]
fn given_dynamo_shaped_fixture_when_running_broad_then_reports_three_samples() {
    let mode = performance_mode();
    println!(
        "bg_jobs_perf_realistic suite=broad baseline_id={} mode={} seed={} key_bytes_avg={} \
         value_sizes={} logical_attributes={} attribute_names={} ttl_attribute=true \
         index_entries={} query_pages=1,10,25,100 near_1mib_byte_limit=1048576 \
         candidate_inventory=lifecycle_claim_complete,failure_reconcile,fair_selection,\
         schedule_materialisation,wake_merge,http_batch,conformance_store",
        BASELINE_ID,
        mode,
        SEED,
        KEY_BYTES,
        csv_usize(&VALUE_SIZES),
        LOGICAL_ATTRIBUTES,
        ATTRIBUTE_NAMES.join(","),
        csv_usize(&INDEX_ENTRIES),
    );

    for _ in 0..WARMUPS {
        black_box(block_on(run_broad_workload()));
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_fixture_when_running_broad_then_reports_three_samples",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        let outcome = block_on(run_broad_workload());
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        let serial_calls = outcome.counts.gets + outcome.counts.ranges + outcome.counts.commits;
        let adjusted_nanos = elapsed_nanos.saturating_add(serial_calls as u128 * 1_000_000);
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=broad phase=sample mode={} sample={} ",
                "warmups={} seed={} lifecycle_jobs={} lifecycle_succeeded={} ",
                "fault_assertions={} fault_unknowns={} conformance_assertions={} ",
                "conformance_conflicts={} fair_selected={} schedule_occurrences={} ",
                "wake_revision={} http_outcomes={} http_retry_outcomes={} ",
                "gets={} ranges={} commits={} committed={} conflicts={} unknown={} errors={} ",
                "get_key_bytes={} range_request_key_bytes={} range_result_bytes={} ",
                "transaction_bytes={} transaction_checks={} transaction_mutations={} ",
                "allocations={} allocated_bytes={} elapsed_nanos={} ",
                "one_ms_serial_store_call_adjusted_nanos={}"
            ),
            mode,
            sample,
            WARMUPS,
            SEED,
            LIFECYCLE_JOBS,
            outcome.lifecycle_succeeded,
            outcome.fault_assertions,
            outcome.fault_unknowns,
            outcome.conformance_assertions,
            outcome.conformance_conflicts,
            outcome.fair_selected,
            outcome.schedule_occurrences,
            outcome.wake_revision,
            outcome.http_outcomes,
            outcome.http_retry_outcomes,
            outcome.counts.gets,
            outcome.counts.ranges,
            outcome.counts.commits,
            outcome.counts.committed,
            outcome.counts.conflicts,
            outcome.counts.unknown,
            outcome.counts.errors,
            outcome.counts.get_key_bytes,
            outcome.counts.range_request_key_bytes,
            outcome.counts.range_result_bytes,
            outcome.counts.transaction_bytes,
            outcome.counts.transaction_checks,
            outcome.counts.transaction_mutations,
            allocations.allocation_count,
            allocations.allocated_bytes,
            elapsed_nanos,
            adjusted_nanos,
        );
        samples.push(Sample {
            elapsed_nanos,
            adjusted_nanos,
            allocations: allocations.allocation_count,
            allocated_bytes: allocations.allocated_bytes,
        });
    }
    print_summary(&mode, &samples);
}

#[test]
#[ignore = "candidate-only schedule allocation evidence; run explicitly during the optimisation \
            loop"]
fn given_large_schedule_backlog_when_evaluating_then_reports_three_samples() {
    const ITERATIONS: usize = 100;
    let schedule = schedule_allocation_fixture();
    let cursor = schedule
        .cursor_after(Timestamp::from_millis(
            NOW.as_millis() - 10 * 60 * 60 * 1_000,
        ))
        .expect("fixed schedule cursor");
    for _ in 0..WARMUPS {
        black_box(repeat_schedule_evaluation(&schedule, &cursor, ITERATIONS));
    }
    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_large_schedule_backlog_when_evaluating_then_reports_three_samples",
            file!(),
            line!(),
            Some("candidate"),
        );
        let started = Instant::now();
        let occurrences = repeat_schedule_evaluation(&schedule, &cursor, ITERATIONS);
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=schedule_metadata phase=sample sample={} ",
                "iterations={} occurrences={} elapsed_nanos={} allocations={} allocated_bytes={}"
            ),
            sample,
            ITERATIONS,
            occurrences,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }
}

fn schedule_allocation_fixture() -> RecurringSchedule {
    RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([0x73; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("schedule-metadata-job").expect("fixed schedule kind"),
            schema_version: nz16(1),
            payload: value_bytes(7_000, VALUE_SIZES[1]),
            fairness: FairnessClass::LowVolume,
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })
        .expect("fixed schedule template"),
        cadence: Cadence::CronUtc(CronExpression::try_new("* * * * *").expect("fixed cron")),
        misfire: MisfirePolicy::CatchUp {
            maximum_occurrences: nz16(64),
        },
        overlap: OverlapPolicy::Allow,
        enabled: true,
    })
}

fn repeat_schedule_evaluation(
    schedule: &RecurringSchedule,
    cursor: &ScheduleCursor,
    iterations: usize,
) -> usize {
    let mut occurrences = 0usize;
    for _ in 0..iterations {
        let evaluation = schedule
            .evaluate(cursor, NOW)
            .expect("fixed schedule evaluation");
        occurrences = occurrences.saturating_add(evaluation.occurrences.len());
        black_box(evaluation);
    }
    occurrences
}

#[test]
#[ignore = "candidate-only endpoint approval allocation measurement"]
fn given_dynamo_shaped_endpoints_when_matching_then_reports_three_samples() {
    const REQUESTS: usize = 256;
    let mode = performance_mode();
    let endpoint = ApprovedEndpoint::with_subdomains("example.com").expect("fixed endpoint");
    let urls = (0..REQUESTS)
        .map(|index| {
            let host = if index % 2 == 0 {
                "api.example.com"
            } else {
                "example.com"
            };
            Url::parse(&format!("https://{host}/jobs/{index}")).expect("fixed URL")
        })
        .collect::<Vec<_>>();

    for _ in 0..WARMUPS {
        for url in &urls {
            std::hint::black_box(endpoint.matches(url));
        }
    }

    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_endpoints_when_matching_then_reports_three_samples",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        for url in &urls {
            std::hint::black_box(endpoint.matches(url));
        }
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            "bg_jobs_perf_realistic suite=endpoint phase=candidate sample={} mode={} requests={} \
             elapsed_nanos={} allocations={} allocated_bytes={}",
            sample,
            mode,
            REQUESTS,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }

    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_endpoints_when_matching_then_reports_three_samples_legacy",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        for url in &urls {
            std::hint::black_box(legacy_endpoint_matches(url));
        }
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            "bg_jobs_perf_realistic suite=endpoint phase=legacy sample={} mode={} requests={} \
             elapsed_nanos={} allocations={} allocated_bytes={}",
            sample,
            mode,
            REQUESTS,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }
}

fn legacy_endpoint_matches(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let Some(port) = url.port_or_known_default() else {
        return false;
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let host_match = host == "example.com" || host.ends_with(&format!(".{}", "example.com"));
    host_match && port == 443
}

#[test]
#[ignore = "candidate-only HTTP batch classification measurement"]
fn given_dynamo_shaped_http_batch_when_classifying_responses_then_reports_three_samples() {
    const ITEMS: usize = 64;
    const ITERATIONS: usize = 1_000;
    let policy = HttpPolicyId::try_new("batch-classification").expect("fixed batch policy");
    let jobs = (0..ITEMS)
        .map(|index| {
            let request = HttpRequest::try_new(HttpRequestInput {
                method: Method::POST,
                url: Url::parse("https://api.example.com/jobs").expect("fixed URL"),
                headers: HeaderMap::new(),
                body: value_bytes(10_000 + index, VALUE_SIZES[1]),
            })
            .expect("fixed HTTP request");
            HttpJob::new(policy.clone(), request)
        })
        .collect::<Vec<_>>();
    let contexts = jobs
        .iter()
        .enumerate()
        .map(|(index, job)| BatchItemContext {
            execution_id: ExecutionId::from(job_id_bytes(11_000 + index)),
            attempt_id: AttemptId::from(job_id_bytes(12_000 + index)),
            request: &job.request,
        })
        .collect::<Vec<_>>();
    let responses = contexts
        .iter()
        .enumerate()
        .map(|(index, item)| BatchItemResponse {
            attempt_id: item.attempt_id,
            status: match index % 4 {
                0 => StatusCode::OK,
                1 => StatusCode::TOO_MANY_REQUESTS,
                2 => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            },
            headers: HeaderMap::new(),
        })
        .collect::<Vec<_>>();
    let limits = BatchClassificationLimits {
        retry_after_max: Duration::from_secs(30),
        retry_after_fallback: Duration::from_secs(1),
    };
    for _ in 0..WARMUPS {
        for _ in 0..ITERATIONS {
            black_box(
                BatchResultSet::from_response(
                    &contexts,
                    BatchResponse::PerItem(responses.clone()),
                    limits,
                    SystemTime::UNIX_EPOCH,
                    NOW,
                )
                .expect("fixed HTTP batch classification"),
            );
        }
    }
    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_http_batch_when_classifying_responses_then_reports_three_samples",
            file!(),
            line!(),
            Some("source"),
        );
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            black_box(
                BatchResultSet::from_response(
                    &contexts,
                    BatchResponse::PerItem(responses.clone()),
                    limits,
                    SystemTime::UNIX_EPOCH,
                    NOW,
                )
                .expect("fixed HTTP batch classification"),
            );
        }
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            "bg_jobs_perf_realistic suite=http_batch_classification phase=source sample={} \
             items={} iterations={} elapsed_nanos={} allocations={} allocated_bytes={}",
            sample,
            ITEMS,
            ITERATIONS,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }
}

#[test]
#[ignore = "candidate-only batch formation measurement"]
fn given_dynamo_shaped_batch_when_forming_then_reports_three_samples() {
    const ITEMS: usize = 64;
    const ITERATIONS: usize = 128;
    let mode = performance_mode();
    let limits = BatchLimits::try_new(BatchLimitsInput {
        max_items: nz16(ITEMS as u16),
        max_payload_bytes: nz_usize(ITEMS * VALUE_SIZES[1]),
        max_formation_delay: Duration::from_secs(1),
    })
    .expect("fixed batch limits");
    let items = (0..ITEMS).map(realistic_batch_item).collect::<Vec<_>>();

    for _ in 0..WARMUPS {
        for _ in 0..ITERATIONS {
            let mut builder =
                BatchBuilder::try_new(items[0].clone(), limits, NOW).expect("first batch item");
            for item in items.iter().skip(1) {
                builder
                    .try_add(item.clone(), NOW)
                    .expect("compatible batch item");
            }
            std::hint::black_box(builder.finish());
        }
    }

    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_batch_when_forming_then_reports_three_samples",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let mut builder =
                BatchBuilder::try_new(items[0].clone(), limits, NOW).expect("first batch item");
            for item in items.iter().skip(1) {
                builder
                    .try_add(item.clone(), NOW)
                    .expect("compatible batch item");
            }
            std::hint::black_box(builder.finish());
        }
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            "bg_jobs_perf_realistic suite=batch phase=candidate sample={} mode={} items={} \
             iterations={} elapsed_nanos={} allocations={} allocated_bytes={}",
            sample,
            mode,
            ITEMS,
            ITERATIONS,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }

    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_batch_when_forming_then_reports_three_samples_legacy",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        for _ in 0..ITERATIONS {
            let mut accepted = Vec::with_capacity(ITEMS);
            accepted.push(items[0].clone());
            for item in items.iter().skip(1) {
                assert!(
                    !accepted
                        .iter()
                        .any(|current| current.compatibility != item.compatibility)
                );
                assert!(!item.ordering_key.as_ref().is_some_and(|key| {
                    accepted
                        .iter()
                        .any(|current| current.ordering_key.as_ref() == Some(key))
                }));
                accepted.push(item.clone());
            }
            std::hint::black_box(accepted);
        }
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        println!(
            "bg_jobs_perf_realistic suite=batch phase=legacy sample={} mode={} items={} \
             iterations={} elapsed_nanos={} allocations={} allocated_bytes={}",
            sample,
            mode,
            ITEMS,
            ITERATIONS,
            elapsed_nanos,
            allocations.allocation_count,
            allocations.allocated_bytes,
        );
    }
}

fn realistic_batch_item(index: usize) -> BatchItem {
    BatchItem {
        job_id: JobId::from(job_id_bytes(6_000 + index)),
        execution_id: ExecutionId::from(job_id_bytes(7_000 + index)),
        attempt_id: AttemptId::from(job_id_bytes(8_000 + index)),
        payload: value_bytes(9_000 + index, VALUE_SIZES[1]),
        compatibility: BatchCompatibility {
            handler_kind: JobKind::try_new("batch-handler").expect("fixed batch kind"),
            schema_version: nz16(1),
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode: EffectMode::Idempotent,
            retry_policy: RetryPolicy::preset(RetryPreset::Interactive),
            timeout: Duration::from_secs(1),
            priority: Priority::Default,
            fairness: FairnessClass::LowVolume,
        },
        ordering_key: None,
        ordering_position: index as u64,
        enqueued_at: NOW,
        batch_deadline: NOW
            .checked_add(Duration::from_secs(1))
            .expect("fixed deadline"),
    }
}

struct BroadOutcome {
    lifecycle_succeeded: u32,
    fault_assertions: u32,
    fault_unknowns: u32,
    conformance_assertions: u32,
    conformance_conflicts: u32,
    fair_selected: u32,
    schedule_occurrences: u32,
    wake_revision: u64,
    http_outcomes: u32,
    http_retry_outcomes: u32,
    counts: StoreSnapshot,
}

async fn run_broad_workload() -> BroadOutcome {
    let lifecycle_store = OutcomeStore::new(FakeStore::distributed());
    let lifecycle_system = build_lifecycle_system(lifecycle_store.clone());
    let lifecycle_succeeded = run_lifecycle(&lifecycle_system).await;
    let lifecycle_counts = lifecycle_store.snapshot();

    let fault_inner = OutcomeStore::new(FakeStore::distributed());
    let fault_store = FaultStore::new(fault_inner.clone());
    let fault_report = run_faults(&fault_store, &ConformanceConfig::default())
        .await
        .expect("fault conformance workload");
    let fault_counts = fault_inner.snapshot();

    let conformance_store = OutcomeStore::new(FakeStore::distributed());
    let basic = run_basic(&conformance_store, &ConformanceConfig::default())
        .await
        .expect("basic conformance workload");
    let conformance_counts = conformance_store.snapshot();

    let fair_selected = measure_fairness();
    let (schedule_occurrences, wake_revision) = measure_schedule_wake();
    let (http_outcomes, http_retry_outcomes) = measure_http_batch();
    BroadOutcome {
        lifecycle_succeeded,
        fault_assertions: fault_report.assertions,
        fault_unknowns: fault_report.unknowns,
        conformance_assertions: basic.assertions,
        conformance_conflicts: basic.conflicts,
        fair_selected,
        schedule_occurrences,
        wake_revision,
        http_outcomes,
        http_retry_outcomes,
        counts: lifecycle_counts + fault_counts + conformance_counts,
    }
}

async fn run_lifecycle(system: &JobSystem<OutcomeStore<FakeStore>>) -> u32 {
    let jobs = (0..LIFECYCLE_JOBS)
        .map(|index| NewJob {
            job_id: JobId::from(job_id_bytes(index)),
            kind: JobKind::try_new("broad-job").expect("fixed job kind"),
            schema_version: nz16(1),
            payload: value_bytes(index, VALUE_SIZES[index % VALUE_SIZES.len()]),
            fairness: FairnessClass::from(FairnessPath::new(
                FairnessKey::try_new(format!("broad-{index}").as_bytes()).expect("fixed fair key"),
                None,
            )),
            ordering_key: None,
            priority: Priority::Default,
            scheduled_at: NOW,
            expires_at: None,
            retry_override: None,
            deduplication: None,
        })
        .collect::<Vec<_>>();
    for job in jobs {
        system
            .enqueue_raw(job, NOW)
            .await
            .expect("fixed broad enqueue");
    }
    let report = system
        .drive(
            DriveRequest::try_from(DriveRequestInput {
                queues: bg_jobs::QueueSelection::all(),
                max_claims: nz32(LIFECYCLE_JOBS as u32),
                max_concurrency: nz16(1),
                max_payload_bytes_in_flight: nz_usize(64 * 1024),
                max_completion_details: LIFECYCLE_JOBS as u32,
                max_store_operations: nz32((LIFECYCLE_JOBS * 24) as u32),
                stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX / 2),
                finish_by: MonotonicDeadline::from_nanos(u64::MAX),
            })
            .expect("fixed broad drive request"),
            NOW,
            || MonotonicDeadline::ZERO,
        )
        .await
        .expect("fixed broad drive");
    assert_eq!(
        report.counts.succeeded, LIFECYCLE_JOBS as u32,
        "broad lifecycle did not consume the fixed job workload: {report:?}"
    );
    report.counts.succeeded
}

struct BroadHandler;

impl JobHandler for BroadHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async {
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("broad-complete").expect("fixed outcome"),
            ))
        })
    }
}

fn build_lifecycle_system(store: OutcomeStore<FakeStore>) -> JobSystem<OutcomeStore<FakeStore>> {
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind: JobKind::try_new("broad-job").expect("fixed job kind"),
                schema_version: nz16(1),
                queue: QueueName::try_new("broad").expect("fixed queue"),
                effect_mode: EffectMode::Idempotent,
                cost_units: nz16(1),
                fairness_policy: FairnessPolicy::from(nz16(1)),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: BroadHandler,
            },
            None,
        )
        .expect("fixed broad handler registration");
    JobSystemBuilder::new(store)
        .catalog(catalog)
        .namespace(Namespace::try_new(b"broad").expect("fixed broad namespace"))
        .owner(OwnerId::from([0x91; 16]))
        .scheduler(common::wake_scheduler())
        .build()
        .expect("fixed broad job system")
}

fn measure_fairness() -> u32 {
    let budget = FairnessBudget::try_new(FairnessBudgetInput {
        candidate_window: nz32(32),
        max_concurrency_per_scope: nz32(2),
        max_rate_per_scope: nz32(32),
        max_low_volume_service: nz32(2),
        max_payload_bytes: nz_usize(64 * 1024),
        max_cost_units: nz16(3),
    })
    .expect("fixed fair budget");
    let mut ledger = FairnessLedger::new(budget);
    let mut ids = Vec::with_capacity(32);
    for index in 0..32 {
        let id = JobId::from(job_id_bytes(1_000 + index));
        ids.push(id);
        ledger
            .add_candidate(FairCandidateInput {
                job_id: id,
                fairness: FairnessClass::from(FairnessPath::new(
                    FairnessKey::try_new(format!("fair-{}", index % 4).as_bytes())
                        .expect("fixed fair key"),
                    None,
                )),
                priority: Priority::Default,
                cost_units: nz16(1),
                scheduled_at: NOW,
                payload_bytes: VALUE_SIZES[index % VALUE_SIZES.len()],
                ordering_key: None,
                ordering_position: 0,
                block: None,
            })
            .expect("fixed fair candidate");
    }
    let mut selected = 0;
    for id in ids {
        ledger.reset_priority_window();
        if let Ok(permit) = ledger.select(id) {
            ledger
                .release(permit, FairRelease::Complete)
                .expect("fair release");
            selected += 1;
        }
    }
    assert!(selected >= 16);
    selected
}

fn measure_schedule_wake() -> (u32, u64) {
    let schedule = RecurringSchedule::new(RecurringScheduleInput {
        schedule_id: ScheduleId::from([0x71; 16]),
        job_template: JobTemplate::try_new(JobTemplateInput {
            kind: JobKind::try_new("scheduled-job").expect("fixed schedule kind"),
            schema_version: nz16(1),
            payload: value_bytes(2_000, VALUE_SIZES[1]),
            fairness: FairnessClass::LowVolume,
            ordering_key: None,
            priority: Priority::Default,
            expires_after: None,
            retry_override: None,
            deduplication: None,
        })
        .expect("fixed schedule template"),
        cadence: Cadence::CronUtc(CronExpression::try_new("*/5 * * * *").expect("fixed cron")),
        misfire: MisfirePolicy::CatchUp {
            maximum_occurrences: nz16(4),
        },
        overlap: OverlapPolicy::Allow,
        enabled: true,
    });
    let cursor = schedule
        .cursor_after(Timestamp::from_millis(NOW.as_millis() - 45 * 60 * 1_000))
        .expect("fixed cursor");
    let evaluation = schedule
        .evaluate(&cursor, NOW)
        .expect("schedule evaluation");
    let early = Timestamp::from_millis(NOW.as_millis() + 5_000);
    let repaired = Timestamp::from_millis(NOW.as_millis() + 30_000);
    let mut watermark = WakeWatermark::new();
    assert!(watermark.lower(early));
    assert!(watermark.raise_stale(Some(repaired)));
    let merged = WakeCandidates {
        watermarks: vec![WakeHint::At(repaired)],
        due_heads: vec![WakeHint::At(early)],
        schedule_heads: Vec::new(),
    }
    .merge(nz32(4));
    assert_eq!(merged, WakeHint::At(early));
    (evaluation.occurrences.len() as u32, watermark.revision())
}

fn measure_http_batch() -> (u32, u32) {
    let policy = HttpPolicyId::try_new("realistic-http").expect("fixed HTTP policy ID");
    let requests = (0..8)
        .map(|index| {
            let request = HttpRequest::try_new(HttpRequestInput {
                method: Method::POST,
                url: Url::parse("https://api.example.com/jobs").expect("fixed URL"),
                headers: HeaderMap::new(),
                body: value_bytes(3_000 + index, VALUE_SIZES[index % VALUE_SIZES.len()]),
            })
            .expect("fixed HTTP request");
            HttpJob::new(policy.clone(), request)
        })
        .collect::<Vec<_>>();
    let contexts = requests
        .iter()
        .enumerate()
        .map(|(index, job)| BatchItemContext {
            execution_id: ExecutionId::from(job_id_bytes(4_000 + index)),
            attempt_id: AttemptId::from(job_id_bytes(5_000 + index)),
            request: &job.request,
        })
        .collect::<Vec<_>>();
    let responses = contexts
        .iter()
        .enumerate()
        .map(|(index, item)| BatchItemResponse {
            attempt_id: item.attempt_id,
            status: match index % 4 {
                0 => StatusCode::OK,
                1 => StatusCode::TOO_MANY_REQUESTS,
                2 => StatusCode::INTERNAL_SERVER_ERROR,
                _ => StatusCode::BAD_REQUEST,
            },
            headers: HeaderMap::new(),
        })
        .collect();
    let result = BatchResultSet::from_response(
        &contexts,
        BatchResponse::PerItem(responses),
        BatchClassificationLimits {
            retry_after_max: Duration::from_secs(30),
            retry_after_fallback: Duration::from_secs(1),
        },
        SystemTime::UNIX_EPOCH,
        NOW,
    )
    .expect("fixed HTTP batch classification");
    let retry = result
        .outcomes()
        .iter()
        .filter(|outcome| matches!(outcome.outcome, JobOutcome::Retry { .. }))
        .count() as u32;
    (result.outcomes().len() as u32, retry)
}

#[derive(Clone)]
struct OutcomeStore<S: JobStore> {
    inner: S,
    counters: Arc<StoreCounters>,
}

impl<S: JobStore> OutcomeStore<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            counters: Arc::new(StoreCounters::default()),
        }
    }

    fn snapshot(&self) -> StoreSnapshot {
        self.counters.snapshot()
    }
}

impl<S: JobStore> JobStore for OutcomeStore<S> {
    type Error = S::Error;

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
        let future = self.inner.get(key);
        let counters = Arc::clone(&self.counters);
        async move {
            let result = future.await;
            if result.is_err() {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
            result
        }
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
        let future = self.inner.get_many(keys);
        let counters = Arc::clone(&self.counters);
        async move {
            let result = future.await;
            if result.is_err() {
                counters.errors.fetch_add(1, Ordering::Relaxed);
            }
            result
        }
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        self.counters.ranges.fetch_add(1, Ordering::Relaxed);
        let request_bytes = request
            .start()
            .into_iter()
            .chain(request.end())
            .chain(request.continuation())
            .map(|key| key.as_bytes().len() as u64)
            .sum::<u64>();
        self.counters
            .range_request_key_bytes
            .fetch_add(request_bytes, Ordering::Relaxed);
        let future = self.inner.read_range(request);
        let counters = Arc::clone(&self.counters);
        async move {
            let result = future.await;
            match result {
                Ok(page) => {
                    counters
                        .range_result_bytes
                        .fetch_add(page.total_bytes() as u64, Ordering::Relaxed);
                    Ok(page)
                }
                Err(error) => {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    Err(error)
                }
            }
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
        self.counters
            .transaction_checks
            .fetch_add(transaction.checks().len() as u64, Ordering::Relaxed);
        self.counters
            .transaction_mutations
            .fetch_add(transaction.mutations().len() as u64, Ordering::Relaxed);
        let future = self.inner.commit(transaction);
        let counters = Arc::clone(&self.counters);
        async move {
            let result = future.await;
            match result {
                Ok(CommitOutcome::Committed) => {
                    counters.committed.fetch_add(1, Ordering::Relaxed);
                    Ok(CommitOutcome::Committed)
                }
                Ok(CommitOutcome::Conflict) => {
                    counters.conflicts.fetch_add(1, Ordering::Relaxed);
                    Ok(CommitOutcome::Conflict)
                }
                Ok(CommitOutcome::Unknown) => {
                    counters.unknown.fetch_add(1, Ordering::Relaxed);
                    Ok(CommitOutcome::Unknown)
                }
                Err(error) => {
                    counters.errors.fetch_add(1, Ordering::Relaxed);
                    Err(error)
                }
            }
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
    errors: AtomicU64,
    get_key_bytes: AtomicU64,
    range_request_key_bytes: AtomicU64,
    range_result_bytes: AtomicU64,
    transaction_bytes: AtomicU64,
    transaction_checks: AtomicU64,
    transaction_mutations: AtomicU64,
}

#[derive(Clone, Copy, Default)]
struct StoreSnapshot {
    gets: u64,
    ranges: u64,
    commits: u64,
    committed: u64,
    conflicts: u64,
    unknown: u64,
    errors: u64,
    get_key_bytes: u64,
    range_request_key_bytes: u64,
    range_result_bytes: u64,
    transaction_bytes: u64,
    transaction_checks: u64,
    transaction_mutations: u64,
}

impl std::ops::Add for StoreSnapshot {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            gets: self.gets + other.gets,
            ranges: self.ranges + other.ranges,
            commits: self.commits + other.commits,
            committed: self.committed + other.committed,
            conflicts: self.conflicts + other.conflicts,
            unknown: self.unknown + other.unknown,
            errors: self.errors + other.errors,
            get_key_bytes: self.get_key_bytes + other.get_key_bytes,
            range_request_key_bytes: self.range_request_key_bytes + other.range_request_key_bytes,
            range_result_bytes: self.range_result_bytes + other.range_result_bytes,
            transaction_bytes: self.transaction_bytes + other.transaction_bytes,
            transaction_checks: self.transaction_checks + other.transaction_checks,
            transaction_mutations: self.transaction_mutations + other.transaction_mutations,
        }
    }
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
            errors: self.errors.load(Ordering::Relaxed),
            get_key_bytes: self.get_key_bytes.load(Ordering::Relaxed),
            range_request_key_bytes: self.range_request_key_bytes.load(Ordering::Relaxed),
            range_result_bytes: self.range_result_bytes.load(Ordering::Relaxed),
            transaction_bytes: self.transaction_bytes.load(Ordering::Relaxed),
            transaction_checks: self.transaction_checks.load(Ordering::Relaxed),
            transaction_mutations: self.transaction_mutations.load(Ordering::Relaxed),
        }
    }
}

struct Sample {
    elapsed_nanos: u128,
    adjusted_nanos: u128,
    allocations: u64,
    allocated_bytes: u64,
}

fn print_summary(mode: &str, samples: &[Sample]) {
    let elapsed = samples
        .iter()
        .map(|sample| sample.elapsed_nanos)
        .collect::<Vec<_>>();
    let adjusted = samples
        .iter()
        .map(|sample| sample.adjusted_nanos)
        .collect::<Vec<_>>();
    let allocations = samples
        .iter()
        .map(|sample| sample.allocations)
        .collect::<Vec<_>>();
    let allocated_bytes = samples
        .iter()
        .map(|sample| sample.allocated_bytes)
        .collect::<Vec<_>>();
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=broad phase=summary mode={} baseline_id={} ",
            "samples={} elapsed_nanos={} median_elapsed_nanos={} ",
            "median_one_ms_serial_store_call_adjusted_nanos={} allocations={} ",
            "allocated_bytes={}"
        ),
        mode,
        BASELINE_ID,
        samples.len(),
        csv_u128(&elapsed),
        median(&elapsed),
        median(&adjusted),
        csv_u64(&allocations),
        csv_u64(&allocated_bytes),
    );
}

fn value_bytes(index: usize, length: usize) -> Bytes {
    let mut bytes = vec![0u8; length];
    bytes[0] = LOGICAL_ATTRIBUTES;
    bytes[1] = 1;
    bytes[2..10].copy_from_slice(&(NOW.as_millis() as u64 + index as u64).to_be_bytes());
    let mut state = SEED ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    for byte in &mut bytes[10..] {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *byte = (state >> 32) as u8;
    }
    Bytes::from(bytes)
}

fn job_id_bytes(index: usize) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&SEED.wrapping_add(index as u64).to_be_bytes());
    bytes[8..].copy_from_slice(&(index as u64).to_be_bytes());
    bytes
}

fn performance_mode() -> String {
    std::env::var("BG_JOBS_PERF_MODE").unwrap_or_else(|_| "manual".to_owned())
}

fn median(values: &[u128]) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn csv_usize(values: &[usize]) -> String {
    values
        .iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_u64(values: &[u64]) -> String {
    values
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_u128(values: &[u128]) -> String {
    values
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("performance conformance runtime should build")
        .block_on(future)
}

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("fixed non-zero u16")
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("fixed non-zero u32")
}

fn nz_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("fixed non-zero usize")
}
