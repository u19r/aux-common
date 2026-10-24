//! Debug-only, ignored performance evidence for Dynamo-shaped job data.
//!
//! The fixture is deliberately immutable: this test prints comparable samples
//! and never writes a baseline file.  Consumers should run `just
//! bg-jobs-perf-realistic baseline` and retain that output as the baseline
//! receipt before evaluating candidates.

use std::{
    future::Future,
    hint::black_box,
    num::{NonZeroU16, NonZeroU32, NonZeroUsize},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use alloc_counter::AllocationGuard;
use bg_jobs::{
    DriveStopReason, EffectMode, ExecutionContext, FairnessClass, FairnessKey, FairnessPath,
    FairnessPolicy, HandlerFuture, JobCatalog, JobHandler, JobId, JobKind, JobOutcome, JobStore,
    Namespace, OutcomeCode, OwnerId, Priority, QueueName, QueueSelection, RetryPreset,
    RetrySelection, Timestamp,
    runtime::{JobSystem, JobSystemBuilder, MonotonicDeadline},
    store::{
        Check, CommitOperationId, CommitOutcome, Mutation, RangeDirection, RangePage, RangeRequest,
        RangeRequestInput, StoreCapabilities, StoreCapabilitiesInput, StoreKey, StoreLevel,
        StoreTransaction, StoreTransactionInput, TransactionLimits,
    },
    test_support::{
        FakeStore, FakeStoreError, TestProfile,
        codec::{KeyCodec, KeyTag},
        raw::{DriveRequest, DriveRequestInput, HandlerDefinition, NewJob},
    },
};
use bytes::Bytes;

mod common;

const BASELINE_ID: &str = "u08-dynamo-shaped-v1";
const SEED: u64 = 0x8e57_0c2a_6d19_4b33;
const SAMPLES: usize = 3;
const WARMUPS: usize = 1;
const KEY_BYTES: usize = 100;
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
const BASE_ITEMS: usize = 900;
const INDEXES_PER_ITEM: [usize; 2] = [2, 3];
const QUERY_PAGES: [u32; 4] = [1, 10, 25, 100];
const NEAR_MIB_BYTES: usize = 1_048_576;
const LIFECYCLE_JOBS: usize = 48;
const NOW: Timestamp = Timestamp::from_millis(1_740_000_000_000);
const CONCURRENCY_YIELD_ROUNDS: u8 = 32;

#[test]
#[ignore = "debug-only realistic performance harness; run through just bg-jobs-perf-realistic"]
fn given_dynamo_shaped_fixture_when_running_focused_then_reports_three_samples() {
    let mode = performance_mode();
    let fixture = DynamoFixture::build();
    fixture.assert_shape();
    println!(
        "bg_jobs_perf_realistic suite=focused baseline_id={} mode={} seed={} key_bytes_avg={} \
         value_sizes={} logical_attributes={} attribute_names={} ttl_attribute=true \
         index_entries={} query_pages={} near_1mib_byte_limit={} base_items={} \
         candidate_inventory=payload_clone,key_encoding,index_materialisation,\
         range_page_materialisation,serial_store_calls",
        BASELINE_ID,
        mode,
        SEED,
        fixture.average_key_bytes(),
        csv_usize(&VALUE_SIZES),
        LOGICAL_ATTRIBUTES,
        ATTRIBUTE_NAMES.join(","),
        csv_usize(&INDEXES_PER_ITEM),
        csv_u32(&QUERY_PAGES),
        NEAR_MIB_BYTES,
        fixture.items.len(),
    );

    for _ in 0..WARMUPS {
        let store = MeasuredStore::new();
        fixture.seed(&store).expect("warm-up fixture seed");
        let system = build_system(store.clone());
        black_box(block_on(run_focused_workload(&system, &store, &fixture)));
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let store = MeasuredStore::new();
        fixture.seed(&store).expect("sample fixture seed");
        let system = build_system(store.clone());
        let guard = AllocationGuard::start(
            module_path!(),
            "given_dynamo_shaped_fixture_when_running_focused_then_reports_three_samples",
            file!(),
            line!(),
            Some(mode.as_str()),
        );
        let started = Instant::now();
        let outcome = block_on(run_focused_workload(&system, &store, &fixture));
        let elapsed_nanos = started.elapsed().as_nanos();
        let allocations = guard.finish();
        let counts = store.snapshot();
        let serial_calls = counts.gets + counts.ranges + counts.commits;
        let adjusted_nanos = elapsed_nanos.saturating_add(serial_calls as u128 * 1_000_000);
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=focused phase=sample mode={} sample={} ",
                "warmups={} seed={} lifecycle_jobs={} query_pages={} ",
                "query_entries_by_page={} query_bytes_by_page={} query_total_entries={} ",
                "near_1mib_entries={} near_1mib_bytes={} ",
                "gets={} ranges={} commits={} committed={} conflicts={} unknown={} ",
                "get_key_bytes={} range_request_key_bytes={} range_result_bytes={} ",
                "transaction_bytes={} allocations={} allocated_bytes={} elapsed_nanos={} ",
                "one_ms_serial_store_call_adjusted_nanos={}"
            ),
            mode,
            sample,
            WARMUPS,
            SEED,
            outcome.lifecycle_jobs,
            csv_u32(&QUERY_PAGES),
            csv_u32(&outcome.query_entries),
            csv_u64(&outcome.query_bytes),
            outcome.query_entries.iter().sum::<u32>(),
            outcome.near_entries,
            outcome.near_bytes,
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
            counts,
        });
    }
    print_summary(&mode, &samples);
}

#[test]
#[ignore = "candidate-only concurrency evidence; run explicitly during the optimisation loop"]
fn given_drive_concurrency_when_store_and_handler_futures_yield_then_reports_bounded_overlap() {
    let max_store_operations = 128;
    let mut serial_samples = Vec::with_capacity(SAMPLES);
    let mut concurrent_samples = Vec::with_capacity(SAMPLES);
    for _ in 0..WARMUPS {
        let _ = run_overlap_sample(1, 3_200, max_store_operations);
        let _ = run_overlap_sample(4, 3_200, max_store_operations);
    }
    for sample in 0..SAMPLES {
        let serial = run_overlap_sample(1, 3_200, max_store_operations);
        let concurrent = run_overlap_sample(4, 3_200, max_store_operations);
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=drive_concurrency phase=sample sample={} ",
                "serial_elapsed_nanos={} concurrent_elapsed_nanos={} ",
                "serial_allocations={} serial_allocated_bytes={} ",
                "concurrent_allocations={} concurrent_allocated_bytes={} ",
                "serial_store_operations={} concurrent_store_operations={} ",
                "serial_store_peak={} concurrent_store_peak={} ",
                "serial_handler_peak={} concurrent_handler_peak={} ",
                "serial_succeeded={} concurrent_succeeded={}"
            ),
            sample,
            serial.elapsed_nanos,
            concurrent.elapsed_nanos,
            serial.allocations,
            serial.allocated_bytes,
            concurrent.allocations,
            concurrent.allocated_bytes,
            serial.operations,
            concurrent.operations,
            serial.store_peak,
            concurrent.store_peak,
            serial.handler_peak,
            concurrent.handler_peak,
            serial.succeeded,
            concurrent.succeeded,
        );
        assert_eq!(serial.succeeded, 4);
        assert_eq!(concurrent.succeeded, 4);
        assert!(serial.store_peak >= 2);
        assert_eq!(serial.handler_peak, 1);
        assert!(concurrent.store_peak >= 2);
        assert!(concurrent.handler_peak >= 2);
        assert!(concurrent.operations <= u64::from(max_store_operations));
        serial_samples.push(serial);
        concurrent_samples.push(concurrent);
    }
    let serial_elapsed = serial_samples
        .iter()
        .map(|sample| sample.elapsed_nanos)
        .collect::<Vec<_>>();
    let concurrent_elapsed = concurrent_samples
        .iter()
        .map(|sample| sample.elapsed_nanos)
        .collect::<Vec<_>>();
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=drive_concurrency phase=summary ",
            "serial_elapsed_nanos={} serial_median_elapsed_nanos={} ",
            "concurrent_elapsed_nanos={} concurrent_median_elapsed_nanos={} ",
            "serial_store_peak={} concurrent_store_peak={} ",
            "serial_handler_peak={} concurrent_handler_peak={}"
        ),
        csv_u128(&serial_elapsed),
        median(&serial_elapsed),
        csv_u128(&concurrent_elapsed),
        median(&concurrent_elapsed),
        serial_samples
            .iter()
            .map(|sample| sample.store_peak)
            .max()
            .unwrap_or_default(),
        concurrent_samples
            .iter()
            .map(|sample| sample.store_peak)
            .max()
            .unwrap_or_default(),
        serial_samples
            .iter()
            .map(|sample| sample.handler_peak)
            .max()
            .unwrap_or_default(),
        concurrent_samples
            .iter()
            .map(|sample| sample.handler_peak)
            .max()
            .unwrap_or_default(),
    );

    let bounded = run_overlap_sample(4, 1_600, max_store_operations);
    assert_eq!(bounded.succeeded, 4);
    assert!(bounded.store_peak <= 4);
    assert!(bounded.handler_peak <= 2);
    assert!(bounded.operations <= u64::from(max_store_operations));
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=drive_concurrency phase=payload_bound ",
            "payload_bytes_in_flight=1600 store_operations={} store_peak={} handler_peak={}"
        ),
        bounded.operations, bounded.store_peak, bounded.handler_peak,
    );

    let operation_limited = run_overlap_sample(4, 3_200, 8);
    assert_eq!(operation_limited.succeeded, 0);
    assert_eq!(operation_limited.stop_reason, DriveStopReason::Capacity);
    assert!(operation_limited.operations <= 8);
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=drive_concurrency phase=store_bound ",
            "max_store_operations=8 operations={} succeeded={} stop_reason={:?}"
        ),
        operation_limited.operations, operation_limited.succeeded, operation_limited.stop_reason,
    );

    let deadline_limited = run_overlap_deadline_sample();
    assert_eq!(deadline_limited.succeeded, 0);
    assert_eq!(deadline_limited.stop_reason, DriveStopReason::Deadline);
    assert_eq!(deadline_limited.handler_peak, 0);
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=drive_concurrency phase=deadline_bound ",
            "operations={} succeeded={} stop_reason={:?}"
        ),
        deadline_limited.operations, deadline_limited.succeeded, deadline_limited.stop_reason,
    );
}

#[test]
#[ignore = "candidate-only transaction metadata evidence; run explicitly during the optimisation \
            loop"]
fn given_repeated_transaction_validation_when_metadata_is_cached_then_reports_three_samples() {
    const ITERATIONS: usize = 100_000;
    let transaction = metadata_transaction();
    let capabilities = StoreCapabilities::try_from(StoreCapabilitiesInput {
        level: StoreLevel::Local,
        max_key_bytes: nz_usize(256),
        max_value_bytes: nz_usize(2_048),
        max_get_many_keys: nz32(256),
        max_get_many_key_bytes: nz_usize(65_536),
        max_transaction_bytes: nz_usize(1_000_000),
        max_transaction_keys: nz32(256),
        max_range_items: nz32(1),
        max_range_bytes: nz_usize(1_024),
        max_transaction_duration: Duration::from_secs(1),
    })
    .expect("fixed metadata capabilities");
    for _ in 0..WARMUPS {
        black_box(repeat_cached_validation(
            &transaction,
            capabilities,
            ITERATIONS,
        ));
        black_box(repeat_legacy_validation(
            &transaction,
            capabilities,
            ITERATIONS,
        ));
    }
    let mut cached_samples = Vec::with_capacity(SAMPLES);
    let mut legacy_samples = Vec::with_capacity(SAMPLES);
    for sample in 0..SAMPLES {
        let started = Instant::now();
        let cached = repeat_cached_validation(&transaction, capabilities, ITERATIONS);
        let cached_elapsed_nanos = started.elapsed().as_nanos();
        let started = Instant::now();
        let legacy = repeat_legacy_validation(&transaction, capabilities, ITERATIONS);
        let legacy_elapsed_nanos = started.elapsed().as_nanos();
        assert_eq!(cached, legacy);
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=transaction_metadata phase=sample sample={} ",
                "iterations={} cached_elapsed_nanos={} legacy_elapsed_nanos={} result={}"
            ),
            sample, ITERATIONS, cached_elapsed_nanos, legacy_elapsed_nanos, cached,
        );
        cached_samples.push(cached_elapsed_nanos);
        legacy_samples.push(legacy_elapsed_nanos);
    }
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=transaction_metadata phase=summary ",
            "cached_elapsed_nanos={} cached_median_elapsed_nanos={} ",
            "legacy_elapsed_nanos={} legacy_median_elapsed_nanos={}"
        ),
        csv_u128(&cached_samples),
        median(&cached_samples),
        csv_u128(&legacy_samples),
        median(&legacy_samples),
    );
}

fn metadata_transaction() -> StoreTransaction {
    let checks = (0..64)
        .map(|index| {
            Check::Value(
                StoreKey::try_from(format!("metadata-check-{index}").into_bytes())
                    .expect("fixed metadata key"),
                Bytes::from(vec![index as u8; 800]),
            )
        })
        .collect();
    let mutations = (0..64)
        .map(|index| {
            Mutation::Put(
                StoreKey::try_from(format!("metadata-mutation-{index}").into_bytes())
                    .expect("fixed metadata key"),
                Bytes::from(vec![index as u8; 800]),
            )
        })
        .collect();
    StoreTransaction::try_from(StoreTransactionInput {
        operation_id: CommitOperationId::from([0x31; 16]),
        checks,
        mutations,
        limits: TransactionLimits {
            max_checks: nz32(128),
            max_mutations: nz32(128),
            max_bytes: nz_usize(1_000_000),
        },
    })
    .expect("fixed metadata transaction")
}

#[test]
#[ignore = "candidate-only borrowed lease-key decode evidence; run explicitly during the \
            optimisation loop"]
fn given_repeated_lease_key_decodes_when_borrowed_then_reports_three_samples() {
    const ITERATIONS: usize = 100_000;
    let namespace = Namespace::try_new(b"lease-decode").expect("fixed lease namespace");
    let job_id = JobId::from([0x21; 16]);
    let key =
        KeyCodec::encode(&namespace, KeyTag::Lease, &[job_id.as_bytes()]).expect("fixed lease key");
    for _ in 0..WARMUPS {
        black_box(repeat_borrowed_decodes(&namespace, &key, ITERATIONS));
        black_box(repeat_owned_decodes(&namespace, &key, ITERATIONS));
    }
    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_repeated_lease_key_decodes_when_borrowed_then_reports_three_samples",
            file!(),
            line!(),
            Some("candidate"),
        );
        let started = Instant::now();
        let borrowed = repeat_borrowed_decodes(&namespace, &key, ITERATIONS);
        let borrowed_elapsed_nanos = started.elapsed().as_nanos();
        let borrowed_allocations = guard.finish();
        let guard = AllocationGuard::start(
            module_path!(),
            "given_repeated_lease_key_decodes_when_borrowed_then_reports_three_samples",
            file!(),
            line!(),
            Some("legacy"),
        );
        let started = Instant::now();
        let owned = repeat_owned_decodes(&namespace, &key, ITERATIONS);
        let owned_elapsed_nanos = started.elapsed().as_nanos();
        let owned_allocations = guard.finish();
        assert_eq!(borrowed, owned);
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=lease_decode phase=sample sample={} ",
                "iterations={} borrowed_elapsed_nanos={} owned_elapsed_nanos={} ",
                "borrowed_allocations={} borrowed_allocated_bytes={} ",
                "owned_allocations={} owned_allocated_bytes={}"
            ),
            sample,
            ITERATIONS,
            borrowed_elapsed_nanos,
            owned_elapsed_nanos,
            borrowed_allocations.allocation_count,
            borrowed_allocations.allocated_bytes,
            owned_allocations.allocation_count,
            owned_allocations.allocated_bytes,
        );
    }
}

fn repeat_borrowed_decodes(namespace: &Namespace, key: &StoreKey, iterations: usize) -> usize {
    let mut components = 0usize;
    for _ in 0..iterations {
        let decoded = KeyCodec::decode_borrowed(namespace, key).expect("lease key decodes");
        components = components.saturating_add(decoded.components.len());
        black_box(decoded);
    }
    components
}

fn repeat_owned_decodes(namespace: &Namespace, key: &StoreKey, iterations: usize) -> usize {
    let mut components = 0usize;
    for _ in 0..iterations {
        let decoded = KeyCodec::decode(namespace, key).expect("lease key decodes");
        components = components.saturating_add(decoded.components.len());
        black_box(decoded);
    }
    components
}

#[test]
#[ignore = "candidate-only single-component lease-key decode evidence; run explicitly during the \
            optimisation loop"]
fn given_repeated_lease_key_decodes_when_single_component_then_reports_three_samples() {
    const ITERATIONS: usize = 100_000;
    let namespace = Namespace::try_new(b"lease-single-decode").expect("fixed lease namespace");
    let job_id = JobId::from([0x21; 16]);
    let key =
        KeyCodec::encode(&namespace, KeyTag::Lease, &[job_id.as_bytes()]).expect("fixed lease key");
    for _ in 0..WARMUPS {
        black_box(repeat_single_component_decodes(
            &namespace, &key, ITERATIONS,
        ));
        black_box(repeat_borrowed_decodes(&namespace, &key, ITERATIONS));
    }
    for sample in 0..SAMPLES {
        let guard = AllocationGuard::start(
            module_path!(),
            "given_repeated_lease_key_decodes_when_single_component_then_reports_three_samples",
            file!(),
            line!(),
            Some("candidate"),
        );
        let started = Instant::now();
        let single_component = repeat_single_component_decodes(&namespace, &key, ITERATIONS);
        let single_component_elapsed_nanos = started.elapsed().as_nanos();
        let single_component_allocations = guard.finish();
        let guard = AllocationGuard::start(
            module_path!(),
            "given_repeated_lease_key_decodes_when_single_component_then_reports_three_samples",
            file!(),
            line!(),
            Some("legacy"),
        );
        let started = Instant::now();
        let borrowed = repeat_borrowed_decodes(&namespace, &key, ITERATIONS);
        let borrowed_elapsed_nanos = started.elapsed().as_nanos();
        let borrowed_allocations = guard.finish();
        assert_eq!(single_component, borrowed);
        println!(
            concat!(
                "bg_jobs_perf_realistic suite=lease_single_decode phase=sample sample={} ",
                "iterations={} single_component_elapsed_nanos={} borrowed_elapsed_nanos={} ",
                "single_component_allocations={} single_component_allocated_bytes={} ",
                "borrowed_allocations={} borrowed_allocated_bytes={}"
            ),
            sample,
            ITERATIONS,
            single_component_elapsed_nanos,
            borrowed_elapsed_nanos,
            single_component_allocations.allocation_count,
            single_component_allocations.allocated_bytes,
            borrowed_allocations.allocation_count,
            borrowed_allocations.allocated_bytes,
        );
    }
}

fn repeat_single_component_decodes(
    namespace: &Namespace,
    key: &StoreKey,
    iterations: usize,
) -> usize {
    let mut valid_components = 0usize;
    for _ in 0..iterations {
        let (tag, component) =
            KeyCodec::decode_single_component(namespace, key).expect("lease key decodes");
        valid_components = valid_components.saturating_add(usize::from(
            tag == KeyTag::Lease && component.len() == JobId::BYTE_LENGTH,
        ));
        black_box((tag, component));
    }
    valid_components
}

fn repeat_cached_validation(
    transaction: &StoreTransaction,
    capabilities: StoreCapabilities,
    iterations: usize,
) -> bool {
    let mut valid = true;
    for _ in 0..iterations {
        valid &= capabilities.validate_transaction(transaction).is_ok();
        black_box(transaction.encoded_bytes());
    }
    valid
}

fn repeat_legacy_validation(
    transaction: &StoreTransaction,
    capabilities: StoreCapabilities,
    iterations: usize,
) -> bool {
    let mut valid = true;
    for _ in 0..iterations {
        let encoded_bytes = transaction
            .checks()
            .iter()
            .map(Check::encoded_bytes)
            .chain(transaction.mutations().iter().map(Mutation::encoded_bytes))
            .sum::<usize>();
        let max_key_bytes = transaction
            .checks()
            .iter()
            .map(|check| check.key().as_bytes().len())
            .chain(
                transaction
                    .mutations()
                    .iter()
                    .map(|mutation| mutation.key().as_bytes().len()),
            )
            .max()
            .unwrap_or_default();
        let max_value_bytes = transaction
            .checks()
            .iter()
            .filter_map(|check| match check {
                Check::Absent(_) => None,
                Check::Value(_, value) => Some(value.len()),
            })
            .chain(
                transaction
                    .mutations()
                    .iter()
                    .filter_map(|mutation| match mutation {
                        Mutation::Delete(_) => None,
                        Mutation::Put(_, value) => Some(value.len()),
                    }),
            )
            .max()
            .unwrap_or_default();
        valid &= transaction.checks().len() + transaction.mutations().len()
            <= capabilities.max_transaction_keys().get() as usize;
        valid &= encoded_bytes <= capabilities.max_transaction_bytes().get();
        valid &= max_key_bytes <= capabilities.max_key_bytes().get();
        valid &= max_value_bytes <= capabilities.max_value_bytes().get();
        black_box(encoded_bytes);
    }
    valid
}

struct OverlapSample {
    elapsed_nanos: u128,
    allocations: u64,
    allocated_bytes: u64,
    operations: u64,
    store_peak: u64,
    handler_peak: u64,
    succeeded: u32,
    stop_reason: DriveStopReason,
}

fn run_overlap_sample(
    max_concurrency: u16,
    max_payload_bytes_in_flight: usize,
    max_store_operations: u32,
) -> OverlapSample {
    let store = OverlapStore::new();
    let system = build_overlap_system(store.clone());
    enqueue_overlap_jobs(&system);
    store.reset();
    let request = overlap_request(
        max_concurrency,
        max_payload_bytes_in_flight,
        max_store_operations,
    );
    assert_eq!(request.max_store_operations().get(), max_store_operations);
    let guard = AllocationGuard::start(
        module_path!(),
        "given_drive_concurrency_when_store_and_handler_futures_yield_then_reports_bounded_overlap",
        file!(),
        line!(),
        Some("candidate"),
    );
    let started = Instant::now();
    let report =
        block_on(system.drive(request, NOW, || MonotonicDeadline::ZERO)).expect("overlap drive");
    let elapsed_nanos = started.elapsed().as_nanos();
    let allocations = guard.finish();
    let snapshot = store.snapshot();
    OverlapSample {
        elapsed_nanos,
        allocations: allocations.allocation_count,
        allocated_bytes: allocations.allocated_bytes,
        operations: snapshot.operations,
        store_peak: snapshot.store_peak,
        handler_peak: snapshot.handler_peak,
        succeeded: report.counts.succeeded,
        stop_reason: report.stop_reason,
    }
}

fn run_overlap_deadline_sample() -> OverlapSample {
    let store = OverlapStore::new();
    let system = build_overlap_system(store.clone());
    enqueue_overlap_jobs(&system);
    store.reset();
    let request = overlap_request_with_stop(4, 3_200, 64, MonotonicDeadline::ZERO);
    let started = Instant::now();
    let report =
        block_on(system.drive(request, NOW, || MonotonicDeadline::ZERO)).expect("deadline drive");
    let elapsed_nanos = started.elapsed().as_nanos();
    let snapshot = store.snapshot();
    OverlapSample {
        elapsed_nanos,
        allocations: 0,
        allocated_bytes: 0,
        operations: snapshot.operations,
        store_peak: snapshot.store_peak,
        handler_peak: snapshot.handler_peak,
        succeeded: report.counts.succeeded,
        stop_reason: report.stop_reason,
    }
}

fn overlap_request(
    max_concurrency: u16,
    max_payload_bytes_in_flight: usize,
    max_store_operations: u32,
) -> DriveRequest {
    overlap_request_with_stop(
        max_concurrency,
        max_payload_bytes_in_flight,
        max_store_operations,
        MonotonicDeadline::from_nanos(u64::MAX / 2),
    )
}

fn overlap_request_with_stop(
    max_concurrency: u16,
    max_payload_bytes_in_flight: usize,
    max_store_operations: u32,
    stop_claiming_at: MonotonicDeadline,
) -> DriveRequest {
    DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nz32(4),
        max_concurrency: nz16(max_concurrency),
        max_payload_bytes_in_flight: nz_usize(max_payload_bytes_in_flight),
        max_completion_details: 4,
        max_store_operations: nz32(max_store_operations),
        stop_claiming_at,
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("fixed overlap request")
}

fn enqueue_overlap_jobs(system: &JobSystem<OverlapStore>) {
    for index in 0..4 {
        block_on(system.enqueue_raw(
            NewJob {
                job_id: JobId::from(job_id_bytes(200 + index)),
                kind: overlap_kind(index),
                schema_version: nz16(1),
                payload: value_bytes(index, 800),
                fairness: scoped_fairness(index),
                ordering_key: None,
                priority: Priority::Default,
                scheduled_at: NOW,
                expires_at: None,
                retry_override: None,
                deduplication: None,
            },
            NOW,
        ))
        .expect("fixed overlap enqueue");
    }
}

#[derive(Clone)]
struct OverlapStore {
    inner: FakeStore,
    state: Arc<OverlapState>,
}

impl OverlapStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::new(),
            state: Arc::new(OverlapState::default()),
        }
    }

    fn reset(&self) {
        self.state.reset();
    }

    fn snapshot(&self) -> OverlapSnapshot {
        self.state.snapshot()
    }
}

impl JobStore for OverlapStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
        let future = self.inner.get(key);
        let state = Arc::clone(&self.state);
        async move {
            state.enter_store();
            YieldNTimes::new(CONCURRENCY_YIELD_ROUNDS).await;
            let result = future.await;
            state.leave_store();
            state.operation();
            result
        }
    }

    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a {
        let future = self.inner.get_many(keys);
        let state = Arc::clone(&self.state);
        async move {
            state.enter_store();
            YieldNTimes::new(CONCURRENCY_YIELD_ROUNDS).await;
            let result = future.await;
            state.leave_store();
            state.operation();
            result
        }
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        let future = self.inner.read_range(request);
        let state = Arc::clone(&self.state);
        async move {
            state.enter_store();
            YieldNTimes::new(CONCURRENCY_YIELD_ROUNDS).await;
            let result = future.await;
            state.leave_store();
            state.operation();
            result
        }
    }

    fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> impl Future<Output = Result<CommitOutcome, Self::Error>> + Send + 'a {
        let future = self.inner.commit(transaction);
        let state = Arc::clone(&self.state);
        async move {
            state.enter_store();
            YieldNTimes::new(CONCURRENCY_YIELD_ROUNDS).await;
            let result = future.await;
            state.leave_store();
            state.operation();
            result
        }
    }
}

struct OverlapHandler {
    state: Arc<OverlapState>,
}

impl JobHandler for OverlapHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            state.enter_handler();
            YieldNTimes::new(CONCURRENCY_YIELD_ROUNDS).await;
            state.leave_handler();
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("overlap-complete").expect("fixed overlap outcome"),
            ))
        })
    }
}

fn build_overlap_system(store: OverlapStore) -> JobSystem<OverlapStore> {
    let mut catalog = JobCatalog::new();
    for index in 0..4 {
        catalog
            .register_raw(
                HandlerDefinition {
                    kind: overlap_kind(index),
                    schema_version: nz16(1),
                    queue: overlap_queue(index),
                    effect_mode: EffectMode::Idempotent,
                    cost_units: nz16(1),
                    fairness_policy: FairnessPolicy::from(nz16(1)),
                    default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                    default_timeout: Duration::from_secs(1),
                    handler: OverlapHandler {
                        state: Arc::clone(&store.state),
                    },
                },
                None,
            )
            .expect("fixed overlap handler registration");
    }
    JobSystemBuilder::new(store)
        .catalog(catalog)
        .namespace(Namespace::try_new(b"overlap").expect("fixed overlap namespace"))
        .owner(OwnerId::from([0x82; 16]))
        .scheduler(Arc::new(TestProfile::new()))
        .build()
        .expect("fixed overlap job system")
}

fn overlap_kind(index: usize) -> JobKind {
    JobKind::try_new(format!("overlap-job-{index}")).expect("fixed overlap kind")
}

fn overlap_queue(index: usize) -> QueueName {
    QueueName::try_new(format!("overlap-{index}")).expect("fixed overlap queue")
}

#[derive(Default)]
struct OverlapState {
    operations: AtomicU64,
    store_active: AtomicU64,
    store_peak: AtomicU64,
    handler_active: AtomicU64,
    handler_peak: AtomicU64,
}

impl OverlapState {
    fn reset(&self) {
        self.operations.store(0, Ordering::Relaxed);
        self.store_active.store(0, Ordering::Relaxed);
        self.store_peak.store(0, Ordering::Relaxed);
        self.handler_active.store(0, Ordering::Relaxed);
        self.handler_peak.store(0, Ordering::Relaxed);
    }

    fn operation(&self) {
        self.operations.fetch_add(1, Ordering::Relaxed);
    }

    fn enter_store(&self) {
        let active = self.store_active.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.store_peak, active);
    }

    fn leave_store(&self) {
        self.store_active.fetch_sub(1, Ordering::Relaxed);
    }

    fn enter_handler(&self) {
        let active = self.handler_active.fetch_add(1, Ordering::Relaxed) + 1;
        update_peak(&self.handler_peak, active);
    }

    fn leave_handler(&self) {
        self.handler_active.fetch_sub(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> OverlapSnapshot {
        OverlapSnapshot {
            operations: self.operations.load(Ordering::Relaxed),
            store_peak: self.store_peak.load(Ordering::Relaxed),
            handler_peak: self.handler_peak.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy)]
struct OverlapSnapshot {
    operations: u64,
    store_peak: u64,
    handler_peak: u64,
}

fn update_peak(peak: &AtomicU64, candidate: u64) {
    let mut current = peak.load(Ordering::Relaxed);
    while candidate > current {
        match peak.compare_exchange_weak(current, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

struct YieldNTimes {
    remaining: u8,
}

impl YieldNTimes {
    fn new(rounds: u8) -> Self {
        Self { remaining: rounds }
    }
}

impl Future for YieldNTimes {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        if self.remaining == 0 {
            Poll::Ready(())
        } else {
            self.remaining -= 1;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

struct DynamoFixture {
    items: Vec<DynamoItem>,
}

struct DynamoItem {
    key: StoreKey,
    value: Bytes,
    index_keys: Vec<StoreKey>,
}

impl DynamoFixture {
    fn build() -> Self {
        let items = (0..BASE_ITEMS)
            .map(|index| {
                let value = value_bytes(index, VALUE_SIZES[index % VALUE_SIZES.len()]);
                let index_keys = (0..INDEXES_PER_ITEM[index % INDEXES_PER_ITEM.len()])
                    .map(|gsi| index_key(gsi, index))
                    .collect();
                DynamoItem {
                    key: item_key(index),
                    value,
                    index_keys,
                }
            })
            .collect();
        Self { items }
    }

    fn seed(&self, store: &MeasuredStore) -> Result<(), FakeStoreError> {
        for item in &self.items {
            store.put_raw(item.key.clone(), item.value.clone())?;
            for key in &item.index_keys {
                store.put_raw(key.clone(), Bytes::from_static(b"gsi-projection"))?;
            }
        }
        Ok(())
    }

    fn assert_shape(&self) {
        assert_eq!(self.average_key_bytes(), KEY_BYTES);
        assert!(self.items.iter().all(|item| {
            VALUE_SIZES.contains(&item.value.len())
                && item.value.first() == Some(&LOGICAL_ATTRIBUTES)
                && item.value.get(1) == Some(&1)
                && (2..=3).contains(&item.index_keys.len())
        }));
        assert_eq!(
            self.items
                .iter()
                .map(|item| item.index_keys.len())
                .sum::<usize>(),
            2_250,
            "the fixed 2/3 GSI-equivalent mix must remain unchanged"
        );
    }

    fn average_key_bytes(&self) -> usize {
        let (bytes, count) = self
            .items
            .iter()
            .fold((0usize, 0usize), |(bytes, count), item| {
                let indexes = item
                    .index_keys
                    .iter()
                    .map(|key| key.as_bytes().len())
                    .sum::<usize>();
                (
                    bytes + item.key.as_bytes().len() + indexes,
                    count + 1 + item.index_keys.len(),
                )
            });
        bytes / count
    }
}

fn item_key(index: usize) -> StoreKey {
    shaped_key(b"realistic/base/", index, 0)
}

fn index_key(gsi: usize, index: usize) -> StoreKey {
    let prefix = if gsi == 0 {
        b"realistic/gsi0/".as_slice()
    } else if gsi == 1 {
        b"realistic/gsi1/".as_slice()
    } else {
        b"realistic/gsi2/".as_slice()
    };
    shaped_key(prefix, index, gsi as u8 + 1)
}

fn shaped_key(prefix: &[u8], index: usize, lane: u8) -> StoreKey {
    let mut bytes = vec![0u8; KEY_BYTES];
    bytes[..prefix.len()].copy_from_slice(prefix);
    bytes[prefix.len()..prefix.len() + 8].copy_from_slice(&(index as u64).to_be_bytes());
    bytes[prefix.len() + 8] = lane;
    StoreKey::try_from(bytes).expect("fixed shaped key is non-empty")
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

struct FocusedOutcome {
    lifecycle_jobs: u32,
    query_entries: Vec<u32>,
    query_bytes: Vec<u64>,
    near_entries: u32,
    near_bytes: u64,
}

async fn run_focused_workload(
    system: &JobSystem<MeasuredStore>,
    store: &MeasuredStore,
    fixture: &DynamoFixture,
) -> FocusedOutcome {
    let jobs = fixture
        .items
        .iter()
        .take(LIFECYCLE_JOBS)
        .enumerate()
        .map(|(index, item)| NewJob {
            job_id: JobId::from(job_id_bytes(index)),
            kind: JobKind::try_new("realistic-job").expect("fixed job kind"),
            schema_version: nz16(1),
            payload: item.value.clone(),
            fairness: scoped_fairness(index % 8),
            ordering_key: None,
            priority: Priority::Default,
            scheduled_at: NOW,
            expires_at: None,
            retry_override: None,
            deduplication: None,
        })
        .collect::<Vec<_>>();
    let payload_bytes = jobs.iter().map(|job| job.payload.len()).sum::<usize>();
    for job in jobs {
        system.enqueue_raw(job, NOW).await.expect("fixed enqueue");
    }
    let request = DriveRequest::try_from(DriveRequestInput {
        queues: QueueSelection::all(),
        max_claims: nz32(LIFECYCLE_JOBS as u32),
        max_concurrency: nz16(1),
        max_payload_bytes_in_flight: nz_usize(payload_bytes + VALUE_SIZES[2]),
        max_completion_details: LIFECYCLE_JOBS as u32,
        max_store_operations: nz32((LIFECYCLE_JOBS * 24) as u32),
        stop_claiming_at: MonotonicDeadline::from_nanos(u64::MAX / 2),
        finish_by: MonotonicDeadline::from_nanos(u64::MAX),
    })
    .expect("fixed drive request");
    let report = system
        .drive(request, NOW, || MonotonicDeadline::ZERO)
        .await
        .expect("fixed drive");
    assert_eq!(report.counts.succeeded, LIFECYCLE_JOBS as u32);
    assert_eq!(report.completions.len(), LIFECYCLE_JOBS);

    let (query_entries, query_bytes, near_entries, near_bytes) = run_queries(store).await;
    FocusedOutcome {
        lifecycle_jobs: report.counts.succeeded,
        query_entries,
        query_bytes,
        near_entries,
        near_bytes,
    }
}

async fn run_queries(store: &MeasuredStore) -> (Vec<u32>, Vec<u64>, u32, u64) {
    let start = StoreKey::try_from(&b"realistic/base/"[..]).expect("range start");
    let mut end_bytes = b"realistic/base/".to_vec();
    end_bytes.push(0xff);
    let end = StoreKey::try_from(end_bytes).expect("range end");
    let mut entries = Vec::with_capacity(QUERY_PAGES.len());
    let mut bytes = Vec::with_capacity(QUERY_PAGES.len());
    for item_limit in QUERY_PAGES {
        let page = read_page(store, &start, &end, item_limit, 2 * NEAR_MIB_BYTES).await;
        entries.push(page.entries.len() as u32);
        bytes.push(page.total_bytes() as u64);
    }
    let page = read_page(store, &start, &end, BASE_ITEMS as u32, NEAR_MIB_BYTES).await;
    assert!(page.total_bytes() > 900_000 && page.total_bytes() <= NEAR_MIB_BYTES);
    (
        entries,
        bytes,
        page.entries.len() as u32,
        page.total_bytes() as u64,
    )
}

async fn read_page(
    store: &MeasuredStore,
    start: &StoreKey,
    end: &StoreKey,
    item_limit: u32,
    byte_limit: usize,
) -> RangePage {
    store
        .read_range(
            RangeRequest::try_from(RangeRequestInput {
                start: Some(start.clone()),
                end: Some(end.clone()),
                direction: RangeDirection::Forward,
                item_limit: nz32(item_limit),
                byte_limit: nz_usize(byte_limit),
                continuation: None,
            })
            .expect("fixed query page"),
        )
        .await
        .expect("fixed query read")
}

struct CompleteHandler;

impl JobHandler for CompleteHandler {
    fn execute<'a>(
        &'a self,
        _context: ExecutionContext<'a>,
        _payload: &'a [u8],
    ) -> HandlerFuture<'a> {
        Box::pin(async {
            Ok(JobOutcome::Complete(
                OutcomeCode::try_new("realistic-complete").expect("fixed outcome"),
            ))
        })
    }
}

fn build_system(store: MeasuredStore) -> JobSystem<MeasuredStore> {
    let mut catalog = JobCatalog::new();
    catalog
        .register_raw(
            HandlerDefinition {
                kind: JobKind::try_new("realistic-job").expect("fixed job kind"),
                schema_version: nz16(1),
                queue: QueueName::try_new("realistic").expect("fixed queue"),
                effect_mode: EffectMode::Idempotent,
                cost_units: nz16(1),
                fairness_policy: FairnessPolicy::from(nz16(1)),
                default_retry: RetrySelection::Preset(RetryPreset::Interactive),
                default_timeout: Duration::from_secs(1),
                handler: CompleteHandler,
            },
            None,
        )
        .expect("fixed handler registration");
    JobSystemBuilder::new(store)
        .catalog(catalog)
        .namespace(Namespace::try_new(b"realistic").expect("fixed namespace"))
        .owner(OwnerId::from([0x81; 16]))
        .scheduler(common::wake_scheduler())
        .build()
        .expect("fixed realistic job system")
}

fn scoped_fairness(index: usize) -> FairnessClass {
    FairnessClass::from(FairnessPath::new(
        FairnessKey::try_new(format!("scope-{index}").as_bytes()).expect("fixed fair key"),
        None,
    ))
}

fn job_id_bytes(index: usize) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&SEED.wrapping_add(index as u64).to_be_bytes());
    bytes[8..].copy_from_slice(&(index as u64).to_be_bytes());
    bytes
}

#[derive(Clone)]
struct MeasuredStore {
    inner: FakeStore,
    counters: Arc<StoreCounters>,
}

impl MeasuredStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::new(),
            counters: Arc::new(StoreCounters::default()),
        }
    }

    fn put_raw(&self, key: StoreKey, value: Bytes) -> Result<(), FakeStoreError> {
        self.inner.put_raw(key, value)
    }

    fn snapshot(&self) -> StoreSnapshot {
        self.counters.snapshot()
    }
}

impl JobStore for MeasuredStore {
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

#[derive(Clone, Copy, Default)]
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

struct Sample {
    elapsed_nanos: u128,
    adjusted_nanos: u128,
    allocations: u64,
    allocated_bytes: u64,
    counts: StoreSnapshot,
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
    let counts = samples
        .iter()
        .fold(StoreSnapshot::default(), |mut total, sample| {
            total.gets += sample.counts.gets;
            total.ranges += sample.counts.ranges;
            total.commits += sample.counts.commits;
            total.committed += sample.counts.committed;
            total.conflicts += sample.counts.conflicts;
            total.unknown += sample.counts.unknown;
            total.get_key_bytes += sample.counts.get_key_bytes;
            total.range_request_key_bytes += sample.counts.range_request_key_bytes;
            total.range_result_bytes += sample.counts.range_result_bytes;
            total.transaction_bytes += sample.counts.transaction_bytes;
            total
        });
    println!(
        concat!(
            "bg_jobs_perf_realistic suite=focused phase=summary mode={} baseline_id={} ",
            "samples={} elapsed_nanos={} median_elapsed_nanos={} ",
            "median_one_ms_serial_store_call_adjusted_nanos={} allocations={} ",
            "allocated_bytes={} total_gets={} total_ranges={} total_commits={} ",
            "total_committed={} total_conflicts={} total_unknown={} total_transaction_bytes={}"
        ),
        mode,
        BASELINE_ID,
        samples.len(),
        csv_u128(&elapsed),
        median(&elapsed),
        median(&adjusted),
        csv_u64(&allocations),
        csv_u64(&allocated_bytes),
        counts.gets,
        counts.ranges,
        counts.commits,
        counts.committed,
        counts.conflicts,
        counts.unknown,
        counts.transaction_bytes,
    );
}

fn performance_mode() -> String {
    std::env::var("BG_JOBS_PERF_MODE").unwrap_or_else(|_| "manual".to_owned())
}

fn median(values: &[u128]) -> u128 {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted[sorted.len() / 2]
}

fn csv_u32(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
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

fn nz16(value: u16) -> NonZeroU16 {
    NonZeroU16::new(value).expect("fixed non-zero u16")
}

fn nz32(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).expect("fixed non-zero u32")
}

fn nz_usize(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).expect("fixed non-zero usize")
}
