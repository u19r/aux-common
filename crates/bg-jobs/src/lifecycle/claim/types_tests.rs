use std::{
    future::Future,
    num::{NonZeroU16, NonZeroU64},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Instant,
};

use alloc_counter::AllocationGuard;
use bytes::Bytes;

use crate::{
    JobStore,
    codec::encode_job_record,
    error::JobResult,
    ids::{JobId, LeaseToken, Namespace, OrderingKey, OwnerId},
    keys,
    model::{JobRecordV1, JobState, Lease},
    policy::{FairnessClass, FairnessPolicy},
    store::{
        CommitOutcome, RangePage, RangeRequest, StoreCapabilities, StoreKey, StoreTransaction,
    },
    test_helper::{FakeStore, FakeStoreError, block_on},
    time::Timestamp,
};

const SAMPLES: usize = 3;
const WARMUPS: usize = 1;
const READ_YIELDS: usize = 512;
const FOCUSED_CAPACITY: u16 = 1;
const BROAD_CAPACITY: u16 = 16;
const CHECKPOINT_BYTES: usize = 1_100;

#[test]
fn given_a_revoked_claim_when_requesting_context_then_no_execution_permission_is_exposed() {
    let system = crate::test_helper::system(FakeStore::local(), FairnessPolicy::low_volume(), 1);
    block_on(system.enqueue_raw(
        crate::test_helper::low_volume_job(98, Timestamp::ZERO),
        Timestamp::ZERO,
    ))
    .expect("enqueue commits");
    let mut claim =
        block_on(system.claim(JobId::from([98; 16]), Timestamp::ZERO)).expect("claim commits");
    assert!(claim.context().is_some());
    assert!(matches!(
        block_on(system.renew(&mut claim, Timestamp::from_millis(2000))),
        Err(crate::JobSystemError::LeaseLost)
    ));
    assert!(claim.context().is_none());
}

#[test]
#[ignore = "debug-only claim performance baseline; run explicitly during the optimisation loop"]
fn given_realistic_claim_reads_when_serial_then_reports_three_samples() {
    for workload in [Workload::Focused, Workload::Broad] {
        for _ in 0..WARMUPS {
            let fixture = ClaimFixture::build(READ_YIELDS);
            let _ = black_box(block_on(run_serial_reads(
                &fixture.system,
                &fixture.record,
                workload.capacity(),
            )));
        }
        let mut samples = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            let fixture = ClaimFixture::build(READ_YIELDS);
            let guard = AllocationGuard::start(
                module_path!(),
                "given_realistic_claim_reads_when_serial_then_reports_three_samples",
                file!(),
                line!(),
                Some(workload.label()),
            );
            let started = Instant::now();
            let result = block_on(run_serial_reads(
                &fixture.system,
                &fixture.record,
                workload.capacity(),
            ))
            .expect("serial claim reads succeed");
            let elapsed_nanos = started.elapsed().as_nanos();
            let allocations = guard.finish();
            let metrics = fixture.store.snapshot();
            assert_eq!(result.0, 0);
            assert!(result.1.is_some());
            assert_eq!(metrics.get_calls, 1);
            assert_eq!(metrics.get_many_calls, 1);
            assert_eq!(metrics.peak_active, 1);
            println!(
                "bg_jobs_perf_claim mode=baseline workload={} sample={} key_bytes={} \
                 record_bytes={} permit_keys={} get_calls={} get_many_calls={} get_many_keys={} \
                 get_key_bytes={} get_many_key_bytes={} allocations={} allocated_bytes={} \
                 elapsed_nanos={} peak_active={}",
                workload.label(),
                sample,
                fixture.average_key_bytes(),
                fixture.record_bytes,
                workload.permit_key_count(),
                metrics.get_calls,
                metrics.get_many_calls,
                metrics.get_many_keys,
                metrics.get_key_bytes,
                metrics.get_many_key_bytes,
                allocations.allocation_count,
                allocations.allocated_bytes,
                elapsed_nanos,
                metrics.peak_active,
            );
            samples.push(Sample {
                elapsed_nanos,
                allocations: allocations.allocation_count,
                allocated_bytes: allocations.allocated_bytes,
            });
        }
        println!(
            "bg_jobs_perf_claim mode=baseline workload={} median_elapsed_nanos={} \
             elapsed_nanos={} allocations={} allocated_bytes={}",
            workload.label(),
            median(samples.iter().map(|sample| sample.elapsed_nanos).collect()),
            csv(samples.iter().map(|sample| sample.elapsed_nanos).collect()),
            csv(samples.iter().map(|sample| sample.allocations).collect()),
            csv(samples
                .iter()
                .map(|sample| sample.allocated_bytes)
                .collect()),
        );
    }
}

#[test]
fn given_claim_reads_when_joined_then_both_operations_overlap_and_keep_their_results() {
    let fixture = ClaimFixture::build(2);
    let (fence, permits) = block_on(super::flow::join_claim_reads(
        &fixture.system,
        &fixture.record,
        Workload::Focused.capacity(),
    ));
    let fence = fence.expect("fence read succeeds");
    let permits = permits
        .expect("permit discovery succeeds")
        .expect("a permit set is available");
    let metrics = fixture.store.snapshot();

    assert_eq!(fence, 0);
    assert_eq!(permits.len(), Workload::Focused.permit_key_count());
    assert_eq!(metrics.get_calls, 1);
    assert_eq!(metrics.get_many_calls, 1);
    assert_eq!(metrics.peak_active, 2);
}

#[test]
fn given_joined_claim_reads_when_dropped_then_inflight_reads_are_cancelled() {
    let fixture = ClaimFixture::build(2);
    let mut future = Box::pin(super::flow::join_claim_reads(
        &fixture.system,
        &fixture.record,
        Workload::Focused.capacity(),
    ));
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);

    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
    assert_eq!(fixture.store.metrics.active.load(Ordering::Relaxed), 2);
    drop(future);
    assert_eq!(fixture.store.metrics.active.load(Ordering::Relaxed), 0);
}

#[test]
fn given_a_malformed_fence_marker_when_claiming_then_fence_error_precedes_permit_result() {
    let fixture = ClaimFixture::build(2);
    let operation_key = keys::operation_key(fixture.system.namespace(), &fixture.record.job_id)
        .expect("operation key is valid");
    fixture
        .store
        .inner
        .put_raw(operation_key, Bytes::from_static(&[0x7f]))
        .expect("malformed operation marker writes");
    fixture.store.reset_metrics();
    let due_key = keys::due_key(
        fixture.system.namespace(),
        &fixture.record.queue,
        fixture.record.scheduled_at,
        &fixture.record.job_id,
    )
    .expect("due key is valid");
    let result = block_on(super::claim_record_with_capacity(
        &fixture.system,
        super::ClaimRecordInput {
            record: fixture.record.clone(),
            encoded: encode_job_record(&fixture.record).expect("record encodes"),
            route: super::ClaimRoute::Due {
                key: due_key,
                value: keys::due_value(fixture.record.scheduled_at).expect("due value encodes"),
            },
            now: Timestamp::ZERO,
            capacity: Workload::Focused.capacity(),
            deadline: None,
        },
    ));
    let metrics = fixture.store.snapshot();

    assert!(matches!(
        result,
        Err(crate::error::JobSystemError::StoreData(_))
    ));
    assert_eq!(metrics.get_calls, 1);
    assert_eq!(metrics.get_many_calls, 1);
    assert_eq!(metrics.peak_active, 2);
}

#[test]
fn given_each_state_with_a_lease_route_when_claiming_then_state_is_rejected_unchanged() {
    for state in [
        JobState::Scheduled,
        JobState::Leased(
            Lease::try_new(
                OwnerId::from([1; 16]),
                LeaseToken::from([3; 16]),
                NonZeroU64::MIN,
                Timestamp::from_millis(1),
            )
            .expect("active lease is valid"),
        ),
        JobState::DeadLettered,
        JobState::Cancelled,
    ] {
        let fixture = ClaimFixture::build(0);
        let id = fixture.record.job_id;
        let mut record = fixture.record.clone();
        record.state = state;
        let encoded = encode_job_record(&record).expect("state fixture encodes");
        let job_key = keys::job_key(fixture.system.namespace(), &id).expect("job key is valid");
        fixture
            .store
            .inner
            .put_raw(job_key, encoded)
            .expect("state fixture writes");
        let due_key = keys::due_key(
            fixture.system.namespace(),
            &record.queue,
            record.scheduled_at,
            &id,
        )
        .expect("due key is valid");
        fixture
            .store
            .inner
            .delete_raw(&due_key)
            .expect("due route deletes");
        let lease_key = keys::lease_key(fixture.system.namespace(), &record.queue, &id)
            .expect("lease key is valid");
        fixture
            .store
            .inner
            .put_raw(
                lease_key,
                keys::lease_value(&id).expect("lease value is valid"),
            )
            .expect("lease route writes");
        let before = fixture.store.inner.snapshot().expect("snapshot succeeds");

        let result = block_on(super::claim(&fixture.system, id, Timestamp::ZERO));

        assert!(matches!(
            result,
            Err(crate::error::JobSystemError::LeaseConflict)
        ));
        assert_eq!(
            fixture.store.inner.snapshot().expect("snapshot succeeds"),
            before,
        );
    }
}

#[test]
#[ignore = "debug-only claim performance candidate; run explicitly during the optimisation loop"]
fn given_realistic_claim_reads_when_concurrent_then_reports_three_samples() {
    for workload in [Workload::Focused, Workload::Broad] {
        for _ in 0..WARMUPS {
            let fixture = ClaimFixture::build(READ_YIELDS);
            let _ = black_box(block_on(super::flow::join_claim_reads(
                &fixture.system,
                &fixture.record,
                workload.capacity(),
            )));
        }
        let mut samples = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            let fixture = ClaimFixture::build(READ_YIELDS);
            let guard = AllocationGuard::start(
                module_path!(),
                "given_realistic_claim_reads_when_concurrent_then_reports_three_samples",
                file!(),
                line!(),
                Some(workload.label()),
            );
            let started = Instant::now();
            let (fence, permits) = block_on(super::flow::join_claim_reads(
                &fixture.system,
                &fixture.record,
                workload.capacity(),
            ));
            let elapsed_nanos = started.elapsed().as_nanos();
            let allocations = guard.finish();
            let metrics = fixture.store.snapshot();
            assert_eq!(fence.expect("concurrent fence read succeeds"), 0);
            assert_eq!(
                permits
                    .expect("concurrent permit discovery succeeds")
                    .expect("a permit set is available")
                    .len(),
                3,
            );
            assert_eq!(metrics.get_calls, 1);
            assert_eq!(metrics.get_many_calls, 1);
            assert_eq!(metrics.get_many_keys, workload.permit_key_count());
            assert_eq!(metrics.peak_active, 2);
            println!(
                "bg_jobs_perf_claim mode=candidate workload={} sample={} key_bytes={} \
                 record_bytes={} permit_keys={} get_calls={} get_many_calls={} get_many_keys={} \
                 get_key_bytes={} get_many_key_bytes={} allocations={} allocated_bytes={} \
                 elapsed_nanos={} peak_active={}",
                workload.label(),
                sample,
                fixture.average_key_bytes(),
                fixture.record_bytes,
                workload.permit_key_count(),
                metrics.get_calls,
                metrics.get_many_calls,
                metrics.get_many_keys,
                metrics.get_key_bytes,
                metrics.get_many_key_bytes,
                allocations.allocation_count,
                allocations.allocated_bytes,
                elapsed_nanos,
                metrics.peak_active,
            );
            samples.push(Sample {
                elapsed_nanos,
                allocations: allocations.allocation_count,
                allocated_bytes: allocations.allocated_bytes,
            });
        }
        println!(
            "bg_jobs_perf_claim mode=candidate workload={} median_elapsed_nanos={} \
             elapsed_nanos={} allocations={} allocated_bytes={}",
            workload.label(),
            median(samples.iter().map(|sample| sample.elapsed_nanos).collect()),
            csv(samples.iter().map(|sample| sample.elapsed_nanos).collect()),
            csv(samples.iter().map(|sample| sample.allocations).collect()),
            csv(samples
                .iter()
                .map(|sample| sample.allocated_bytes)
                .collect()),
        );
    }
}

async fn run_serial_reads<S: JobStore>(
    system: &crate::engine::JobSystem<S>,
    record: &JobRecordV1,
    capacity: std::num::NonZeroU16,
) -> JobResult<(u64, Option<Vec<StoreKey>>), S::Error> {
    let fence = super::flow::load_fence_high_water(system, record.job_id).await?;
    let permits = crate::fairness::find_available_permit_keys(system, record, capacity).await?;
    Ok((fence, permits))
}

#[derive(Clone, Copy)]
enum Workload {
    Focused,
    Broad,
}

impl Workload {
    const fn label(self) -> &'static str {
        match self {
            Self::Focused => "focused",
            Self::Broad => "broad",
        }
    }

    fn capacity(self) -> std::num::NonZeroU16 {
        match self {
            Self::Focused => {
                std::num::NonZeroU16::new(FOCUSED_CAPACITY).unwrap_or(std::num::NonZeroU16::MIN)
            }
            Self::Broad => {
                std::num::NonZeroU16::new(BROAD_CAPACITY).unwrap_or(std::num::NonZeroU16::MIN)
            }
        }
    }

    const fn permit_key_count(self) -> usize {
        match self {
            Self::Focused => 3,
            Self::Broad => 48,
        }
    }
}

struct ClaimFixture {
    store: YieldingStore,
    system: crate::engine::JobSystem<YieldingStore>,
    record: JobRecordV1,
    record_bytes: usize,
}

impl ClaimFixture {
    fn build(read_yields: usize) -> Self {
        let store = YieldingStore::new(read_yields);
        let system = crate::engine::JobSystem::new(
            store.clone(),
            crate::JobCatalog::from_registry(crate::test_helper::registry(FairnessPolicy::from(
                NonZeroU16::MIN,
            ))),
            Namespace::try_new(b"claim-perf-namespace-1234567890").expect("namespace is valid"),
            OwnerId::from([7; 16]),
            crate::test_helper::wake_scheduler(),
        );
        let mut job = crate::test_helper::job(
            1,
            Bytes::from(vec![0x41; 1_200]),
            FairnessClass::low_volume(),
            Timestamp::ZERO,
            None,
            None,
        );
        job.fairness = FairnessClass::from(crate::policy::FairnessPath::new(
            crate::ids::FairnessKey::try_new([0x42; 16]).expect("primary fairness key is valid"),
            Some(
                crate::ids::FairnessKey::try_new([0x43; 16])
                    .expect("secondary fairness key is valid"),
            ),
        ));
        job.ordering_key = Some(OrderingKey::try_new([0x45; 16]).expect("ordering key is valid"));
        block_on(system.enqueue_raw(job, Timestamp::ZERO)).expect("fixture enqueue succeeds");
        let job_id = JobId::from([1; 16]);
        let job_key = keys::job_key(system.namespace(), &job_id).expect("job key is valid");
        let encoded = block_on(JobStore::get(&store.inner, job_key.clone()))
            .expect("fixture record read succeeds")
            .expect("fixture record exists");
        let mut record = crate::codec::decode_job_record(&encoded).expect("fixture record decodes");
        record.checkpoint = Some(Bytes::from(vec![0x44; CHECKPOINT_BYTES]));
        let encoded = encode_job_record(&record).expect("realistic record encodes");
        store
            .inner
            .put_raw(job_key, encoded.clone())
            .expect("realistic record write succeeds");
        store.reset_metrics();
        Self {
            store,
            system,
            record,
            record_bytes: encoded.len(),
        }
    }

    fn average_key_bytes(&self) -> usize {
        let keys = keys::permit_key_sets(
            self.system.namespace(),
            &self.record,
            std::num::NonZeroU16::new(BROAD_CAPACITY).unwrap_or(std::num::NonZeroU16::MIN),
        )
        .expect("permit keys are valid")
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        keys.iter().map(|key| key.as_bytes().len()).sum::<usize>() / keys.len().max(1)
    }
}

#[derive(Clone)]
struct YieldingStore {
    inner: FakeStore,
    read_yields: usize,
    metrics: Arc<ReadMetrics>,
}

impl YieldingStore {
    fn new(read_yields: usize) -> Self {
        Self {
            inner: FakeStore::new(),
            read_yields,
            metrics: Arc::new(ReadMetrics::default()),
        }
    }

    fn reset_metrics(&self) {
        self.metrics.get_calls.store(0, Ordering::Relaxed);
        self.metrics.get_many_calls.store(0, Ordering::Relaxed);
        self.metrics.get_many_keys.store(0, Ordering::Relaxed);
        self.metrics.get_key_bytes.store(0, Ordering::Relaxed);
        self.metrics.get_many_key_bytes.store(0, Ordering::Relaxed);
        self.metrics.peak_active.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ReadSnapshot {
        ReadSnapshot {
            get_calls: self.metrics.get_calls.load(Ordering::Relaxed),
            get_many_calls: self.metrics.get_many_calls.load(Ordering::Relaxed),
            get_many_keys: self.metrics.get_many_keys.load(Ordering::Relaxed),
            get_key_bytes: self.metrics.get_key_bytes.load(Ordering::Relaxed),
            get_many_key_bytes: self.metrics.get_many_key_bytes.load(Ordering::Relaxed),
            peak_active: self.metrics.peak_active.load(Ordering::Relaxed),
        }
    }
}

impl JobStore for YieldingStore {
    type Error = FakeStoreError;

    fn capabilities(&self) -> StoreCapabilities {
        self.inner.capabilities()
    }

    fn get(
        &self,
        key: StoreKey,
    ) -> impl Future<Output = Result<Option<Bytes>, Self::Error>> + Send + '_ {
        self.metrics.get_calls.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .get_key_bytes
            .fetch_add(key.as_bytes().len(), Ordering::Relaxed);
        DelayedRead::new(
            self.inner.get(key),
            self.read_yields,
            Arc::clone(&self.metrics),
        )
    }

    fn get_many<'a>(
        &'a self,
        keys: &'a [StoreKey],
    ) -> impl Future<Output = Result<Vec<Option<Bytes>>, Self::Error>> + Send + 'a {
        self.metrics.get_many_calls.fetch_add(1, Ordering::Relaxed);
        self.metrics
            .get_many_keys
            .fetch_add(keys.len(), Ordering::Relaxed);
        self.metrics.get_many_key_bytes.fetch_add(
            keys.iter().map(|key| key.as_bytes().len()).sum(),
            Ordering::Relaxed,
        );
        DelayedRead::new(
            self.inner.get_many(keys),
            self.read_yields,
            Arc::clone(&self.metrics),
        )
    }

    fn read_range(
        &self,
        request: RangeRequest,
    ) -> impl Future<Output = Result<RangePage, Self::Error>> + Send + '_ {
        self.inner.read_range(request)
    }

    fn commit<'a>(
        &'a self,
        transaction: &'a StoreTransaction,
    ) -> impl Future<Output = Result<CommitOutcome, Self::Error>> + Send + 'a {
        self.inner.commit(transaction)
    }
}

struct DelayedRead<F> {
    inner: Pin<Box<F>>,
    remaining: usize,
    metrics: Arc<ReadMetrics>,
    active: bool,
}

impl<F: Future> DelayedRead<F> {
    fn new(inner: F, remaining: usize, metrics: Arc<ReadMetrics>) -> Self {
        Self {
            inner: Box::pin(inner),
            remaining,
            metrics,
            active: false,
        }
    }
}

impl<F: Future> Future for DelayedRead<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.as_mut().get_mut();
        if !this.active {
            this.active = true;
            let active = this.metrics.active.fetch_add(1, Ordering::Relaxed) + 1;
            let mut peak = this.metrics.peak_active.load(Ordering::Relaxed);
            while active > peak {
                match this.metrics.peak_active.compare_exchange(
                    peak,
                    active,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => peak = current,
                }
            }
        }
        if this.remaining > 0 {
            this.remaining -= 1;
            context.waker().wake_by_ref();
            return Poll::Pending;
        }
        match this.inner.as_mut().poll(context) {
            Poll::Ready(output) => {
                this.finish();
                Poll::Ready(output)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F> DelayedRead<F> {
    fn finish(&mut self) {
        if self.active {
            self.active = false;
            self.metrics.active.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

impl<F> Drop for DelayedRead<F> {
    fn drop(&mut self) {
        self.finish();
    }
}

#[derive(Default)]
struct ReadMetrics {
    active: AtomicUsize,
    peak_active: AtomicUsize,
    get_calls: AtomicUsize,
    get_many_calls: AtomicUsize,
    get_many_keys: AtomicUsize,
    get_key_bytes: AtomicUsize,
    get_many_key_bytes: AtomicUsize,
}

struct ReadSnapshot {
    get_calls: usize,
    get_many_calls: usize,
    get_many_keys: usize,
    get_key_bytes: usize,
    get_many_key_bytes: usize,
    peak_active: usize,
}

struct Sample {
    elapsed_nanos: u128,
    allocations: u64,
    allocated_bytes: u64,
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn csv<T: std::fmt::Display>(values: Vec<T>) -> String {
    values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn black_box<T>(value: T) -> T {
    std::hint::black_box(value)
}
