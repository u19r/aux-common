//! Repeated real lifecycle work with bounded retained namespace state.

use std::{
    num::NonZeroU32,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};

use bg_jobs::{
    DriveBudget, JobSystemError, Namespace, QueueSelection, Timestamp,
    runtime::{JobSystem, MonotonicDeadline, ScheduleCursor},
    store::{JobStore, RangeDirection, RangeRequest, RangeRequestInput, StoreKey},
    test_support::codec::{KeyCodec, KeyTag},
};

use crate::{
    ConformanceError, CountingStore,
    recovery_fixture::{recovery_job, recovery_schedule, recovery_system},
};

type GrowthResult<T, E> = Result<T, ConformanceError<JobSystemError<E>>>;

/// Logical job-owned rows and encoded key/value bytes, excluding provider
/// page allocation and application history. Both must stop growing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetainedJobStorage {
    pub rows: usize,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleGrowthReport {
    pub completed: u32,
    pub after_first_batch: RetainedJobStorage,
    pub after_second_batch: RetainedJobStorage,
    pub idle_mutations: u64,
}

/// Runs two equal batches of completed recurring jobs, then the same number
/// of idle observations. Supply an empty unique namespace. The same real
/// handler runs for every occurrence; this is not a journal-only workload.
pub async fn run_lifecycle_growth<S: JobStore + Clone>(
    store: S,
    namespace: Namespace,
    batch_size: NonZeroU32,
) -> GrowthResult<LifecycleGrowthReport, S::Error> {
    run_growth(store, namespace, batch_size, GrowthWorkload::Recurring).await
}

/// Runs equal batches of unique deduplication identities through actual
/// handler completion, retention-window expiry and scheduler retirement.
pub async fn run_deduplication_growth<S: JobStore + Clone>(
    store: S,
    namespace: Namespace,
    batch_size: NonZeroU32,
) -> GrowthResult<LifecycleGrowthReport, S::Error> {
    run_growth(
        store,
        namespace,
        batch_size,
        GrowthWorkload::ExpiringDeduplication,
    )
    .await
}

#[derive(Clone, Copy)]
enum GrowthWorkload {
    Recurring,
    ExpiringDeduplication,
}

async fn run_growth<S: JobStore + Clone>(
    store: S,
    namespace: Namespace,
    batch_size: NonZeroU32,
    workload: GrowthWorkload,
) -> GrowthResult<LifecycleGrowthReport, S::Error> {
    let calls = Arc::new(AtomicU32::new(0));
    let counted = CountingStore::new(store);
    let system = recovery_system(counted.clone(), namespace.clone(), calls.clone())
        .map_err(|_| ConformanceError::Invalid("growth system"))?;
    system
        .initialize_catalog()
        .await
        .map_err(ConformanceError::Store)?;
    execute_batch(&system, 0, batch_size.get(), workload).await?;
    let first = measure_retained_storage(&counted, &namespace).await?;
    execute_batch(&system, batch_size.get(), batch_size.get(), workload).await?;
    let second = measure_retained_storage(&counted, &namespace).await?;
    let completed = batch_size
        .get()
        .checked_mul(2)
        .ok_or(ConformanceError::Invalid("growth batch overflow"))?;
    if calls.load(Ordering::SeqCst) != completed || first != second {
        return Err(ConformanceError::Invalid(
            "completed work retained growing bookkeeping",
        ));
    }
    counted.reset();
    let now = occurrence_time(completed - 1)
        .checked_add(Duration::from_millis(1))
        .map_err(|_| ConformanceError::Invalid("growth idle time"))?;
    for _ in 0..batch_size.get() {
        drive_one(&system, now, 0).await?;
    }
    let idle_mutations = counted.snapshot().transaction_mutations;
    if idle_mutations != 0 {
        return Err(ConformanceError::Invalid(
            "idle observations mutated durable state",
        ));
    }
    Ok(LifecycleGrowthReport {
        completed,
        after_first_batch: first,
        after_second_batch: second,
        idle_mutations,
    })
}

async fn execute_batch<S: JobStore>(
    system: &JobSystem<S>,
    start: u32,
    count: u32,
    workload: GrowthWorkload,
) -> GrowthResult<(), S::Error> {
    let schedule = recovery_schedule().map_err(|_| ConformanceError::Invalid("growth schedule"))?;
    let initial = ScheduleCursor::new(Some(Timestamp::ZERO), true);
    for index in start
        ..start
            .checked_add(count)
            .ok_or(ConformanceError::Invalid("growth interval overflow"))?
    {
        let now = occurrence_time(index);
        match workload {
            GrowthWorkload::Recurring => {
                let report = system
                    .materialize_schedule(&schedule, &initial, now)
                    .await
                    .map_err(ConformanceError::Store)?;
                if report.occurrences.len() != 1 {
                    return Err(ConformanceError::Invalid("growth occurrence admission"));
                }
                drive_one(system, now, 1).await?;
            }
            GrowthWorkload::ExpiringDeduplication => {
                execute_deduplicated_job(system, index, now).await?
            }
        }
    }
    Ok(())
}

async fn execute_deduplicated_job<S: JobStore>(
    system: &JobSystem<S>,
    index: u32,
    now: Timestamp,
) -> GrowthResult<(), S::Error> {
    let mut job =
        recovery_job(1).map_err(|_| ConformanceError::Invalid("growth deduplicated job"))?;
    job.job_id = bg_jobs::JobId::from(u128::from(index).to_be_bytes());
    job.scheduled_at = now;
    let until = now
        .checked_add(Duration::from_millis(1))
        .map_err(|_| ConformanceError::Invalid("growth expiry time"))?;
    let identity = bg_jobs::DeduplicationKey::try_new(index.to_be_bytes())
        .map_err(|_| ConformanceError::Invalid("growth identity"))?;
    job.deduplication = Some(
        bg_jobs::Deduplication::try_new(identity, until)
            .map_err(|_| ConformanceError::Invalid("growth retention"))?,
    );
    system
        .enqueue_raw(job, now)
        .await
        .map_err(ConformanceError::Store)?;
    drive_one(system, now, 1).await?;
    drive_one(system, until, 0).await
}

fn occurrence_time(index: u32) -> Timestamp {
    Timestamp::from_millis(i64::from(index) * 60 * 60 * 1_000)
}

async fn drive_one<S: JobStore>(
    system: &JobSystem<S>,
    now: Timestamp,
    expected: u32,
) -> GrowthResult<(), S::Error> {
    let request = DriveBudget::try_tiny(QueueSelection::all())
        .and_then(|budget| budget.request_at(MonotonicDeadline::ZERO))
        .map_err(|_| ConformanceError::Invalid("growth drive budget"))?;
    let report = system
        .drive(request, now, || MonotonicDeadline::ZERO)
        .await
        .map_err(ConformanceError::Store)?;
    if report.counts.succeeded != expected || report.counts.claimed != expected {
        return Err(ConformanceError::Invalid(
            "growth handler did not complete expected work",
        ));
    }
    Ok(())
}

async fn measure_retained_storage<S: JobStore>(
    store: &S,
    namespace: &Namespace,
) -> GrowthResult<RetainedJobStorage, S::Error> {
    let encoded = KeyCodec::encode(namespace, KeyTag::Catalog, &[])
        .map_err(|_| ConformanceError::Invalid("growth namespace key"))?;
    let prefix = &encoded.as_bytes()[..encoded.as_bytes().len() - 1];
    let mut end = prefix.to_vec();
    end.push(u8::MAX);
    let start =
        StoreKey::try_from(prefix).map_err(|_| ConformanceError::Invalid("growth start key"))?;
    let end = StoreKey::try_from(end).map_err(|_| ConformanceError::Invalid("growth end key"))?;
    let capabilities = store.capabilities();
    let mut continuation = None;
    let mut retained = RetainedJobStorage { rows: 0, bytes: 0 };
    loop {
        let request = RangeRequest::try_from(RangeRequestInput {
            start: Some(start.clone()),
            end: Some(end.clone()),
            direction: RangeDirection::Forward,
            item_limit: capabilities.max_range_items(),
            byte_limit: capabilities.max_range_bytes(),
            continuation,
        })
        .map_err(|_| ConformanceError::Invalid("growth range"))?;
        let page = store
            .read_range(request)
            .await
            .map_err(|error| ConformanceError::Store(JobSystemError::Store(error)))?;
        for entry in page.entries {
            validate_retained_key(namespace, &entry.key)?;
            retained.rows += 1;
            retained.bytes += entry.key.as_bytes().len() + entry.value.len();
        }
        continuation = page.continuation;
        if continuation.is_none() {
            return Ok(retained);
        }
    }
}

fn validate_retained_key<E>(namespace: &Namespace, key: &StoreKey) -> GrowthResult<(), E> {
    let decoded = KeyCodec::decode(namespace, key)
        .map_err(|_| ConformanceError::Invalid("growth retained key"))?;
    match decoded.tag {
        KeyTag::Catalog | KeyTag::Commit | KeyTag::Fence | KeyTag::Wake => Ok(()),
        KeyTag::FairReady if decoded.components == [b"dispatch-state".to_vec()] => Ok(()),
        _ => Err(ConformanceError::Invalid(
            "completed job-specific record remained",
        )),
    }
}
