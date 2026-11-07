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
    DriveBudget, JobId, JobState, JobSystemError, LifecycleObservation, Namespace, QueueSelection,
    Timestamp,
    runtime::{JobSystem, MonotonicDeadline, ScheduleCursor, ScheduleOccurrence},
    store::{JobStore, RangeDirection, RangeRequest, RangeRequestInput, StoreKey},
    test_support::codec::{KeyCodec, KeyTag},
};

use crate::{
    ConformanceError, CountingStore,
    constants::GROWTH_RESOLUTION_ATTEMPTS,
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
pub(super) enum GrowthWorkload {
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
    let execution = GrowthExecution {
        system: &system,
        calls: &calls,
    };
    execution.resolve(|| system.initialize_catalog()).await?;
    execution
        .execute_batch(0, batch_size.get(), workload)
        .await?;
    let first = measure_retained_storage(&counted, &namespace).await?;
    let completed_at = execution
        .execute_batch(batch_size.get(), batch_size.get(), workload)
        .await?;
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
    let idle_mutations = execution
        .measure_idle_mutations(&counted, completed_at, batch_size.get())
        .await?;
    Ok(LifecycleGrowthReport {
        completed,
        after_first_batch: first,
        after_second_batch: second,
        idle_mutations,
    })
}

pub(super) struct GrowthExecution<'a, S: JobStore> {
    pub(super) system: &'a JobSystem<S>,
    pub(super) calls: &'a AtomicU32,
}

impl<S: JobStore> GrowthExecution<'_, S> {
    pub(super) async fn resolve<T, F, Fut>(&self, mut operation: F) -> GrowthResult<T, S::Error>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, JobSystemError<S::Error>>>,
    {
        for _ in 0..GROWTH_RESOLUTION_ATTEMPTS {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(JobSystemError::UnknownCommit) => match self.system.recover_commits().await {
                    Ok(_) | Err(JobSystemError::UnknownCommit) => {}
                    Err(error) => return Err(ConformanceError::Store(error)),
                },
                Err(error) => return Err(ConformanceError::Store(error)),
            }
        }
        Err(ConformanceError::Store(JobSystemError::UnknownCommit))
    }

    pub(super) async fn execute_batch(
        &self,
        start: u32,
        count: u32,
        workload: GrowthWorkload,
    ) -> GrowthResult<Timestamp, S::Error> {
        let schedule =
            recovery_schedule().map_err(|_| ConformanceError::Invalid("growth schedule"))?;
        let initial = ScheduleCursor::new(Some(Timestamp::ZERO), true);
        let end = start
            .checked_add(count)
            .ok_or(ConformanceError::Invalid("growth interval overflow"))?;
        let mut settled_at = Timestamp::ZERO;
        for index in start..end {
            let now = occurrence_time(index);
            settled_at = match workload {
                GrowthWorkload::Recurring => {
                    let job = self.admit_occurrence(&schedule, &initial, now).await?;
                    self.drive_one(now, Some(job)).await?
                }
                GrowthWorkload::ExpiringDeduplication => {
                    self.execute_deduplicated_job(index, now).await?
                }
            };
        }
        Ok(settled_at)
    }

    async fn admit_occurrence(
        &self,
        schedule: &bg_jobs::runtime::RecurringSchedule,
        initial: &ScheduleCursor,
        now: Timestamp,
    ) -> GrowthResult<JobId, S::Error> {
        let job = ScheduleOccurrence {
            schedule_id: schedule.schedule_id,
            intended_at: now,
            generation: initial.generation(),
        }
        .job_id();
        let report = self
            .resolve(|| self.system.materialize_schedule(schedule, initial, now))
            .await?;
        if report.occurrences.len() > 1 || report.cursor.last_intended() != Some(now) {
            return Err(ConformanceError::Invalid("growth occurrence admission"));
        }
        if report.occurrences.is_empty()
            && matches!(
                self.system
                    .observe_lifecycle(job)
                    .await
                    .map_err(ConformanceError::Store)?,
                LifecycleObservation::Missing
            )
        {
            return Err(ConformanceError::Invalid(
                "growth occurrence missing after admission",
            ));
        }
        Ok(job)
    }

    async fn measure_idle_mutations<T: JobStore>(
        &self,
        counted: &CountingStore<T>,
        completed_at: Timestamp,
        count: u32,
    ) -> GrowthResult<u64, S::Error> {
        counted.reset();
        let now = completed_at
            .checked_add(Duration::from_millis(1))
            .map_err(|_| ConformanceError::Invalid("growth idle time"))?;
        for _ in 0..count {
            self.drive_one(now, None).await?;
        }
        let mutations = counted.snapshot().transaction_mutations;
        if mutations != 0 {
            return Err(ConformanceError::Invalid(
                "idle observations mutated durable state",
            ));
        }
        Ok(mutations)
    }

    async fn execute_deduplicated_job(
        &self,
        index: u32,
        now: Timestamp,
    ) -> GrowthResult<Timestamp, S::Error> {
        let mut job =
            recovery_job(1).map_err(|_| ConformanceError::Invalid("growth deduplicated job"))?;
        job.job_id = JobId::from(u128::from(index).to_be_bytes());
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
        self.resolve(|| self.system.enqueue_raw(job.clone(), now))
            .await?;
        let settled_at = self.drive_one(now, Some(job.job_id)).await?;
        self.drive_one(until.max(settled_at), None).await
    }

    pub(super) async fn drive_one(
        &self,
        mut now: Timestamp,
        job: Option<JobId>,
    ) -> GrowthResult<Timestamp, S::Error> {
        let before = self.calls.load(Ordering::SeqCst);
        let expected = u32::from(job.is_some());
        let mut uncertain = false;
        for _ in 0..GROWTH_RESOLUTION_ATTEMPTS {
            let request = DriveBudget::try_tiny(QueueSelection::all())
                .and_then(|budget| budget.request_at(MonotonicDeadline::ZERO))
                .map_err(|_| ConformanceError::Invalid("growth drive budget"))?;
            let report = match self
                .system
                .drive(request, now, || MonotonicDeadline::ZERO)
                .await
            {
                Err(JobSystemError::UnknownCommit) => {
                    uncertain = true;
                    continue;
                }
                Err(error) => return Err(ConformanceError::Store(error)),
                Ok(report) => report,
            };
            if self.turn_completed(&report, before, expected)? {
                return Ok(now);
            }
            if !uncertain {
                return Err(ConformanceError::Invalid(
                    "growth handler did not complete expected work",
                ));
            }
            match self.reconcile_turn(job, now, before).await? {
                None => return Ok(now),
                Some(next) => now = next,
            }
        }
        Err(ConformanceError::Store(JobSystemError::UnknownCommit))
    }

    fn turn_completed(
        &self,
        report: &bg_jobs::DriveReport,
        before: u32,
        expected: u32,
    ) -> GrowthResult<bool, S::Error> {
        let calls = self
            .calls
            .load(Ordering::SeqCst)
            .checked_sub(before)
            .ok_or(ConformanceError::Invalid("growth handler count regressed"))?;
        if calls > expected {
            return Err(ConformanceError::Invalid("growth handler repeated"));
        }
        Ok(report.counts.claimed == expected
            && report.counts.succeeded == expected
            && calls == expected)
    }

    async fn reconcile_turn(
        &self,
        job: Option<JobId>,
        now: Timestamp,
        before: u32,
    ) -> GrowthResult<Option<Timestamp>, S::Error> {
        let job = job.ok_or(ConformanceError::Invalid("idle growth turn executed work"))?;
        let calls = self
            .calls
            .load(Ordering::SeqCst)
            .checked_sub(before)
            .ok_or(ConformanceError::Invalid("growth handler count regressed"))?;
        match self
            .system
            .observe_lifecycle(job)
            .await
            .map_err(ConformanceError::Store)?
        {
            LifecycleObservation::Missing if calls == 1 => Ok(None),
            LifecycleObservation::Current { record, .. } => match record.state {
                JobState::Leased(lease) if calls == 0 => {
                    let expired = lease
                        .expires_at
                        .checked_add(Duration::from_millis(1))
                        .map_err(|_| ConformanceError::Invalid("growth recovery time"))?;
                    Ok(Some(now.max(expired)))
                }
                JobState::Leased(_) | JobState::Scheduled => Ok(Some(now)),
                JobState::DeadLettered | JobState::Cancelled | JobState::Suspended => {
                    Err(ConformanceError::Invalid("growth work did not complete"))
                }
            },
            _ => Err(ConformanceError::Invalid(
                "growth lifecycle evidence missing",
            )),
        }
    }
}

fn occurrence_time(index: u32) -> Timestamp {
    Timestamp::from_millis(i64::from(index) * 60 * 60 * 1_000)
}

pub(super) async fn measure_retained_storage<S: JobStore>(
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
