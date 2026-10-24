use bytes::Bytes;

use super::{
    authority::{self, PriorFenceAuthority},
    operation::ValidatedEnqueue,
    state,
};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    model::{EnqueueDisposition, EnqueueResult, NewJob},
    store::{Check, CommitOutcome, JobStore, Mutation, StoreTransaction},
    time::Timestamp,
};

pub(super) async fn enqueue_new<S: JobStore>(
    system: &JobSystem<S>,
    request: ValidatedEnqueue<'_>,
    expected_dedupe: Option<Bytes>,
    prior_fence: Option<PriorFenceAuthority>,
) -> JobResult<EnqueueResult, S::Error> {
    if prior_fence
        .as_ref()
        .is_some_and(|prior| prior.fence_high_water == u64::MAX)
    {
        return Err(JobSystemError::LeaseConflict);
    }
    let (record, mutations) = state::build_enqueue_state(
        system,
        &request.job,
        request.registration,
        request.digest,
        request.now,
        prior_fence.as_ref(),
    )?;
    let expected_operation = prior_fence.map(|fence| fence.encoded);
    let transaction = build_enqueue_transaction(
        system,
        &request.job,
        &record,
        mutations,
        expected_dedupe,
        expected_operation,
    )
    .await?;
    resolve_enqueue_commit(system, &request, &transaction).await
}

async fn resolve_enqueue_commit<S: JobStore>(
    system: &JobSystem<S>,
    request: &ValidatedEnqueue<'_>,
    transaction: &StoreTransaction,
) -> JobResult<EnqueueResult, S::Error> {
    let may_retry = matches!(
        request.existing_match,
        authority::ExistingJobMatch::StableSeed
    );
    let attempts = if may_retry { 2 } else { 1 };
    for attempt in 0..attempts {
        let outcome = system
            .store()
            .commit(transaction)
            .await
            .map_err(JobSystemError::Store)?;
        let disposition = match outcome {
            CommitOutcome::Committed => {
                return Ok(enqueue_result(
                    &request.job,
                    EnqueueDisposition::Enqueued,
                    request.now,
                ));
            }
            CommitOutcome::Conflict => EnqueueDisposition::AlreadyPresent,
            CommitOutcome::Unknown => EnqueueDisposition::Enqueued,
        };
        match authority::reconcile_after_commit(system, request, disposition).await {
            // Reuse the complete transaction: its operation ID is bound to
            // these exact checks and mutations by the JobStore contract.
            Err(JobSystemError::UnknownCommit)
                if outcome == CommitOutcome::Unknown && may_retry && attempt == 0 => {}
            result => return result,
        }
    }
    Err(JobSystemError::UnknownCommit)
}

fn enqueue_result(job: &NewJob, disposition: EnqueueDisposition, now: Timestamp) -> EnqueueResult {
    EnqueueResult {
        job_id: job.job_id,
        disposition,
        wake: crate::time::WakeHint::from_timestamp(job.scheduled_at, now),
    }
}

async fn build_enqueue_transaction<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    record: &crate::model::JobRecordV1,
    mut mutations: Vec<Mutation>,
    expected_dedupe: Option<Bytes>,
    expected_operation: Option<Bytes>,
) -> JobResult<StoreTransaction, S::Error> {
    let wake_key = keys::wake_key(system.namespace(), &record.queue)?;
    let current_wake = system
        .store()
        .get(wake_key.clone())
        .await
        .map_err(JobSystemError::Store)?;
    let mut checks = vec![Check::Absent(keys::job_key(
        system.namespace(),
        &job.job_id,
    )?)];
    let operation_key = keys::operation_key(system.namespace(), &job.job_id)?;
    checks.push(match expected_operation {
        Some(value) => Check::Value(operation_key, value),
        None => Check::Absent(operation_key),
    });
    let wake_check = crate::wake::apply(
        wake_key,
        current_wake,
        crate::wake::WakeUpdate::Lower(record.scheduled_at),
        &mut mutations,
    )?;
    if let Some(check) = wake_check {
        checks.push(check);
    }
    append_dedupe_check(system, job, expected_dedupe, &mut checks)?;
    crate::transition::checked_transaction(system, checks, mutations)
}

fn append_dedupe_check<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    expected_dedupe: Option<Bytes>,
    checks: &mut Vec<Check>,
) -> JobResult<(), S::Error> {
    let Some(deduplication) = &job.deduplication else {
        return Ok(());
    };
    let key = keys::dedupe_key(system.namespace(), deduplication.key())?;
    checks.push(match expected_dedupe {
        Some(value) => Check::Value(key, value),
        None => Check::Absent(key),
    });
    Ok(())
}
