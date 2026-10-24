use bytes::Bytes;

use super::repository::{load_job, load_job_operation, load_lease_markers, load_scheduled_markers};
use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    failure::CancellationResult,
    ids::{JobId, OperationId},
    keys,
    lifecycle::ClaimedJob,
    model::{JobRecordV1, JobState},
    store::{Check, JobStore, Mutation},
    time::Timestamp,
    transition::{
        authority_checks, checked_transaction, commit_marker, commit_record_without_claim,
        fresh_operation, next_revision, wake_mutation,
    },
};

/// Signals a claimed handler and records cancellation without mutating its job
/// state yet.
pub(crate) async fn request_job_cancellation<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    now: Timestamp,
) -> JobResult<CancellationResult, S::Error> {
    // Cancellation is a control operation on the exact durable lease. A
    // failed handler renewal must not disable idempotent cancellation.
    claim.lease_at(now).ok_or(JobSystemError::LeaseLost)?;
    let key = keys::cancellation_key(system.namespace(), &claim.record().job_id)?;
    let cancellation_check = match system
        .store()
        .get(key.clone())
        .await
        .map_err(JobSystemError::Store)?
    {
        Some(value) => {
            keys::validate_empty_marker(&value, crate::codec::ValueTag::Cancellation)
                .map_err(|_| JobSystemError::PayloadCorrupt)?;
            Check::Value(key.clone(), value)
        }
        None => Check::Absent(key.clone()),
    };
    let mut checks = authority_checks(system, claim)?;
    checks.push(cancellation_check);
    let cancellation = keys::cancellation_value()?;
    let transaction = checked_transaction(
        system,
        checks,
        vec![Mutation::Put(key.clone(), cancellation)],
    )?;
    commit_marker(system, transaction, &key).await?;
    let claim_cancellation = claim.cancellation();
    system.signal_matching_attempt(
        claim.record().job_id,
        claim.fence_high_water(),
        Some(&claim_cancellation),
    );
    system.observe(crate::observer::JobEvent::CancellationRequested {
        queue: claim.record().queue.clone(),
    });
    Ok(CancellationResult::Requested)
}

/// Cancels a scheduled job or requests cooperative cancellation for a leased
/// job.
pub(crate) async fn cancel_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<CancellationResult, S::Error> {
    let (job_key, encoded, record) = load_job(system, job_id).await?;
    match record.state.clone() {
        JobState::Leased(lease) if lease.expires_at > now => {
            let (transaction, fence_high_water) =
                leased_cancel_transaction(system, job_key, encoded, record.queue.clone(), job_id)
                    .await?;
            let cancellation_key = keys::cancellation_key(system.namespace(), &job_id)?;
            commit_marker(system, transaction, &cancellation_key).await?;
            system.signal_matching_attempt(job_id, fence_high_water, None);
            system.observe(crate::observer::JobEvent::CancellationRequested {
                queue: record.queue,
            });
            Ok(CancellationResult::Requested)
        }
        JobState::Leased(_) => Err(JobSystemError::LeaseLost),
        JobState::Scheduled => {
            inactivate_scheduled(system, record, encoded, ScheduledInactivation::Cancel).await?;
            Ok(CancellationResult::Cancelled)
        }
        JobState::Suspended => cancel_suspended(system, job_id).await,
        JobState::DeadLettered | JobState::Cancelled => Ok(CancellationResult::Cancelled),
    }
}

async fn leased_cancel_transaction<S: JobStore>(
    system: &JobSystem<S>,
    job_key: crate::store::StoreKey,
    encoded: Bytes,
    queue: crate::ids::QueueName,
    job_id: JobId,
) -> JobResult<(crate::store::StoreTransaction, u64), S::Error> {
    let cancellation_key = keys::cancellation_key(system.namespace(), &job_id)?;
    let markers = load_lease_markers(system, &queue, job_id).await?;
    let transaction = checked_transaction(
        system,
        vec![
            Check::Value(job_key, encoded),
            Check::Value(markers.lease_key, markers.lease_value),
            Check::Value(markers.operation_key, markers.operation_value),
        ],
        vec![Mutation::Put(cancellation_key, keys::cancellation_value()?)],
    )?;
    Ok((transaction, markers.fence_high_water))
}

pub(super) async fn inactivate_scheduled<S: JobStore>(
    system: &JobSystem<S>,
    mut record: JobRecordV1,
    encoded: Bytes,
    disposition: ScheduledInactivation,
) -> JobResult<(), S::Error> {
    let (transaction, new_encoded) =
        cancel_scheduled_transaction(system, &mut record, &encoded, disposition).await?;
    commit_record_without_claim(system, transaction, &record.job_id, &encoded, &new_encoded)
        .await?;
    system.observe(disposition.event(record.queue));
    Ok(())
}

async fn cancel_scheduled_transaction<S: JobStore>(
    system: &JobSystem<S>,
    record: &mut JobRecordV1,
    encoded: &Bytes,
    disposition: ScheduledInactivation,
) -> JobResult<(crate::store::StoreTransaction, Bytes), S::Error> {
    let (old_due, fair_key, markers) = load_scheduled_markers(system, record).await?;
    record.state = disposition.state();
    record.revision = next_revision(system, record)?;
    let operation = fresh_operation(system)?;
    let new_encoded = encode_job_record(record)?;
    let mut mutations = cancel_scheduled_mutations(
        system,
        record,
        &old_due,
        &new_encoded,
        operation,
        markers.fence_high_water,
    )?;
    let wake_check =
        wake_mutation(system, &record.queue, Some(&old_due), None, &mut mutations).await?;
    let mut checks = vec![
        Check::Value(
            keys::job_key(system.namespace(), &record.job_id)?,
            encoded.clone(),
        ),
        Check::Value(old_due, markers.due_value),
        Check::Value(fair_key, markers.fair_value),
    ];
    let operation_key = keys::operation_key(system.namespace(), &record.job_id)?;
    checks.push(match markers.operation_value {
        Some(value) => Check::Value(operation_key, value),
        None => Check::Absent(operation_key),
    });
    checks.push(Check::Absent(keys::cancellation_key(
        system.namespace(),
        &record.job_id,
    )?));
    if let Some(check) = wake_check {
        checks.push(check);
    }
    Ok((checked_transaction(system, checks, mutations)?, new_encoded))
}

fn cancel_scheduled_mutations<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    old_due: &crate::store::StoreKey,
    new_encoded: &Bytes,
    operation: OperationId,
    fence_high_water: u64,
) -> JobResult<Vec<Mutation>, S::Error> {
    Ok(vec![
        Mutation::Put(
            keys::job_key(system.namespace(), &record.job_id)?,
            new_encoded.clone(),
        ),
        Mutation::Delete(old_due.clone()),
        Mutation::Delete(keys::fair_key(
            system.namespace(),
            &record.queue,
            &record.job_id,
        )?),
        Mutation::Put(
            keys::operation_key(system.namespace(), &record.job_id)?,
            keys::operation_value(&record.job_id, &operation, fence_high_water)?,
        ),
    ])
}

#[derive(Clone, Copy)]
pub(super) enum ScheduledInactivation {
    Cancel,
    Suspend,
}

impl ScheduledInactivation {
    fn state(self) -> JobState {
        match self {
            Self::Cancel => JobState::Cancelled,
            Self::Suspend => JobState::Suspended,
        }
    }

    fn event(self, queue: crate::QueueName) -> crate::observer::JobEvent {
        match self {
            Self::Cancel => crate::observer::JobEvent::Cancelled { queue },
            Self::Suspend => crate::observer::JobEvent::Suspended { queue },
        }
    }
}

async fn cancel_suspended<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<CancellationResult, S::Error> {
    let mut authority = load_job_operation(system, job_id).await?;
    match authority.record.state {
        JobState::Suspended => {}
        JobState::Scheduled
        | JobState::Leased(_)
        | JobState::DeadLettered
        | JobState::Cancelled => {
            return Err(JobSystemError::LeaseConflict);
        }
    }
    let (old_marker, _, fence) = authority.active_operation()?;
    let old_marker = old_marker.clone();
    authority.record.state = JobState::Cancelled;
    authority.record.revision = next_revision(system, &authority.record)?;
    let next = encode_job_record(&authority.record)?;
    let operation = fresh_operation(system)?;
    let marker = keys::operation_value(&job_id, &operation, fence)?;
    let transaction = checked_transaction(
        system,
        vec![
            Check::Value(authority.job_key.clone(), authority.encoded.clone()),
            Check::Value(authority.operation_key.clone(), old_marker),
        ],
        vec![
            Mutation::Put(authority.job_key, next.clone()),
            Mutation::Put(authority.operation_key, marker),
        ],
    )?;
    commit_record_without_claim(system, transaction, &job_id, &authority.encoded, &next).await?;
    system.observe(crate::observer::JobEvent::Cancelled {
        queue: authority.record.queue,
    });
    Ok(CancellationResult::Cancelled)
}
