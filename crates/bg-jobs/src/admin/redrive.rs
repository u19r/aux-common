use bytes::Bytes;

use super::repository::load_job_operation;
use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    failure::{RedriveExecution, RedriveRequest, RedriveResult},
    ids::{ExecutionId, JobId, OperationId},
    keys,
    model::{JobRecordV1, JobState},
    store::{Check, JobStore, Mutation},
    transition::{
        checked_transaction, commit_record_without_claim, fresh_operation, next_revision,
        wake_mutation,
    },
};

/// Redrives a dead-lettered job with explicit generation and execution identity
/// authority.
pub(crate) async fn redrive_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    request: RedriveRequest,
) -> JobResult<RedriveResult, S::Error> {
    let authority = load_job_operation(system, job_id).await?;
    match &authority.record.state {
        JobState::DeadLettered if authority.record.revision == request.expected_revision => {}
        JobState::Scheduled | JobState::Leased(_) | JobState::Cancelled | JobState::Suspended => {
            return Err(JobSystemError::LeaseConflict);
        }
        JobState::DeadLettered => return Err(JobSystemError::LeaseConflict),
    }
    let (_, operation, fence_high_water) = authority.active_operation()?;
    if operation != request.expected_operation {
        return Err(JobSystemError::LeaseLost);
    }
    system
        .registry()
        .contains(&authority.record.kind, authority.record.schema_version)
        .then_some(())
        .ok_or(JobSystemError::UnregisteredHandler)?;
    let next = prepare_redrive(system, authority.record, &request)?;
    commit_redrive(system, authority.encoded, next, request, fence_high_water).await
}

pub(super) fn prepare_redrive<S: JobStore>(
    system: &JobSystem<S>,
    mut record: JobRecordV1,
    request: &RedriveRequest,
) -> JobResult<JobRecordV1, S::Error> {
    let revision = next_revision(system, &record)?;
    let execution_id = match request.execution {
        RedriveExecution::ReuseExecutionId => record.execution_id,
        RedriveExecution::NewExecutionId => {
            ExecutionId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?
        }
    };
    let generation = record
        .generation
        .checked_add(1)
        .ok_or(JobSystemError::LeaseConflict)?;
    let had_expiry = record.expires_at.is_some();
    record.generation = generation;
    record.execution_id = execution_id;
    record.attempts = None;
    record.checkpoint = None;
    record.scheduled_at = request.scheduled_at;
    if had_expiry {
        record.expires_at = Some(
            request
                .scheduled_at
                .checked_add(record.policy.retry_policy.maximum_age())?,
        );
    }
    record.state = JobState::Scheduled;
    record.revision = revision;
    Ok(record)
}

async fn commit_redrive<S: JobStore>(
    system: &JobSystem<S>,
    encoded: Bytes,
    next: JobRecordV1,
    request: RedriveRequest,
    fence_high_water: u64,
) -> JobResult<RedriveResult, S::Error> {
    let (transaction, new_encoded) =
        redrive_transaction(system, &encoded, &next, &request, fence_high_water).await?;
    let job_id = next.job_id;
    commit_record_without_claim(system, transaction, &job_id, &encoded, &new_encoded).await?;
    let reused_execution = request.execution == RedriveExecution::ReuseExecutionId;
    system.observe(crate::observer::JobEvent::Redriven {
        queue: next.queue,
        reused_execution,
    });
    Ok(RedriveResult {
        job_id,
        generation: next.generation,
        execution_id: next.execution_id,
        reused_execution,
    })
}

async fn redrive_transaction<S: JobStore>(
    system: &JobSystem<S>,
    encoded: &Bytes,
    next: &JobRecordV1,
    request: &RedriveRequest,
    fence_high_water: u64,
) -> JobResult<(crate::store::StoreTransaction, Bytes), S::Error> {
    let job_id = next.job_id;
    let job_key = keys::job_key(system.namespace(), &job_id)?;
    let operation_key = keys::operation_key(system.namespace(), &job_id)?;
    let new_operation = fresh_operation(system)?;
    let new_encoded = encode_job_record(next)?;
    let due_key = keys::due_key(system.namespace(), &next.queue, next.scheduled_at, &job_id)?;
    let dlq_key = keys::dead_letter_key(system.namespace(), &next.queue, &job_id)?;
    let mut mutations =
        redrive_mutations(system, next, &new_encoded, new_operation, fence_high_water)?;
    let wake_check =
        wake_mutation(system, &next.queue, None, Some(&due_key), &mut mutations).await?;
    let mut checks = redrive_checks::<S::Error>(
        job_key,
        encoded,
        operation_key,
        dlq_key,
        request.expected_operation,
        job_id,
        fence_high_water,
    )?;
    if let Some(check) = wake_check {
        checks.push(check);
    }
    Ok((checked_transaction(system, checks, mutations)?, new_encoded))
}

fn redrive_mutations<S: JobStore>(
    system: &JobSystem<S>,
    next: &JobRecordV1,
    new_encoded: &Bytes,
    operation: OperationId,
    fence_high_water: u64,
) -> JobResult<Vec<Mutation>, S::Error> {
    let job_id = next.job_id;
    let job_key = keys::job_key(system.namespace(), &job_id)?;
    let operation_key = keys::operation_key(system.namespace(), &job_id)?;
    let due_key = keys::due_key(system.namespace(), &next.queue, next.scheduled_at, &job_id)?;
    let dlq_key = keys::dead_letter_key(system.namespace(), &next.queue, &job_id)?;
    Ok(vec![
        Mutation::Put(job_key, new_encoded.clone()),
        Mutation::Delete(dlq_key),
        Mutation::Put(due_key, keys::due_value(next.scheduled_at)?),
        Mutation::Put(
            keys::fair_key(system.namespace(), &next.queue, &job_id)?,
            keys::fair_value(&job_id)?,
        ),
        Mutation::Put(
            operation_key,
            keys::operation_value(&job_id, &operation, fence_high_water)?,
        ),
    ])
}

fn redrive_checks<E>(
    job_key: crate::store::StoreKey,
    encoded: &Bytes,
    operation_key: crate::store::StoreKey,
    dlq_key: crate::store::StoreKey,
    operation: OperationId,
    job_id: JobId,
    fence_high_water: u64,
) -> Result<Vec<Check>, JobSystemError<E>> {
    Ok(vec![
        Check::Value(job_key, encoded.clone()),
        Check::Value(
            operation_key,
            keys::operation_value(&job_id, &operation, fence_high_water)?,
        ),
        Check::Value(dlq_key, keys::dead_letter_value(&job_id)?),
    ])
}
