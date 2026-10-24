use bytes::Bytes;

use super::repository::load_job_operation;
use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::{JobId, OperationId},
    keys,
    model::{JobRecordV1, JobState},
    store::{Check, JobStore, Mutation, StoreKey, StoreTransaction},
    transition::{checked_transaction, commit_record_without_claim, next_revision, wake_mutation},
};

/// Restores routing for an understood, revision-checked corrupt record.
/// Unknown-version values are rejected before they can be decoded or
/// interpreted. The repair transaction is deliberately scoped to the one job
/// and its operation marker, so an unrelated pending transition cannot be
/// overwritten.
pub(crate) async fn repair_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    expected_revision: u64,
    expected_operation: OperationId,
) -> JobResult<(), S::Error> {
    let authority = load_job_operation(system, job_id).await?;
    let operation_value =
        validate_repair_authority(&authority, job_id, expected_revision, expected_operation)?;
    let super::repository::JobOperation {
        job_key,
        encoded,
        record,
        operation_key,
        operation_value: _,
    } = authority;
    let authority = RepairAuthority {
        job_key,
        encoded,
        operation_key,
        operation_value,
    };
    let (record, new_encoded) = prepare_repair_record(system, record)?;
    let transaction = build_repair_transaction(system, &authority, &record, &new_encoded).await?;
    commit_record_without_claim(
        system,
        transaction,
        &job_id,
        &authority.encoded,
        &new_encoded,
    )
    .await?;
    system.observe(crate::observer::JobEvent::Repaired {
        queue: record.queue,
    });
    Ok(())
}

fn validate_repair_authority<E>(
    authority: &super::repository::JobOperation,
    job_id: JobId,
    expected_revision: u64,
    expected_operation: OperationId,
) -> Result<Bytes, JobSystemError<E>> {
    let operation_value = authority
        .operation_value
        .clone()
        .ok_or(JobSystemError::LeaseLost)?;
    let (operation, _fence_high_water) = keys::decode_active_operation(&operation_value, &job_id)
        .map_err(|_| JobSystemError::PayloadCorrupt)?;
    if operation != expected_operation {
        return Err(JobSystemError::LeaseLost);
    }
    if authority.record.revision != expected_revision {
        return Err(JobSystemError::LeaseConflict);
    }
    match &authority.record.state {
        JobState::Scheduled => Ok(operation_value),
        JobState::Leased(_)
        | JobState::DeadLettered
        | JobState::Cancelled
        | JobState::Suspended => Err(JobSystemError::LeaseConflict),
    }
}

struct RepairAuthority {
    job_key: StoreKey,
    encoded: Bytes,
    operation_key: StoreKey,
    operation_value: Bytes,
}

fn prepare_repair_record<S: JobStore>(
    system: &JobSystem<S>,
    mut record: JobRecordV1,
) -> JobResult<(JobRecordV1, Bytes), S::Error> {
    record.revision = next_revision(system, &record)?;
    let new_encoded = encode_job_record(&record)?;
    Ok((record, new_encoded))
}

async fn build_repair_transaction<S: JobStore>(
    system: &JobSystem<S>,
    authority: &RepairAuthority,
    record: &JobRecordV1,
    new_encoded: &Bytes,
) -> JobResult<StoreTransaction, S::Error> {
    let due_key = keys::due_key(
        system.namespace(),
        &record.queue,
        record.scheduled_at,
        &record.job_id,
    )?;
    let mut mutations = repair_mutations(
        system,
        authority.job_key.clone(),
        record,
        new_encoded,
        &due_key,
    )?;
    let mut checks = vec![
        Check::Value(authority.job_key.clone(), authority.encoded.clone()),
        Check::Value(
            authority.operation_key.clone(),
            authority.operation_value.clone(),
        ),
    ];
    if let Some(wake_check) =
        wake_mutation(system, &record.queue, None, Some(&due_key), &mut mutations).await?
    {
        checks.push(wake_check);
    }
    checked_transaction(system, checks, mutations)
}

fn repair_mutations<S: JobStore>(
    system: &JobSystem<S>,
    job_key: StoreKey,
    record: &JobRecordV1,
    new_encoded: &Bytes,
    due_key: &StoreKey,
) -> JobResult<Vec<Mutation>, S::Error> {
    Ok(vec![
        Mutation::Put(job_key, new_encoded.clone()),
        Mutation::Put(due_key.clone(), keys::due_value(record.scheduled_at)?),
        Mutation::Put(
            keys::fair_key(system.namespace(), &record.queue, &record.job_id)?,
            keys::fair_value(&record.job_id)?,
        ),
    ])
}
