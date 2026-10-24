//! Lease authority and lifecycle transaction builders.

use std::time::Duration;

use bytes::Bytes;
use sha2::{Digest, Sha256};

use super::{checked_transaction, wake_mutation};
use crate::{
    codec::decode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::{ExecutionId, OperationId},
    keys,
    lifecycle::ClaimedJob,
    model::{JobRecordV1, JobState},
    policy::OutcomeCode,
    store::{Check, JobStore, Mutation, StoreKey, StoreTransaction},
    time::Timestamp,
};

pub(crate) fn current_lease<S: JobStore>(
    _system: &JobSystem<S>,
    claim: &ClaimedJob,
    now: Timestamp,
) -> JobResult<crate::model::Lease, S::Error> {
    if claim.authority_lost() {
        return Err(JobSystemError::LeaseLost);
    }
    claim
        .lease_at(now)
        .cloned()
        .ok_or(JobSystemError::LeaseLost)
}

pub(crate) fn next_revision<S: JobStore>(
    _system: &JobSystem<S>,
    record: &JobRecordV1,
) -> JobResult<u64, S::Error> {
    record
        .revision
        .checked_add(1)
        .ok_or(JobSystemError::LeaseConflict)
}

pub(crate) fn fresh_operation<S: JobStore>(
    _system: &JobSystem<S>,
) -> JobResult<OperationId, S::Error> {
    OperationId::generate().map_err(|_| JobSystemError::EntropyUnavailable)
}

pub(crate) fn code(value: &'static str) -> Result<OutcomeCode, crate::error::ValidationError> {
    OutcomeCode::try_new(value)
}

pub(crate) fn jitter_duration(
    execution: &ExecutionId,
    attempt: std::num::NonZeroU16,
    now: Timestamp,
    cap: Duration,
) -> Duration {
    let mut digest = Sha256::new();
    digest.update(execution.as_bytes());
    digest.update(attempt.get().to_be_bytes());
    digest.update(now.as_millis().to_be_bytes());
    let bytes = digest.finalize();
    let cap_millis = cap.as_millis().max(1);
    let sample = u64::from_be_bytes(bytes[..8].try_into().unwrap_or([0; 8]));
    Duration::from_millis(sample % u64::try_from(cap_millis).unwrap_or(u64::MAX))
}

pub(crate) fn lease_record_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    record: &JobRecordV1,
    encoded: &Bytes,
    operation: OperationId,
) -> JobResult<StoreTransaction, S::Error> {
    let mut checks = authority_checks(system, claim)?;
    checks.push(Check::Absent(keys::cancellation_key(
        system.namespace(),
        &record.job_id,
    )?));
    let permit_value = keys::permit_value_for_record(record)?;
    let mut mutations = vec![
        Mutation::Put(
            keys::job_key(system.namespace(), &record.job_id)?,
            encoded.clone(),
        ),
        Mutation::Put(
            keys::operation_key(system.namespace(), &record.job_id)?,
            keys::operation_value(&record.job_id, &operation, lease_fence(record)?)?,
        ),
    ];
    for permit_key in claim.permit_keys() {
        mutations.push(Mutation::Put(permit_key.clone(), permit_value.clone()));
    }
    checked_transaction(system, checks, mutations)
}

pub(crate) async fn scheduled_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    record: &JobRecordV1,
    encoded: &Bytes,
    operation: OperationId,
    due_key: StoreKey,
) -> JobResult<StoreTransaction, S::Error> {
    let mut mutations = scheduled_mutations(system, claim, record, encoded, operation, &due_key)?;
    let wake_check = wake_mutation(
        system,
        &record.queue,
        claim.due_key(),
        Some(&due_key),
        &mut mutations,
    )
    .await?;
    let mut checks = authority_checks(system, claim)?;
    checks.push(Check::Absent(keys::cancellation_key(
        system.namespace(),
        &record.job_id,
    )?));
    if let Some(check) = wake_check {
        checks.push(check);
    }
    checked_transaction(system, checks, mutations)
}

fn scheduled_mutations<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    record: &JobRecordV1,
    encoded: &Bytes,
    operation: OperationId,
    due_key: &StoreKey,
) -> JobResult<Vec<Mutation>, S::Error> {
    let mut mutations = vec![
        Mutation::Put(
            keys::job_key(system.namespace(), &record.job_id)?,
            encoded.clone(),
        ),
        Mutation::Delete(claim.lease_key().clone()),
        Mutation::Put(due_key.clone(), keys::due_value(record.scheduled_at)?),
        Mutation::Put(
            keys::fair_key(system.namespace(), &record.queue, &record.job_id)?,
            keys::fair_value(&record.job_id)?,
        ),
        Mutation::Put(
            keys::operation_key(system.namespace(), &record.job_id)?,
            keys::operation_value(&record.job_id, &operation, claim.fence_high_water())?,
        ),
    ];
    for permit_key in claim.permit_keys() {
        mutations.push(Mutation::Delete(permit_key.clone()));
    }
    Ok(mutations)
}

pub(crate) enum TerminalTransition {
    DeadLetter(StoreKey),
    WorkerCancellation,
    CancellationAcknowledgement,
}

pub(crate) async fn terminal_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    record: &JobRecordV1,
    encoded: &Bytes,
    operation: OperationId,
    transition: TerminalTransition,
) -> JobResult<StoreTransaction, S::Error> {
    let mut mutations = terminal_mutations(system, claim, record, encoded, operation, &transition)?;
    if let Some(due_key) = claim.due_key() {
        mutations.push(Mutation::Delete(due_key.clone()));
    }
    let wake_check =
        wake_mutation(system, &record.queue, claim.due_key(), None, &mut mutations).await?;
    let mut checks = authority_checks(system, claim)?;
    if let Some(check) = wake_check {
        checks.push(check);
    }
    let cancellation_key = keys::cancellation_key(system.namespace(), &record.job_id)?;
    checks.push(match transition {
        TerminalTransition::CancellationAcknowledgement => {
            Check::Value(cancellation_key, keys::cancellation_value()?)
        }
        TerminalTransition::DeadLetter(_) | TerminalTransition::WorkerCancellation => {
            Check::Absent(cancellation_key)
        }
    });
    checked_transaction(system, checks, mutations)
}

fn terminal_mutations<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    record: &JobRecordV1,
    encoded: &Bytes,
    operation: OperationId,
    transition: &TerminalTransition,
) -> JobResult<Vec<Mutation>, S::Error> {
    let mut mutations = vec![
        Mutation::Put(
            keys::job_key(system.namespace(), &record.job_id)?,
            encoded.clone(),
        ),
        Mutation::Delete(claim.lease_key().clone()),
        Mutation::Delete(claim.fair_key().clone()),
        Mutation::Put(
            keys::operation_key(system.namespace(), &record.job_id)?,
            keys::operation_value(&record.job_id, &operation, claim.fence_high_water())?,
        ),
    ];
    if let TerminalTransition::CancellationAcknowledgement = transition {
        mutations.push(Mutation::Delete(keys::cancellation_key(
            system.namespace(),
            &record.job_id,
        )?));
    }
    for permit_key in claim.permit_keys() {
        mutations.push(Mutation::Delete(permit_key.clone()));
    }
    if let TerminalTransition::DeadLetter(dlq_key) = transition {
        mutations.push(Mutation::Put(
            dlq_key.clone(),
            keys::dead_letter_value(&record.job_id)?,
        ));
    }
    Ok(mutations)
}

pub(crate) fn authority_checks<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
) -> JobResult<Vec<Check>, S::Error> {
    let mut checks = vec![
        Check::Value(
            keys::job_key(system.namespace(), &claim.record().job_id)?,
            claim.encoded().clone(),
        ),
        Check::Value(
            claim.lease_key().clone(),
            keys::lease_value(&claim.record().job_id)?,
        ),
        Check::Value(
            keys::operation_key(system.namespace(), &claim.record().job_id)?,
            keys::operation_value(
                &claim.record().job_id,
                &claim.operation_id(),
                claim.fence_high_water(),
            )?,
        ),
    ];
    // The in-memory claim may already contain the renewed lease while its
    // encoded authority still names the previous owner.  Decode that exact
    // persisted value for the permit check; otherwise a stale renewal could
    // overwrite or release a newer owner's durable slot.
    let persisted = decode_job_record(claim.encoded())?;
    let permit_value = keys::permit_value_for_record(&persisted)?;
    checks.extend(
        claim
            .permit_keys()
            .iter()
            .cloned()
            .map(|key| Check::Value(key, permit_value.clone())),
    );
    Ok(checks)
}

fn lease_fence<E>(record: &JobRecordV1) -> Result<u64, JobSystemError<E>> {
    match &record.state {
        JobState::Leased(lease) => Ok(lease.fence.get()),
        _ => Err(JobSystemError::LeaseLost),
    }
}
