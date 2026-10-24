//! Atomic claim checks and mutations.

use bytes::Bytes;

use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::OperationId,
    keys,
    lifecycle::claim::{ClaimRoute, types::ClaimTransactionInput},
    model::{AttemptHistory, JobRecordV1, JobState},
    store::{Check, JobStore, Mutation, StoreTransaction},
    time::Timestamp,
};

pub(super) fn claim_transaction<S: JobStore>(
    system: &JobSystem<S>,
    input: ClaimTransactionInput<'_>,
) -> JobResult<
    (
        crate::store::StoreKey,
        crate::store::StoreKey,
        crate::store::StoreKey,
        StoreTransaction,
    ),
    S::Error,
> {
    let ClaimTransactionInput {
        record,
        encoded,
        route,
        new_encoded,
        operation_id,
        permit_keys,
        existing_permit_value,
    } = input;
    let (job_key, fair_key, lease_key, mutations) = claim_mutations(
        system,
        record,
        &route,
        new_encoded,
        operation_id,
        &permit_keys,
    )?;
    let mut checks = claim_checks(
        job_key.clone(),
        encoded.clone(),
        route.key().clone(),
        route.value().clone(),
        &permit_keys,
        existing_permit_value.as_ref(),
    );
    // A committed cooperative cancellation supersedes retry/reclaim
    // authority.  Keep this guard in the claim transaction so an expired
    // lease cannot be handed to a new handler before the cancellation is
    // acknowledged.
    checks.push(Check::Absent(keys::cancellation_key(
        system.namespace(),
        &record.job_id,
    )?));
    let transaction = crate::transition::checked_transaction(system, checks, mutations)?;
    Ok((job_key, fair_key, lease_key, transaction))
}

fn claim_checks(
    job_key: crate::store::StoreKey,
    encoded: Bytes,
    route_key: crate::store::StoreKey,
    route_value: Bytes,
    permit_keys: &[crate::store::StoreKey],
    existing_permit_value: Option<&Bytes>,
) -> Vec<Check> {
    let mut checks = vec![
        Check::Value(job_key.clone(), encoded.clone()),
        Check::Value(route_key, route_value),
    ];
    checks.extend(
        permit_keys
            .iter()
            .cloned()
            .map(|key| match existing_permit_value {
                Some(value) => Check::Value(key, value.clone()),
                None => Check::Absent(key),
            }),
    );
    checks
}

fn claim_mutations<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    route: &ClaimRoute,
    new_encoded: Bytes,
    operation_id: OperationId,
    permit_keys: &[crate::store::StoreKey],
) -> JobResult<
    (
        crate::store::StoreKey,
        crate::store::StoreKey,
        crate::store::StoreKey,
        Vec<Mutation>,
    ),
    S::Error,
> {
    let job_key = keys::job_key(system.namespace(), &record.job_id)?;
    let fair_key = keys::fair_key(system.namespace(), &record.queue, &record.job_id)?;
    let lease_key = keys::lease_key(system.namespace(), &record.queue, &record.job_id)?;
    let fence_high_water = match &record.state {
        JobState::Leased(lease) => lease.fence.get(),
        _ => return Err(JobSystemError::LeaseLost),
    };
    let mut mutations = vec![
        Mutation::Put(job_key.clone(), new_encoded),
        Mutation::Delete(route.key().clone()),
        Mutation::Delete(fair_key.clone()),
        Mutation::Put(lease_key.clone(), keys::lease_value(&record.job_id)?),
        Mutation::Put(
            keys::operation_key(system.namespace(), &record.job_id)?,
            keys::operation_value(&record.job_id, &operation_id, fence_high_water)?,
        ),
    ];
    let permit_value = keys::permit_value_for_record(record)?;
    for permit_key in permit_keys {
        mutations.push(Mutation::Put(permit_key.clone(), permit_value.clone()));
    }
    if !route.removes_route() {
        mutations.remove(1);
    }
    Ok((job_key, fair_key, lease_key, mutations))
}

pub(super) fn claimable(record: &JobRecordV1, now: Timestamp) -> bool {
    match &record.state {
        JobState::Scheduled => true,
        JobState::Leased(lease) => lease.expires_at <= now,
        JobState::DeadLettered | JobState::Cancelled | JobState::Suspended => false,
    }
}

pub(super) fn next_attempt(record: &JobRecordV1, now: Timestamp) -> Result<AttemptHistory, ()> {
    let history = match &record.attempts {
        None => AttemptHistory {
            attempts: std::num::NonZeroU32::MIN,
            first_attempt_at: now,
            last_attempt_at: now,
            last_outcome: None,
        },
        Some(history) => AttemptHistory {
            attempts: history
                .attempts
                .get()
                .checked_add(1)
                .and_then(std::num::NonZeroU32::new)
                .ok_or(())?,
            first_attempt_at: history.first_attempt_at,
            last_attempt_at: now,
            last_outcome: history.last_outcome.clone(),
        },
    };
    Ok(history)
}
