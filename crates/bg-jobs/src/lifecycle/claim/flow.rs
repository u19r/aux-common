//! Claim loading, validation, and lifecycle assembly.

use std::{
    future::poll_fn,
    num::NonZeroU16,
    sync::{Arc, atomic::AtomicI64},
};

use bytes::Bytes;

use super::{
    ClaimRecordInput, ClaimRoute, ClaimedJob, authority::prepare_claim_record,
    transaction::claim_transaction, types::ClaimTransactionInput,
};
use crate::{
    codec::{decode_job_record, encode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::{AttemptId, JobId, OperationId},
    keys,
    lifecycle::{identity::validate_persisted_identity, payload::load_payload_and_cancellation},
    model::{CancellationToken, JobRecordV1, JobState},
    store::{JobStore, StoreKey},
    time::Timestamp,
};

pub(crate) async fn claim<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<ClaimedJob, S::Error> {
    claim_with_capacity(system, job_id, now, NonZeroU16::MIN).await
}

/// Claims through the normal lifecycle transaction while allowing a caller
/// that owns a bounded fair scope to reserve more than one durable slot.  The
/// default public claim remains one slot; batch formation supplies the
/// configured scope capacity explicitly so two compatible siblings can be
/// claimed atomically without a connector-only permit path.
pub(crate) async fn claim_with_capacity<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
    capacity: NonZeroU16,
) -> JobResult<ClaimedJob, S::Error> {
    let job_key = keys::job_key(system.namespace(), &job_id)?;
    let encoded = system
        .store()
        .get(job_key)
        .await
        .map_err(JobSystemError::Store)?
        .ok_or(JobSystemError::NotFound)?;
    let record = decode_job_record(&encoded)?;
    validate_persisted_identity(system, job_id, &record)?;
    let route = load_claim_route(system, &record, job_id, now).await?;
    claim_record_with_capacity(
        system,
        ClaimRecordInput {
            record,
            encoded,
            route,
            now,
            capacity,
            deadline: None,
        },
    )
    .await
}

async fn load_claim_route<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<ClaimRoute, S::Error> {
    let due_key = keys::due_key(
        system.namespace(),
        &record.queue,
        record.scheduled_at,
        &job_id,
    )?;
    if let Some(value) = system
        .store()
        .get(due_key.clone())
        .await
        .map_err(JobSystemError::Store)?
    {
        return Ok(ClaimRoute::Due {
            key: due_key,
            value,
        });
    }

    let lease_key = keys::lease_key(system.namespace(), &record.queue, &job_id)?;
    let value = system
        .store()
        .get(lease_key.clone())
        .await
        .map_err(JobSystemError::Store)?
        .ok_or(JobSystemError::LeaseConflict)?;
    match &record.state {
        JobState::Leased(lease) if lease.expires_at <= now => Ok(ClaimRoute::ExpiredLease {
            key: lease_key,
            value,
        }),
        JobState::Scheduled
        | JobState::Leased(_)
        | JobState::DeadLettered
        | JobState::Cancelled
        | JobState::Suspended => Err(JobSystemError::LeaseConflict),
    }
}

/// Claims a record while reserving one complete durable permit set within the
/// caller's bounded per-scope capacity.  Discovery is advisory; the claim
/// transaction rechecks every selected key as absent alongside the job and
/// route values, so a racing node cannot acquire a partially overlapping set.
pub(crate) async fn claim_record_with_capacity<S: JobStore>(
    system: &JobSystem<S>,
    input: ClaimRecordInput<'_>,
) -> JobResult<ClaimedJob, S::Error> {
    let deadline = input.deadline;
    let ClaimReadState {
        record,
        encoded,
        route,
        now,
        existing_permit_value,
        fence_result,
        permit_result,
    } = read_claim_state(system, input).await?;
    let fence_high_water = fence_result?;
    let record = prepare_claim_record(
        system,
        record,
        now,
        fence_high_water,
        deadline.map(|bound| bound.until),
    )?;
    let new_encoded = encode_job_record(&record)?;
    let attempt_id = AttemptId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
    let operation_id = OperationId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
    let permit_keys = permit_result?.ok_or(JobSystemError::LeaseConflict)?;
    let (fair_key, lease_key) = commit_claim(
        system,
        ClaimTransactionInput {
            record: &record,
            encoded: &encoded,
            route: route.clone(),
            new_encoded: new_encoded.clone(),
            operation_id,
            permit_keys: permit_keys.clone(),
            existing_permit_value,
        },
    )
    .await?;
    let parts = ClaimParts {
        route,
        fair_key,
        lease_key,
        permit_keys,
        attempt_id,
        operation_id,
        execution_deadline: deadline.map(|bound| bound.until),
    };
    finish_claim(system, record, new_encoded, parts, deadline).await
}

struct ClaimReadState<E> {
    record: JobRecordV1,
    encoded: Bytes,
    route: ClaimRoute,
    now: Timestamp,
    existing_permit_value: Option<Bytes>,
    fence_result: JobResult<u64, E>,
    permit_result: JobResult<Option<Vec<StoreKey>>, E>,
}

async fn read_claim_state<S: JobStore>(
    system: &JobSystem<S>,
    input: ClaimRecordInput<'_>,
) -> JobResult<ClaimReadState<S::Error>, S::Error> {
    let ClaimRecordInput {
        record,
        encoded,
        route,
        now,
        capacity,
        deadline: _,
    } = input;
    validate_persisted_identity(system, record.job_id, &record)?;
    validate_claim_route(system, &record, &route)?;
    let reclaiming_expired_lease = route.replaces_permits();
    let existing_permit_value = reclaiming_expired_lease
        .then(|| keys::permit_value_for_record(&record))
        .transpose()?;
    let (fence_result, permit_result) =
        join_claim_reads_with_mode(system, &record, capacity, reclaiming_expired_lease).await;
    Ok(ClaimReadState {
        record,
        encoded,
        route,
        now,
        existing_permit_value,
        fence_result,
        permit_result,
    })
}

struct ClaimParts {
    execution_deadline: Option<Timestamp>,
    route: ClaimRoute,
    fair_key: StoreKey,
    lease_key: StoreKey,
    permit_keys: Vec<StoreKey>,
    attempt_id: AttemptId,
    operation_id: OperationId,
}

impl ClaimParts {
    fn assemble_claim<E>(
        self,
        record: JobRecordV1,
        encoded: Bytes,
        payload: Bytes,
        cancellation: CancellationToken,
    ) -> JobResult<ClaimedJob, E> {
        let fence_high_water = match &record.state {
            JobState::Leased(lease) => lease.fence.get(),
            _ => return Err(JobSystemError::LeaseLost),
        };
        Ok(ClaimedJob {
            execution_deadline: self.execution_deadline,
            record,
            encoded,
            payload,
            due_key: self.route.removes_route().then(|| self.route.key().clone()),
            fair_key: self.fair_key,
            lease_key: self.lease_key,
            permit_keys: self.permit_keys,
            attempt_id: self.attempt_id,
            operation_id: self.operation_id,
            fence_high_water,
            cancellation,
            authority_lost: std::sync::atomic::AtomicBool::new(false),
            poll_work_found: std::sync::atomic::AtomicBool::new(false),
            last_heartbeat: Arc::new(AtomicI64::new(i64::MIN)),
        })
    }
}

async fn commit_claim<S: JobStore>(
    system: &JobSystem<S>,
    input: ClaimTransactionInput<'_>,
) -> JobResult<(StoreKey, StoreKey), S::Error> {
    let expected_old = input.encoded;
    let expected_new = input.new_encoded.clone();
    let (job_key, fair_key, lease_key, transaction) = claim_transaction(system, input)?;
    crate::transition::commit_transition(
        system,
        transaction,
        job_key,
        Some(expected_old),
        Some(&expected_new),
        crate::transition::TransitionConflict::LeaseConflict,
    )
    .await?;
    Ok((fair_key, lease_key))
}

async fn finish_claim<S: JobStore>(
    system: &JobSystem<S>,
    record: JobRecordV1,
    encoded: Bytes,
    parts: ClaimParts,
    deadline: Option<super::ClaimDeadline<'_>>,
) -> JobResult<ClaimedJob, S::Error> {
    let (payload, cancellation_value) = load_payload_and_cancellation(system, &record).await?;
    let cancellation = CancellationToken::new();
    if cancellation_value.is_some() {
        cancellation.cancel();
    }
    let claim = parts.assemble_claim(record, encoded, payload, cancellation)?;
    super::publication::publish_claim(system, &claim, deadline).await?;
    Ok(claim)
}

fn validate_claim_route<S: JobStore>(
    _system: &JobSystem<S>,
    record: &JobRecordV1,
    route: &ClaimRoute,
) -> JobResult<(), S::Error> {
    match route {
        ClaimRoute::Due { value, .. } => {
            if keys::decode_timestamp_value(value, crate::codec::ValueTag::Due)?
                != record.scheduled_at
            {
                return Err(JobSystemError::LeaseConflict);
            }
        }
        ClaimRoute::ExpiredLease { value, .. } => {
            keys::validate_job_marker(value, crate::codec::ValueTag::Lease, &record.job_id)?;
        }
    }
    Ok(())
}

pub(super) async fn load_fence_high_water<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<u64, S::Error> {
    let operation_key = keys::operation_key(system.namespace(), &job_id)?;
    let Some(encoded) = system
        .store()
        .get(operation_key)
        .await
        .map_err(JobSystemError::Store)?
    else {
        return Ok(0);
    };
    Ok(keys::decode_operation_fence_high_water(&encoded, &job_id)?)
}

#[cfg(test)]
pub(super) async fn join_claim_reads<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    capacity: NonZeroU16,
) -> (
    JobResult<u64, S::Error>,
    JobResult<Option<Vec<StoreKey>>, S::Error>,
) {
    join_claim_reads_with_mode(system, record, capacity, false).await
}

async fn join_claim_reads_with_mode<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    capacity: NonZeroU16,
    reclaiming_expired_lease: bool,
) -> (
    JobResult<u64, S::Error>,
    JobResult<Option<Vec<StoreKey>>, S::Error>,
) {
    let fence_future = load_fence_high_water(system, record.job_id);
    let permit_future = find_claim_permit_keys(system, record, capacity, reclaiming_expired_lease);
    let mut fence = std::pin::pin!(fence_future);
    let mut permits = std::pin::pin!(permit_future);
    let mut fence_result = None;
    let mut permit_result = None;
    poll_fn(|context| {
        if fence_result.is_none()
            && let std::task::Poll::Ready(result) = fence.as_mut().poll(context)
        {
            fence_result = Some(result);
        }
        if permit_result.is_none()
            && let std::task::Poll::Ready(result) = permits.as_mut().poll(context)
        {
            permit_result = Some(result);
        }
        if fence_result.is_some() && permit_result.is_some() {
            match (fence_result.take(), permit_result.take()) {
                (Some(fence), Some(permits)) => std::task::Poll::Ready((fence, permits)),
                _ => std::task::Poll::Pending,
            }
        } else {
            std::task::Poll::Pending
        }
    })
    .await
}

async fn find_claim_permit_keys<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    capacity: NonZeroU16,
    reclaiming_expired_lease: bool,
) -> JobResult<Option<Vec<StoreKey>>, S::Error> {
    if reclaiming_expired_lease {
        return crate::fairness::find_reclaimable_permit_keys(system, record).await;
    }
    crate::fairness::find_available_permit_keys(system, record, capacity).await
}
