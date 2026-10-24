use std::sync::atomic::Ordering;

use bytes::Bytes;

use super::constants::HEARTBEAT_MIN_INTERVAL;
use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    failure::{CheckpointResult, RenewalResult},
    ids::OperationId,
    lifecycle::ClaimedJob,
    model::{JobState, Lease},
    store::{JobStore, StoreTransaction},
    time::Timestamp,
    transition::{
        commit_record, current_lease, fresh_operation, lease_record_transaction, next_revision,
    },
};

/// Extends a lease while preserving its owner, token, generation, and fence.
fn renewal_lease<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    now: Timestamp,
) -> JobResult<Lease, S::Error> {
    current_lease(system, claim, now).inspect_err(|_| signal_renewal_lost(system, claim))
}

pub(crate) async fn renew<S: JobStore>(
    system: &JobSystem<S>,
    claim: &mut ClaimedJob,
    now: Timestamp,
) -> JobResult<RenewalResult, S::Error> {
    let lease = renewal_lease(system, claim, now)?;
    if heartbeat_is_coalesced(system, claim, now) {
        return Ok(RenewalResult::Coalesced {
            expires_at: lease.expires_at,
        });
    }
    let expires_at = renewal_expiry(system, claim, lease.expires_at, now)?;
    let previous = prepare_renewal_record(system, claim, lease, expires_at)?;
    let prepared = build_renewal_transaction(system, claim).inspect_err(|_error| {
        previous.clone().restore(claim);
    })?;
    let RenewalTransaction {
        operation_id,
        encoded,
        transaction,
    } = prepared;
    match commit_record(system, transaction, claim, &encoded).await {
        Ok(()) => Ok(complete_renewal(
            system,
            claim,
            now,
            expires_at,
            operation_id,
            encoded,
        )),
        Err(error) => {
            previous.restore(claim);
            signal_renewal_lost(system, claim);
            Err(error)
        }
    }
}

fn complete_renewal<S: JobStore>(
    system: &JobSystem<S>,
    claim: &mut ClaimedJob,
    now: Timestamp,
    expires_at: Timestamp,
    operation_id: OperationId,
    encoded: Bytes,
) -> RenewalResult {
    claim.replace_encoded_authority(encoded, operation_id);
    claim
        .last_heartbeat()
        .store(now.as_millis(), Ordering::Release);
    system.observe(crate::observer::JobEvent::Heartbeat {
        queue: claim.record().queue.clone(),
        coalesced: false,
    });
    RenewalResult::Renewed { expires_at }
}

fn signal_renewal_lost<S: JobStore>(system: &JobSystem<S>, claim: &ClaimedJob) {
    claim.lose_authority();
    system.observe(crate::observer::JobEvent::RenewalLost {
        queue: claim.record().queue.clone(),
    });
}

fn renewal_expiry<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    lease_expiry: Timestamp,
    now: Timestamp,
) -> JobResult<Timestamp, S::Error> {
    let registration = system
        .registry()
        .get_ref(&claim.record().kind, claim.record().schema_version)
        .ok_or(JobSystemError::UnregisteredHandler)?;
    let expires_at = now
        .checked_add(registration.default_timeout())?
        .max(lease_expiry);
    Ok(claim
        .execution_deadline
        .map_or(expires_at, |deadline| expires_at.min(deadline)))
}

#[derive(Clone)]
struct RenewalState {
    previous_state: JobState,
    previous_revision: u64,
}

impl RenewalState {
    fn replace(claim: &mut ClaimedJob, state: JobState) -> Self {
        let previous_state = std::mem::replace(&mut claim.record_mut().state, state);
        let previous_revision = claim.record().revision;
        Self {
            previous_state,
            previous_revision,
        }
    }

    fn restore(self, claim: &mut ClaimedJob) {
        claim.record_mut().state = self.previous_state;
        claim.record_mut().revision = self.previous_revision;
    }
}

fn prepare_renewal_record<S: JobStore>(
    system: &JobSystem<S>,
    claim: &mut ClaimedJob,
    lease: Lease,
    expires_at: Timestamp,
) -> JobResult<RenewalState, S::Error> {
    let next_state = JobState::Leased(Lease::try_new(
        lease.owner,
        lease.token,
        lease.fence,
        expires_at,
    )?);
    let previous = RenewalState::replace(claim, next_state);
    let revision = match next_revision(system, claim.record()) {
        Ok(revision) => revision,
        Err(error) => {
            previous.restore(claim);
            return Err(error);
        }
    };
    claim.record_mut().revision = revision;
    Ok(previous)
}

struct RenewalTransaction {
    operation_id: crate::ids::OperationId,
    encoded: Bytes,
    transaction: StoreTransaction,
}

fn build_renewal_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
) -> JobResult<RenewalTransaction, S::Error> {
    let operation_id = fresh_operation(system)?;
    let encoded = encode_job_record(claim.record())?;
    let transaction =
        lease_record_transaction(system, claim, claim.record(), &encoded, operation_id)?;
    Ok(RenewalTransaction {
        operation_id,
        encoded,
        transaction,
    })
}

fn heartbeat_is_coalesced<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
    now: Timestamp,
) -> bool {
    let last = claim.last_heartbeat().load(Ordering::Acquire);
    let minimum = i64::try_from(HEARTBEAT_MIN_INTERVAL.as_millis()).unwrap_or(i64::MAX);
    let coalesced = last != i64::MIN
        && now
            .as_millis()
            .checked_sub(last)
            .is_some_and(|elapsed| elapsed < minimum);
    if coalesced {
        system.observe(crate::observer::JobEvent::Heartbeat {
            queue: claim.record().queue.clone(),
            coalesced: true,
        });
    }
    coalesced
}

/// Conditionally stores an opaque checkpoint no larger than the portable limit.
pub(crate) async fn checkpoint<S: JobStore>(
    system: &JobSystem<S>,
    claim: &mut ClaimedJob,
    checkpoint: Bytes,
    now: Timestamp,
) -> JobResult<CheckpointResult, S::Error> {
    if checkpoint.len() > crate::model::MAX_CHECKPOINT_BYTES {
        return Err(JobSystemError::Validation(
            crate::error::ValidationError::TooLong {
                field: "checkpoint",
                maximum: crate::model::MAX_CHECKPOINT_BYTES,
                actual: checkpoint.len(),
            },
        ));
    }
    if let Err(error) = current_lease(system, claim, now) {
        claim.lose_authority();
        return Err(error);
    }
    let checkpoint_bytes = checkpoint.len() as u32;
    let previous = prepare_checkpoint_record(system, claim, checkpoint)?;
    let prepared = match build_checkpoint_transaction(system, claim) {
        Ok(prepared) => prepared,
        Err(error) => {
            previous.restore(claim);
            return Err(error);
        }
    };
    commit_checkpoint(system, claim, previous, prepared).await?;
    system.observe(crate::observer::JobEvent::Checkpoint {
        queue: claim.record().queue.clone(),
        bytes: checkpoint_bytes,
    });
    Ok(CheckpointResult {
        bytes: checkpoint_bytes,
    })
}

async fn commit_checkpoint<S: JobStore>(
    system: &JobSystem<S>,
    claim: &mut ClaimedJob,
    previous: CheckpointState,
    prepared: CheckpointTransaction,
) -> JobResult<(), S::Error> {
    let CheckpointTransaction {
        operation_id,
        encoded,
        transaction,
    } = prepared;
    if let Err(error) = commit_record(system, transaction, claim, &encoded).await {
        previous.restore(claim);
        claim.lose_authority();
        return Err(error);
    }
    claim.replace_encoded_authority(encoded, operation_id);
    Ok(())
}

struct CheckpointState {
    previous_checkpoint: Option<Bytes>,
    previous_revision: u64,
}

impl CheckpointState {
    fn restore(self, claim: &mut ClaimedJob) {
        claim.record_mut().checkpoint = self.previous_checkpoint;
        claim.record_mut().revision = self.previous_revision;
    }
}

fn prepare_checkpoint_record<S: JobStore>(
    system: &JobSystem<S>,
    claim: &mut ClaimedJob,
    checkpoint: Bytes,
) -> JobResult<CheckpointState, S::Error> {
    let previous_checkpoint = claim.record_mut().checkpoint.take();
    let previous_revision = claim.record().revision;
    claim.record_mut().checkpoint = Some(checkpoint);
    let revision = match next_revision(system, claim.record()) {
        Ok(revision) => revision,
        Err(error) => {
            CheckpointState {
                previous_checkpoint,
                previous_revision,
            }
            .restore(claim);
            return Err(error);
        }
    };
    claim.record_mut().revision = revision;
    Ok(CheckpointState {
        previous_checkpoint,
        previous_revision,
    })
}

struct CheckpointTransaction {
    operation_id: crate::ids::OperationId,
    encoded: Bytes,
    transaction: StoreTransaction,
}

fn build_checkpoint_transaction<S: JobStore>(
    system: &JobSystem<S>,
    claim: &ClaimedJob,
) -> JobResult<CheckpointTransaction, S::Error> {
    let operation_id = fresh_operation(system)?;
    let encoded = encode_job_record(claim.record())?;
    let transaction =
        lease_record_transaction(system, claim, claim.record(), &encoded, operation_id)?;
    Ok(CheckpointTransaction {
        operation_id,
        encoded,
        transaction,
    })
}
