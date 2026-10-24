//! Claim authority preparation and attempt sequencing.

use std::num::NonZeroU64;

use super::transaction::{claimable, next_attempt};
use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::LeaseToken,
    model::{AttemptHistory, JobRecordV1, JobState, Lease},
    store::JobStore,
    time::Timestamp,
};

pub(super) fn prepare_claim_record<S: JobStore>(
    system: &JobSystem<S>,
    mut record: JobRecordV1,
    now: Timestamp,
    fence_high_water: u64,
    deadline: Option<Timestamp>,
) -> JobResult<JobRecordV1, S::Error> {
    if record.scheduled_at > now
        || record.expires_at.is_some_and(|expiry| expiry <= now)
        || record.retention_deadline <= now
        || !claimable(&record, now)
    {
        return Err(JobSystemError::LeaseConflict);
    }

    let (attempts, fence, token, expires_at) =
        claim_authority(system, &record, now, fence_high_water, deadline)?;
    record.generation = record
        .generation
        .checked_add(1)
        .ok_or(JobSystemError::LeaseConflict)?;
    record.attempts = Some(attempts);
    record.state = JobState::Leased(Lease::try_new(*system.owner(), token, fence, expires_at)?);
    record.revision = record
        .revision
        .checked_add(1)
        .ok_or(JobSystemError::LeaseConflict)?;
    Ok(record)
}

fn claim_authority<S: JobStore>(
    system: &JobSystem<S>,
    record: &JobRecordV1,
    now: Timestamp,
    fence_high_water: u64,
    deadline: Option<Timestamp>,
) -> JobResult<(AttemptHistory, NonZeroU64, LeaseToken, Timestamp), S::Error> {
    let registration = system
        .registry()
        .get_ref(&record.kind, record.schema_version)
        .ok_or(JobSystemError::UnregisteredHandler)?;
    if record.has_exhausted_attempts() {
        return Err(JobSystemError::LeaseConflict);
    }

    let attempts = next_attempt(record, now).map_err(|_| JobSystemError::LeaseConflict)?;
    let previous_fence = match &record.state {
        JobState::Leased(lease) => lease.fence.get().max(fence_high_water),
        JobState::Scheduled
        | JobState::DeadLettered
        | JobState::Cancelled
        | JobState::Suspended => fence_high_water,
    };
    let fence = NonZeroU64::new(
        previous_fence
            .checked_add(1)
            .ok_or(JobSystemError::LeaseConflict)?,
    )
    .ok_or(JobSystemError::LeaseConflict)?;
    let token = LeaseToken::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
    let expires_at = now.checked_add(registration.default_timeout())?;
    let expires_at = deadline.map_or(expires_at, |deadline| expires_at.min(deadline));
    if expires_at <= now {
        return Err(JobSystemError::LeaseConflict);
    }
    Ok((attempts, fence, token, expires_at))
}
