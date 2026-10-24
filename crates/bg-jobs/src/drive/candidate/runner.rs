use bytes::Bytes;

use super::{
    checkpoint::ClaimCheckpoint,
    handler::{HandlerContext, HandlerExecution, HandlerInvocation, execute_handler},
};
use crate::{
    budget::{DriveReport, DriveRequest, DriveStopReason},
    drive::{claim_deadline_reached, scheduler::DriveClock},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    lifecycle::{ClaimRecordInput, ClaimRoute, ClaimedJob, claim_record_with_capacity},
    model::{JobExecution, JobRecordV1, JobState},
    store::JobStore,
    time::{MonotonicDeadline, Timestamp},
};

#[derive(Clone)]
pub(in crate::drive) struct Candidate {
    pub(in crate::drive) record: JobRecordV1,
    pub(in crate::drive) encoded: Bytes,
    pub(in crate::drive) key: crate::store::StoreKey,
    pub(in crate::drive) value: Bytes,
    pub(in crate::drive) when: Timestamp,
    pub(in crate::drive) route_is_due: bool,
}

pub(in crate::drive) enum CandidateResult {
    Completed(crate::budget::CompletionDetails),
    Continued { not_before: Timestamp },
    Retried { not_before: Timestamp },
    DeadLettered,
    Cancelled,
    Unregistered,
    LeaseConflict,
    Capacity,
    Deadline,
}

pub(in crate::drive) fn apply_candidate_result(
    report: &mut DriveReport,
    result: CandidateResult,
    max_completion_details: u32,
) -> bool {
    match result {
        CandidateResult::Completed(completion) => {
            report.counts.claimed += 1;
            report.counts.succeeded += 1;
            record_completion(report, completion, max_completion_details);
        }
        CandidateResult::Continued { .. } => {
            report.counts.claimed += 1;
            report.counts.continued += 1;
        }
        CandidateResult::Retried { .. } => {
            report.counts.claimed += 1;
            report.counts.retried += 1;
        }
        CandidateResult::DeadLettered => {
            report.counts.claimed += 1;
            report.counts.dead_lettered += 1;
        }
        CandidateResult::Cancelled => {
            report.counts.claimed += 1;
            report.counts.cancelled += 1;
        }
        CandidateResult::Unregistered => {}
        CandidateResult::LeaseConflict => report.counts.lease_conflicts += 1,
        CandidateResult::Capacity => {
            report.counts.capacity_deferrals += 1;
            report.stop_reason = DriveStopReason::Capacity;
            return true;
        }
        CandidateResult::Deadline => {
            report.stop_reason = DriveStopReason::Deadline;
            return true;
        }
    }
    false
}

pub(in crate::drive) async fn process_candidate<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    candidate: Candidate,
    clock: DriveClock<impl Fn() -> MonotonicDeadline + Send + Sync>,
) -> JobResult<CandidateResult, S::Error> {
    let now = clock.wall_now()?;
    if let Some(result) = precheck_candidate(system, request, &candidate, now).await? {
        return Ok(result);
    }
    let Some(registration) = find_registration(system, &candidate) else {
        return Ok(CandidateResult::Unregistered);
    };
    let current = clock.now();
    if claim_deadline_reached(request, current)
        || request.finish_by().remaining_until(current).is_zero()
    {
        return Ok(CandidateResult::Deadline);
    }
    let wall_now = || clock.wall_now();
    let deadline = match registration.handler().claim_lease_policy() {
        crate::ClaimLeasePolicy::RegisteredTimeout => None,
        crate::ClaimLeasePolicy::DriveBoundedNative => Some(crate::lifecycle::ClaimDeadline {
            until: clock.wall_at(request.finish_by())?,
            wall_now: &wall_now,
        }),
    };
    let due_at = candidate.when.max(candidate.record.created_at);
    match claim_candidate(
        system,
        candidate,
        clock.wall_now()?,
        request.max_concurrency(),
        deadline,
    )
    .await?
    {
        Ok(claimed) => {
            let _observation = super::observation::AttemptObservation::start(
                system,
                &claimed,
                clock.clone(),
                due_at,
            );
            let _attempt = system.register_execution(&claimed).await?;
            execute_claim(
                system,
                claimed,
                ClaimExecution {
                    registration,
                    finish_by: request.finish_by(),
                    clock,
                },
            )
            .await
        }
        Err(ClaimFailure::DeadLettered) => Ok(CandidateResult::DeadLettered),
        Err(ClaimFailure::LeaseConflict) => Ok(CandidateResult::LeaseConflict),
    }
}

fn find_registration<'a, S: JobStore>(
    system: &'a JobSystem<S>,
    candidate: &Candidate,
) -> Option<&'a crate::registry::HandlerRegistration> {
    let registration = system
        .registry()
        .get_ref(&candidate.record.kind, candidate.record.schema_version);
    if registration.is_none() {
        system.observe_error(crate::observer::SafeJobErrorEvent {
            kind: crate::observer::SafeJobErrorKind::UnregisteredHandler,
            queue: Some(candidate.record.queue.clone()),
            effect_mode: None,
        });
    }
    registration
}

enum ClaimFailure {
    DeadLettered,
    LeaseConflict,
}

async fn claim_candidate<S: JobStore>(
    system: &JobSystem<S>,
    candidate: Candidate,
    now: Timestamp,
    capacity: std::num::NonZeroU16,
    deadline: Option<crate::lifecycle::ClaimDeadline<'_>>,
) -> JobResult<Result<ClaimedJob, ClaimFailure>, S::Error> {
    let Candidate {
        record,
        encoded,
        key,
        value,
        route_is_due,
        ..
    } = candidate;
    let job_id = record.job_id;
    let route = if route_is_due {
        ClaimRoute::Due { key, value }
    } else {
        ClaimRoute::ExpiredLease { key, value }
    };
    match claim_record_with_capacity(
        system,
        ClaimRecordInput {
            record,
            encoded,
            route,
            now,
            capacity,
            deadline,
        },
    )
    .await
    {
        Ok(claimed) => Ok(Ok(claimed)),
        Err(JobSystemError::LeaseConflict) => Ok(Err(ClaimFailure::LeaseConflict)),
        Err(JobSystemError::PayloadCorrupt) => {
            crate::failure::dead_letter_by_id(system, job_id, now).await?;
            Ok(Err(ClaimFailure::DeadLettered))
        }
        Err(error) => Err(error),
    }
}

async fn precheck_candidate<S: JobStore>(
    system: &JobSystem<S>,
    request: &DriveRequest,
    candidate: &Candidate,
    now: Timestamp,
) -> JobResult<Option<CandidateResult>, S::Error> {
    let expired = candidate
        .record
        .expires_at
        .is_some_and(|expiry| expiry <= now)
        || candidate.record.retention_deadline <= now;
    let can_expire = match &candidate.record.state {
        JobState::Scheduled => expired,
        JobState::Leased(lease) if lease.expires_at <= now => {
            expired
                || candidate.record.has_exhausted_attempts()
                || system
                    .store()
                    .get(crate::keys::cancellation_key(
                        system.namespace(),
                        &candidate.record.job_id,
                    )?)
                    .await
                    .map_err(JobSystemError::Store)?
                    .is_some()
        }
        JobState::Leased(_)
        | JobState::DeadLettered
        | JobState::Cancelled
        | JobState::Suspended => false,
    };
    if can_expire {
        match system.expire_job(candidate.record.job_id, now).await? {
            crate::failure::ExpiryResult::Cancelled => return Ok(Some(CandidateResult::Cancelled)),
            crate::failure::ExpiryResult::DeadLettered => {
                return Ok(Some(CandidateResult::DeadLettered));
            }
            crate::failure::ExpiryResult::LeaseExpired
            | crate::failure::ExpiryResult::Unchanged => {}
        }
    }
    if candidate.record.payload.total_length as usize > request.max_payload_bytes_in_flight().get()
    {
        system.observe(crate::observer::JobEvent::CapacityLimited {
            resource: crate::observer::CapacityResource::PayloadBytes,
        });
        return Ok(Some(CandidateResult::Capacity));
    }
    Ok(None)
}

struct ClaimExecution<'a, C> {
    registration: &'a crate::registry::HandlerRegistration,
    finish_by: MonotonicDeadline,
    clock: DriveClock<C>,
}

async fn execute_claim<S: JobStore>(
    system: &JobSystem<S>,
    mut claimed: ClaimedJob,
    execution: ClaimExecution<'_, impl Fn() -> MonotonicDeadline + Send + Sync>,
) -> JobResult<CandidateResult, S::Error> {
    let ClaimExecution {
        registration,
        finish_by,
        clock,
    } = execution;
    let now = clock.wall_now()?;
    let lease = crate::transition::current_lease(system, &claimed, now)?;
    let finish_by = finish_by.min(clock.deadline_at(lease.expires_at)?);
    observe_claimed(system, &claimed);
    if finish_by.is_at_or_before(clock.now()) {
        return apply_outcome(system, claimed, deadline_outcome(now)?, now).await;
    }
    let payload = claimed.payload().clone();
    let mut checkpoint = ClaimCheckpoint {
        system,
        claim: &mut claimed,
        finish_by,
        clock: clock.clone(),
    };
    let outcome = execute_handler(HandlerInvocation {
        system,
        finish_by,
        clock: clock.clone(),
        handler: registration.handler().as_ref(),
        context: HandlerContext::Checkpointed(JobExecution::new(&mut checkpoint)),
        payload: &payload,
    })
    .await?;
    let outcome = match outcome {
        HandlerExecution::Outcome(outcome) => outcome,
        HandlerExecution::Deadline => return Ok(CandidateResult::Deadline),
    };
    apply_outcome(system, claimed, outcome, clock.wall_now()?).await
}

fn observe_claimed<S: JobStore>(system: &JobSystem<S>, claimed: &ClaimedJob) {
    let Some(attempts) = claimed.record().attempts.as_ref() else {
        return;
    };
    system.observe(crate::observer::JobEvent::Claimed {
        queue: claimed.record().queue.clone(),
        priority: claimed.record().priority,
        attempt: crate::observer::AttemptBucket::from_attempt(attempts.attempts.get()),
    });
}

fn deadline_outcome(
    now: Timestamp,
) -> Result<crate::model::JobOutcome, crate::error::ValidationError> {
    Ok(crate::model::JobOutcome::Retry {
        class: crate::policy::RetryClass::Transient,
        not_before: Some(now),
        code: crate::policy::OutcomeCode::try_new("drive_deadline")?,
    })
}

async fn apply_outcome<S: JobStore>(
    system: &JobSystem<S>,
    claimed: ClaimedJob,
    outcome: crate::model::JobOutcome,
    now: Timestamp,
) -> JobResult<CandidateResult, S::Error> {
    match crate::failure::apply_outcome(system, claimed, outcome, now).await? {
        crate::failure::OutcomeResult::Completed(completion) => {
            Ok(CandidateResult::Completed(completion))
        }
        crate::failure::OutcomeResult::Continued { not_before } => {
            Ok(CandidateResult::Continued { not_before })
        }
        crate::failure::OutcomeResult::Retried { not_before, .. } => {
            Ok(CandidateResult::Retried { not_before })
        }
        crate::failure::OutcomeResult::DeadLettered { .. } => Ok(CandidateResult::DeadLettered),
        crate::failure::OutcomeResult::Cancelled => Ok(CandidateResult::Cancelled),
    }
}

fn record_completion(
    report: &mut DriveReport,
    completion: crate::budget::CompletionDetails,
    maximum: u32,
) {
    if report.completions.len() < maximum as usize {
        report.completions.push(completion);
    } else {
        report.completions_omitted += 1;
    }
}
