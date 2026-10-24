use super::super::{candidate::CandidateResult, constants::initial_completion_capacity};
#[cfg(test)]
use crate::{
    budget::CompletionDetails,
    ids::{JobId, JobKind, QueueName},
    policy::{EffectMode, OutcomeCode},
};
use crate::{
    budget::{DriveCounts, DriveReport, DriveStopReason},
    engine::JobSystem,
    error::JobResult,
    fairness::{FairDispatchOwner, FairPermit, FairRelease},
    store::JobStore,
    time::{Timestamp, WakeHint},
};

pub(super) struct CompletionBookkeeping<E> {
    pub(super) completed: Vec<Option<super::CompletedCandidate<E>>>,
    pub(super) next_apply: usize,
    pub(super) next_order: usize,
    pub(super) reserved_claims: u32,
    pub(super) future_wake: Option<Timestamp>,
    pub(super) stop_starting: bool,
}

impl<E> CompletionBookkeeping<E> {
    pub(super) fn new(stop_starting: bool) -> Self {
        Self {
            completed: Vec::new(),
            next_apply: 0,
            next_order: 0,
            reserved_claims: 0,
            future_wake: None,
            stop_starting,
        }
    }

    pub(super) fn reserve_claim(&mut self) -> usize {
        let order = self.next_order;
        self.next_order = self.next_order.saturating_add(1);
        self.completed.push(None);
        self.reserved_claims = self.reserved_claims.saturating_add(1);
        order
    }

    pub(super) fn settle(
        &mut self,
        owner: &mut FairDispatchOwner,
        active_payload_bytes: &mut usize,
        completed_candidate: super::CompletedCandidate<E>,
        permit: FairPermit,
    ) {
        self.stop_starting |= completed_candidate.result.is_err();
        // Release the local reservation so this drive can fill another lane.
        // The durable owner was already committed before the effect began;
        // intentionally do not save this post-effect projection.
        settle_ledger_result(owner, permit, &completed_candidate.result);
        *active_payload_bytes =
            active_payload_bytes.saturating_sub(completed_candidate.payload_bytes);
        let order = completed_candidate.order;
        self.completed[order] = Some(completed_candidate);
    }

    pub(super) fn apply(
        &mut self,
        report: &mut DriveReport,
        now: Timestamp,
        max_completion_details: u32,
    ) -> JobResult<(), E> {
        while self.next_apply < self.completed.len() {
            let Some(completed_candidate) = self.completed[self.next_apply].take() else {
                break;
            };
            self.next_apply = self.next_apply.saturating_add(1);
            self.reserved_claims = self.reserved_claims.saturating_sub(1);
            let result = completed_candidate.result?;
            let pending_at = match &result {
                CandidateResult::Completed(_)
                | CandidateResult::DeadLettered
                | CandidateResult::Cancelled => None,
                CandidateResult::Continued { not_before }
                | CandidateResult::Retried { not_before } => Some(*not_before),
                CandidateResult::LeaseConflict
                | CandidateResult::Unregistered
                | CandidateResult::Capacity
                | CandidateResult::Deadline => Some(now),
            };
            if let Some(at) = pending_at {
                self.future_wake = Some(self.future_wake.map_or(at, |current| current.min(at)));
            }
            if super::super::candidate::apply_candidate_result(
                report,
                result,
                max_completion_details,
            ) {
                self.stop_starting = true;
            }
        }
        Ok(())
    }
}

fn settle_ledger_result<E>(
    owner: &mut FairDispatchOwner,
    permit: FairPermit,
    result: &JobResult<CandidateResult, E>,
) {
    let Ok(result) = result else {
        let _ = owner.release(permit, FairRelease::Retry);
        return;
    };
    match result {
        CandidateResult::Completed(_)
        | CandidateResult::DeadLettered
        | CandidateResult::Cancelled => {
            let _ =
                owner.record_service_units(permit.job_id(), u64::from(permit.cost_units().get()));
            let _ = owner.release(permit, FairRelease::Complete);
        }
        CandidateResult::Continued { not_before } | CandidateResult::Retried { not_before } => {
            let job_id = permit.job_id();
            let _ = owner.record_service_units(job_id, u64::from(permit.cost_units().get()));
            let _ = owner.release(permit, FairRelease::Retry);
            owner.defer_candidate(job_id, *not_before);
        }
        CandidateResult::LeaseConflict | CandidateResult::Unregistered => {
            let job_id = permit.job_id();
            let _ = owner.release(permit, FairRelease::Conflict);
            owner.remove_candidate(job_id);
        }
        CandidateResult::Capacity | CandidateResult::Deadline => {
            let _ = owner.release(permit, FairRelease::Retry);
        }
    }
}

pub(super) async fn finish_report<S, E>(
    system: &JobSystem<S>,
    request: &crate::budget::DriveRequest,
    mut report: DriveReport,
    next_wake: WakeHint,
) -> JobResult<DriveReport, E>
where
    S: JobStore,
{
    report.has_immediately_visible_work = next_wake.is_now();
    report.next_wake = next_wake;
    if system.is_shutdown() {
        report.stop_reason = DriveStopReason::Shutdown;
    } else if report.counts.claimed >= request.max_claims().get() {
        report.stop_reason = DriveStopReason::ClaimsExhausted;
    } else if report.stop_reason == DriveStopReason::NoVisibleWork
        && report.has_immediately_visible_work
    {
        report.stop_reason = DriveStopReason::Capacity;
    }
    system.observe(crate::observer::JobEvent::DriveStopped {
        reason: report.stop_reason,
    });
    Ok(report)
}

pub(super) fn empty_report(max_completion_details: u32) -> DriveReport {
    DriveReport {
        counts: DriveCounts::default(),
        completions: Vec::with_capacity(initial_completion_capacity(max_completion_details)),
        completions_omitted: 0,
        has_immediately_visible_work: false,
        next_wake: WakeHint::None,
        stop_reason: DriveStopReason::NoVisibleWork,
    }
}

#[cfg(test)]
pub(crate) fn apply_buffered_results_for_test() -> DriveReport {
    let mut report = empty_report(0);
    let mut bookkeeping = CompletionBookkeeping {
        completed: vec![
            Some(super::CompletedCandidate::<()> {
                order: 0,
                payload_bytes: 0,
                result: Ok(CandidateResult::Capacity),
            }),
            Some(super::CompletedCandidate::<()> {
                order: 1,
                payload_bytes: 0,
                result: Ok(CandidateResult::Completed(test_completion_details())),
            }),
        ],
        next_apply: 0,
        next_order: 2,
        reserved_claims: 2,
        future_wake: None,
        stop_starting: false,
    };

    bookkeeping
        .apply(&mut report, Timestamp::ZERO, 1)
        .expect("test results are successful");
    report
}

#[cfg(test)]
fn test_completion_details() -> CompletionDetails {
    CompletionDetails {
        job_id: JobId::from([2; 16]),
        execution_id: [2; 16].into(),
        generation: 1,
        kind: JobKind::try_new("email").expect("test kind is valid"),
        queue: QueueName::try_new("default").expect("test queue is valid"),
        effect_mode: EffectMode::Idempotent,
        created_at: Timestamp::ZERO,
        completed_at: Timestamp::ZERO,
        attempts: std::num::NonZeroU32::MIN,
        outcome: OutcomeCode::try_new("completed").expect("test outcome is valid"),
    }
}
