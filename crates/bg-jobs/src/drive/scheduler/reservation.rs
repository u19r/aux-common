use std::collections::{BTreeMap, BTreeSet};

use super::super::{
    candidate::Candidate,
    constants::{
        CANCELLATION_READ_STORE_OPERATIONS, CANDIDATE_WORST_CASE_STORE_OPERATIONS,
        OWNER_SAVE_WORST_CASE_STORE_OPERATIONS, OperationBudget,
    },
};
use crate::{
    budget::{DriveRequest, DriveStopReason},
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    fairness::{FairDispatchOwner, FairPermit, FairRelease},
    ids::JobId,
    keys,
    model::JobState,
    store::JobStore,
    time::Timestamp,
};
pub(super) enum CandidateStartStatus {
    Idle,
    LeaseConflict,
    Stop(DriveStopReason),
}

pub(super) struct ReservedCandidate {
    pub(super) permit: FairPermit,
    pub(super) candidate: Candidate,
    pub(super) payload_bytes: usize,
}

pub(super) struct CandidateStarter<'a, S: JobStore> {
    pub(super) system: &'a JobSystem<S>,
    pub(super) request: &'a DriveRequest,
    pub(super) now: Timestamp,
    pub(super) owner: &'a mut FairDispatchOwner,
    pub(super) candidates: &'a mut BTreeMap<JobId, Candidate>,
    pub(super) eligible_ids: &'a BTreeSet<JobId>,
    pub(super) operation_budget: &'a mut OperationBudget,
    pub(super) active_payload_bytes: usize,
    pub(super) has_active: bool,
}

impl<S: JobStore> CandidateStarter<'_, S> {
    pub(super) async fn reserve_next(
        &mut self,
    ) -> JobResult<Result<ReservedCandidate, CandidateStartStatus>, S::Error> {
        self.reconcile_ready_candidates();
        let (permit, candidate) = match self.select_candidate()? {
            Ok(selection) => selection,
            Err(status) => return Ok(Err(status)),
        };
        let payload_bytes = candidate.record.payload.total_length as usize;
        if self.active_payload_bytes.saturating_add(payload_bytes)
            > self.request.max_payload_bytes_in_flight().get()
            && self.has_active
        {
            self.system
                .observe(crate::observer::JobEvent::CapacityLimited {
                    resource: crate::observer::CapacityResource::PayloadBytes,
                });
            let _ = self.owner.release(permit, FairRelease::Retry);
            return Ok(Err(CandidateStartStatus::Idle));
        }
        let candidate_operations = self.candidate_operation_bound(&candidate)?;
        if !self
            .operation_budget
            .reserve(OWNER_SAVE_WORST_CASE_STORE_OPERATIONS.saturating_add(candidate_operations))
        {
            let _ = self.owner.release(permit, FairRelease::Retry);
            return Ok(Err(CandidateStartStatus::Stop(DriveStopReason::Capacity)));
        }
        let permit = match self.save_reservation(permit).await? {
            Ok(permit) => permit,
            Err(status) => return Ok(Err(status)),
        };
        Ok(Ok(ReservedCandidate {
            permit,
            candidate,
            payload_bytes,
        }))
    }

    async fn save_reservation(
        &mut self,
        permit: FairPermit,
    ) -> JobResult<Result<FairPermit, CandidateStartStatus>, S::Error> {
        match self.owner.save(self.system).await {
            Ok(()) => Ok(Ok(permit)),
            Err(error) => {
                let _ = self.owner.release(permit, FairRelease::Retry);
                match error {
                    JobSystemError::LeaseConflict => Ok(Err(CandidateStartStatus::LeaseConflict)),
                    error => Err(error),
                }
            }
        }
    }

    fn candidate_operation_bound(&self, candidate: &Candidate) -> JobResult<u32, S::Error> {
        let permit_capacity = if candidate.route_is_due {
            self.request.max_concurrency()
        } else {
            std::num::NonZeroU16::new(keys::MAX_DURABLE_PERMIT_SLOTS)
                .ok_or(JobSystemError::PayloadCorrupt)?
        };
        let permit_reads = crate::fairness::permit_read_operation_bound(
            self.system,
            &candidate.record,
            permit_capacity,
        )?;
        let mut candidate_operations =
            CANDIDATE_WORST_CASE_STORE_OPERATIONS.saturating_add(permit_reads.saturating_sub(1));
        if matches!(&candidate.record.state, JobState::Leased(lease) if lease.expires_at <= self.now)
        {
            candidate_operations =
                candidate_operations.saturating_add(CANCELLATION_READ_STORE_OPERATIONS);
        }
        Ok(candidate_operations)
    }

    fn reconcile_ready_candidates(&mut self) {
        for candidate in self.candidates.values() {
            let ready = match &candidate.record.state {
                JobState::Scheduled
                | JobState::DeadLettered
                | JobState::Cancelled
                | JobState::Suspended => true,
                JobState::Leased(lease) => lease.expires_at <= self.now,
            };
            if ready {
                self.owner
                    .reconcile_leased_candidate(candidate.record.job_id, candidate.when);
            }
        }
    }

    fn observe_idle_selection(&self, eligible: &BTreeSet<JobId>) {
        if eligible.iter().any(|id| {
            self.candidates
                .get(id)
                .is_some_and(|candidate| candidate.when <= self.now)
        }) {
            self.system
                .observe(crate::observer::JobEvent::CapacityLimited {
                    resource: crate::observer::CapacityResource::Fairness,
                });
        }
    }

    fn select_candidate(
        &mut self,
    ) -> JobResult<Result<(FairPermit, Candidate), CandidateStartStatus>, S::Error> {
        // Expired leases still own durable slots. Trying older waiting work
        // first can exhaust every drive without ever recovering the capacity it
        // needs.
        let recovering: BTreeSet<_> = self.eligible_ids.iter().copied().filter(|id| {
            self.candidates.get(id).is_some_and(|candidate| {
                matches!(&candidate.record.state, JobState::Leased(lease) if lease.expires_at <= self.now)
            })
        }).collect();
        let eligible = if recovering.is_empty() {
            self.eligible_ids
        } else {
            &recovering
        };
        let permit = match self.owner.select_next_due_in(self.now, eligible) {
            Ok(Some(permit)) => permit,
            Ok(None) => {
                self.observe_idle_selection(eligible);
                return Ok(Err(CandidateStartStatus::Idle));
            }
            Err(_) => {
                self.system
                    .observe(crate::observer::JobEvent::CapacityLimited {
                        resource: crate::observer::CapacityResource::Fairness,
                    });
                return Ok(Err(CandidateStartStatus::Stop(DriveStopReason::Capacity)));
            }
        };
        let candidate = self
            .candidates
            .get(&permit.job_id())
            .cloned()
            .ok_or(JobSystemError::PayloadCorrupt)?;
        Ok(Ok((permit, candidate)))
    }
}
