//! Durable candidate and scope state owned by the fair ledger.

use std::collections::BTreeMap;

use super::index::{CandidateRoute, IndexRefresh};
#[cfg(any(test, feature = "test-support"))]
use crate::fairness::ScopeSnapshot;
use crate::{
    fairness::{
        FairCandidate, FairCandidateState, FairPermitGeneration, FairnessBudget, PriorityDeficit,
        ScopeState,
    },
    ids::{JobId, OrderingKey},
};

#[derive(Clone, Debug)]
pub(super) struct CandidateRecord {
    pub(super) candidate: FairCandidate,
    pub(super) state: FairCandidateState,
    pub(super) service_transitions: u64,
    pub(super) acquisition_generation: Option<FairPermitGeneration>,
}

impl CandidateRecord {
    pub(super) fn scheduled(candidate: FairCandidate) -> Self {
        Self {
            candidate,
            state: FairCandidateState::Scheduled,
            service_transitions: 0,
            acquisition_generation: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct OrderRecord {
    pub(super) head: u64,
    pub(super) owner: JobId,
    pub(super) in_flight: bool,
    pub(super) acquisitions: u64,
    pub(super) releases: u64,
}

impl Default for OrderRecord {
    fn default() -> Self {
        Self {
            head: 0,
            owner: JobId::from([0; 16]),
            in_flight: false,
            acquisitions: 0,
            releases: 0,
        }
    }
}

/// The fair-dispatch accounting and admission boundary.
#[derive(Clone, Debug)]
pub struct FairnessLedger {
    pub(super) budget: FairnessBudget,
    pub(super) scopes: BTreeMap<crate::FairScope, ScopeState>,
    pub(super) candidates: BTreeMap<JobId, CandidateRecord>,
    pub(super) orders: BTreeMap<OrderingKey, OrderRecord>,
    pub(super) priority: PriorityDeficit,
    pub(super) service_clock: u128,
}

impl FairnessLedger {
    pub fn new(budget: FairnessBudget) -> Self {
        Self {
            budget,
            scopes: BTreeMap::new(),
            candidates: BTreeMap::new(),
            orders: BTreeMap::new(),
            priority: PriorityDeficit::default(),
            service_clock: 0,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub const fn budget(&self) -> FairnessBudget {
        self.budget
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn scope_snapshot(&self, scope: &crate::FairScope) -> Option<ScopeSnapshot> {
        self.scopes
            .get(scope)
            .map(|state| ScopeSnapshot::from_state(scope, state))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn scope_snapshots(&self) -> impl Iterator<Item = (&crate::FairScope, ScopeSnapshot)> {
        self.scopes
            .iter()
            .map(|(scope, state)| (scope, ScopeSnapshot::from_state(scope, state)))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub const fn priority_deficit(&self) -> PriorityDeficit {
        self.priority
    }

    pub fn candidate_state(&self, job_id: JobId) -> Option<FairCandidateState> {
        self.candidates.get(&job_id).map(|record| record.state)
    }

    pub(super) fn terminal_or_absent_candidates(&self) -> impl Iterator<Item = JobId> + '_ {
        self.candidates
            .iter()
            .filter_map(|(job_id, record)| match record.state {
                FairCandidateState::Absent
                | FairCandidateState::DeadLettered
                | FairCandidateState::Cancelled => Some(*job_id),
                FairCandidateState::Scheduled
                | FairCandidateState::Leased
                | FairCandidateState::RetryWaiting => None,
            })
    }

    pub(super) fn compact_candidate(&mut self, job_id: JobId) -> bool {
        let Some(record) = self.candidates.get(&job_id) else {
            return false;
        };
        match record.state {
            FairCandidateState::Absent
            | FairCandidateState::DeadLettered
            | FairCandidateState::Cancelled => {}
            FairCandidateState::Scheduled
            | FairCandidateState::Leased
            | FairCandidateState::RetryWaiting => return false,
        }
        let ordering_key = record.candidate.ordering_key.clone();
        let old_route = CandidateRoute::from_record(record);
        self.candidates.remove(&job_id);
        self.replace_candidate_route(Some(&old_route), None, IndexRefresh::PreserveOrder);
        if let Some(ordering_key) = ordering_key
            && !self
                .candidates
                .values()
                .any(|record| record.candidate.ordering_key.as_ref() == Some(&ordering_key))
        {
            self.orders.remove(&ordering_key);
        }
        true
    }

    pub(super) fn compact_empty_scopes(&mut self) {
        let candidate_scopes: std::collections::BTreeSet<_> = self
            .candidates
            .values()
            .flat_map(|record| {
                [
                    record.candidate.scope().clone(),
                    record.candidate.scope().primary_scope(),
                ]
            })
            .collect();
        self.scopes.retain(|scope, state| {
            state.in_flight != 0 || state.is_ready() || candidate_scopes.contains(scope)
        });
    }
}
