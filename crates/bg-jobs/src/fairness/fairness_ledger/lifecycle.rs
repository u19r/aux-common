//! Candidate lifecycle and permit settlement for the fair ledger.

use super::{
    admission::CapacityRelease,
    index::{CandidateRoute, IndexRefresh},
    state::{CandidateRecord, FairnessLedger, OrderRecord},
};
#[cfg(any(test, feature = "test-support"))]
use crate::fairness::FairScope;
use crate::{
    error::ValidationError,
    fairness::{
        FairCandidate, FairCandidateInput, FairCandidateState, FairPermit, FairRelease,
        FairnessRejection,
    },
    ids::JobId,
};

#[derive(Clone, Copy)]
enum PermitSettlement {
    Outcome(FairRelease),
    #[cfg(any(test, feature = "test-support"))]
    Service(CapacityRelease),
}

impl PermitSettlement {
    const fn state(self) -> FairCandidateState {
        match self {
            Self::Outcome(FairRelease::Retry | FairRelease::Conflict) => {
                FairCandidateState::RetryWaiting
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Service(_) => FairCandidateState::RetryWaiting,
            #[cfg(any(test, feature = "test-support"))]
            Self::Outcome(FairRelease::DeadLetter) => FairCandidateState::DeadLettered,
            #[cfg(any(test, feature = "test-support"))]
            Self::Outcome(FairRelease::Cancelled) => FairCandidateState::Cancelled,
            Self::Outcome(FairRelease::Complete) => FairCandidateState::Absent,
        }
    }

    const fn capacity_release(self) -> CapacityRelease {
        match self {
            Self::Outcome(FairRelease::Conflict) => CapacityRelease::UndoService,
            Self::Outcome(_) => CapacityRelease::RestoreRate,
            #[cfg(any(test, feature = "test-support"))]
            Self::Service(release) => release,
        }
    }

    const fn advances_order(self) -> bool {
        matches!(self, Self::Outcome(release) if release.is_terminal())
    }

    const fn records_service(self) -> bool {
        #[cfg(any(test, feature = "test-support"))]
        {
            matches!(self, Self::Service(_))
        }
        #[cfg(not(any(test, feature = "test-support")))]
        {
            false
        }
    }
}

impl FairnessLedger {
    /// Inserts one scheduled candidate and creates its primary/secondary
    /// accounting scopes when they are first observed.
    pub fn add_candidate(&mut self, input: FairCandidateInput) -> Result<(), ValidationError> {
        let candidate = FairCandidate::try_from(input)?;
        let job_id = candidate.job_id();
        if self.candidates.contains_key(&candidate.job_id()) {
            return Err(ValidationError::InvalidValue {
                field: "duplicate fair candidate",
            });
        }
        self.register_candidate(&candidate);
        self.candidates
            .insert(candidate.job_id(), CandidateRecord::scheduled(candidate));
        let route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(None, route.as_ref(), IndexRefresh::AdvanceOrder);
        Ok(())
    }

    /// Refreshes fair configuration without replacing live lifecycle state.
    ///
    /// A new or absent candidate becomes scheduled.  A scheduled or retrying
    /// candidate keeps its lifecycle route while its fair configuration and
    /// advisory index are refreshed.  Terminal and leased candidates cannot
    /// be resurrected or rewritten by configuration replay.
    pub fn upsert_candidate(&mut self, input: FairCandidateInput) -> Result<(), ValidationError> {
        let candidate = FairCandidate::try_from(input)?;
        let job_id = candidate.job_id();
        let previous_route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        let previous_state = self.candidates.get(&job_id).map(|record| record.state);
        let next_state = Self::upsert_state(previous_state)?;
        self.register_candidate(&candidate);
        self.replace_candidate_record(job_id, candidate, next_state);
        let next_route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(
            previous_route.as_ref(),
            next_route.as_ref(),
            IndexRefresh::PreserveOrder,
        );
        Ok(())
    }

    fn upsert_state(
        previous_state: Option<FairCandidateState>,
    ) -> Result<FairCandidateState, ValidationError> {
        match previous_state {
            None | Some(FairCandidateState::Absent | FairCandidateState::Scheduled) => {
                Ok(FairCandidateState::Scheduled)
            }
            Some(FairCandidateState::RetryWaiting) => Ok(FairCandidateState::RetryWaiting),
            Some(FairCandidateState::Leased) => Err(ValidationError::InvalidValue {
                field: "leased fair candidate",
            }),
            Some(FairCandidateState::DeadLettered | FairCandidateState::Cancelled) => {
                Err(ValidationError::InvalidValue {
                    field: "terminal fair candidate",
                })
            }
        }
    }

    fn replace_candidate_record(
        &mut self,
        job_id: JobId,
        candidate: FairCandidate,
        state: FairCandidateState,
    ) {
        if let Some(record) = self.candidates.get_mut(&job_id) {
            record.candidate = candidate;
            record.state = state;
        } else {
            let mut record = CandidateRecord::scheduled(candidate);
            record.state = state;
            self.candidates.insert(job_id, record);
        }
    }

    pub(crate) fn defer_candidate(&mut self, job_id: JobId, scheduled_at: crate::time::Timestamp) {
        let old_route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        let Some(record) = self.candidates.get_mut(&job_id) else {
            return;
        };
        record.candidate.scheduled_at = scheduled_at;
        record.state = FairCandidateState::RetryWaiting;
        let new_route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(
            old_route.as_ref(),
            new_route.as_ref(),
            IndexRefresh::PreserveOrder,
        );
    }

    pub(crate) fn remove_candidate(&mut self, job_id: JobId) {
        let leased_permit = self
            .candidates
            .get(&job_id)
            .and_then(|record| match record.state {
                FairCandidateState::Leased => Some(permit_for_leased_record(job_id, record)),
                FairCandidateState::Absent
                | FairCandidateState::Scheduled
                | FairCandidateState::RetryWaiting
                | FairCandidateState::DeadLettered
                | FairCandidateState::Cancelled => None,
            });
        if let Some(permit) = leased_permit {
            // A complete discovery pass proves that a stale leased projection
            // no longer has an authoritative lifecycle record.  Settle its
            // reservation before compaction so capacity and ordering state do
            // not survive the projection that owns them.
            self.apply_settlement(&permit, PermitSettlement::Outcome(FairRelease::Complete));
            self.restore_reconciled_low_volume_service(&permit);
            return;
        }
        let Some(record) = self.candidates.get_mut(&job_id) else {
            return;
        };
        let old_route = Some(CandidateRoute::from_record(record));
        record.state = FairCandidateState::Absent;
        let new_route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(
            old_route.as_ref(),
            new_route.as_ref(),
            IndexRefresh::PreserveOrder,
        );
    }

    pub fn release(
        &mut self,
        permit: FairPermit,
        release: FairRelease,
    ) -> Result<(), FairnessRejection> {
        self.settle_permit(&permit, PermitSettlement::Outcome(release))
    }

    /// Records the cost-bearing service units for one successful fair
    /// operation. The model's service counter is cost-weighted, so ordinary
    /// selection and service settlement both use this canonical accounting
    /// path rather than maintaining an adapter-local counter.
    pub fn record_service_units(&mut self, job_id: JobId, units: u64) -> bool {
        let Some(record) = self.candidates.get_mut(&job_id) else {
            return false;
        };
        record.service_transitions = record.service_transitions.saturating_add(units);
        true
    }

    /// Applies one service unit to a ready candidate and returns it to the
    /// retry route. Service is transient authority: permits and in-flight
    /// slots are restored, while the rate token is restored only when
    /// requested.
    #[cfg(any(test, feature = "test-support"))]
    pub fn service_transition(
        &mut self,
        job_id: JobId,
        refill_rate: bool,
    ) -> Result<FairPermit, FairnessRejection> {
        let permit = self.select(job_id)?;
        self.settle_service(&permit, refill_rate)?;
        Ok(permit)
    }

    /// Settles a permit after the caller has completed the corresponding
    /// durable service transition. The permit remains a retry candidate and
    /// records one service unit without advancing its ordering head.
    #[cfg(any(test, feature = "test-support"))]
    pub fn settle_service(
        &mut self,
        permit: &FairPermit,
        refill_rate: bool,
    ) -> Result<(), FairnessRejection> {
        let release = if refill_rate {
            CapacityRelease::RestoreRate
        } else {
            CapacityRelease::PreserveRate
        };
        self.settle_permit(permit, PermitSettlement::Service(release))
    }

    /// Reconciles a locally persisted lease reservation with the authoritative
    /// lifecycle record observed by a later drive.  Selection is committed
    /// before effects, so the owner can legitimately still say `Leased` after
    /// a process crash or a successful lifecycle transition.  Releasing the
    /// accounting reservation here restores capacity. Low-volume service
    /// remains capped until a later drive observes the durable lifecycle
    /// result, then becomes eligible again without a post-effect owner save.
    pub(super) fn reconcile_leased(
        &mut self,
        job_id: JobId,
        scheduled_at: crate::time::Timestamp,
    ) -> bool {
        let Some(record) = self.candidates.get(&job_id) else {
            return false;
        };
        match record.state {
            FairCandidateState::Leased => {}
            FairCandidateState::Absent
            | FairCandidateState::Scheduled
            | FairCandidateState::RetryWaiting
            | FairCandidateState::DeadLettered
            | FairCandidateState::Cancelled => return false,
        }
        let permit = permit_for_leased_record(job_id, record);
        let old_route = Some(CandidateRoute::from_record(record));
        self.release_capacity(&permit, CapacityRelease::RestoreRate);
        self.restore_reconciled_low_volume_service(&permit);
        if let Some(record) = self.candidates.get_mut(&job_id) {
            record.candidate.scheduled_at = scheduled_at;
            record.state = FairCandidateState::RetryWaiting;
            record.acquisition_generation = None;
        }
        let new_route = self
            .candidates
            .get(&job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(
            old_route.as_ref(),
            new_route.as_ref(),
            IndexRefresh::PreserveOrder,
        );
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn block(&mut self, scope: &FairScope, reason: crate::fairness::CandidateBlock) -> bool {
        let Some(state) = self.scopes.get_mut(scope) else {
            return false;
        };
        state.block = Some(reason);
        true
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn tick(&mut self) {
        for state in self.scopes.values_mut() {
            if state.is_ready() {
                state.quiet_dwell = state.quiet_dwell.saturating_add(1);
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn refill(&mut self, scope: &FairScope) -> bool {
        let Some(state) = self.scopes.get_mut(scope) else {
            return false;
        };
        state.rate = self.budget.max_rate_per_scope().get();
        state.permits = self
            .budget
            .max_concurrency_per_scope()
            .get()
            .saturating_sub(state.in_flight);
        true
    }

    pub fn reset_priority_window(&mut self) {
        self.priority = crate::PriorityDeficit::default();
        for record in self.candidates.values_mut() {
            record.service_transitions = 0;
        }
    }

    fn register_candidate(&mut self, candidate: &FairCandidate) {
        self.ensure_scope(candidate.scope(), candidate.cost_units());
        if candidate.scope().is_secondary() {
            let primary = candidate.scope().primary_scope();
            self.ensure_scope(&primary, candidate.cost_units());
        }
        if let Some(key) = candidate.ordering_key() {
            self.orders
                .entry(key.clone())
                .or_insert_with(|| OrderRecord {
                    head: candidate.ordering_position(),
                    owner: candidate.job_id(),
                    ..OrderRecord::default()
                });
        }
    }

    fn settle_permit(
        &mut self,
        permit: &FairPermit,
        settlement: PermitSettlement,
    ) -> Result<(), FairnessRejection> {
        let Some(record) = self.candidates.get(&permit.job_id) else {
            return Err(FairnessRejection::UnknownScope);
        };
        match record.state {
            FairCandidateState::Leased
                if record.acquisition_generation == Some(permit.acquisition_generation) => {}
            FairCandidateState::Absent
            | FairCandidateState::Scheduled
            | FairCandidateState::RetryWaiting
            | FairCandidateState::DeadLettered
            | FairCandidateState::Cancelled
            | FairCandidateState::Leased => {
                return Err(FairnessRejection::OrderingHead);
            }
        }
        self.apply_settlement(permit, settlement);
        Ok(())
    }

    fn apply_settlement(&mut self, permit: &FairPermit, settlement: PermitSettlement) {
        let old_route = self
            .candidates
            .get(&permit.job_id)
            .map(CandidateRoute::from_record);
        self.release_capacity(permit, settlement.capacity_release());
        if let Some(key) = &permit.ordering_key
            && settlement.advances_order()
            && let Some(order) = self.orders.get_mut(key)
        {
            order.head = permit.ordering_position.saturating_add(1);
        }
        if let Some(record) = self.candidates.get_mut(&permit.job_id) {
            record.state = settlement.state();
            if settlement.records_service() {
                record.service_transitions = record
                    .service_transitions
                    .saturating_add(u64::from(permit.cost_units.get()));
            }
        }
        let new_route = self
            .candidates
            .get(&permit.job_id)
            .map(CandidateRoute::from_record);
        self.replace_candidate_route(
            old_route.as_ref(),
            new_route.as_ref(),
            IndexRefresh::PreserveOrder,
        );
    }
}

fn permit_for_leased_record(job_id: JobId, record: &CandidateRecord) -> FairPermit {
    let candidate = &record.candidate;
    FairPermit {
        job_id,
        scope: candidate.scope.clone(),
        primary: candidate
            .scope
            .is_secondary()
            .then(|| candidate.scope.primary_scope()),
        priority: candidate.priority,
        cost_units: candidate.cost_units,
        ordering_key: candidate.ordering_key.clone(),
        ordering_position: candidate.ordering_position,
        acquisition_generation: record
            .acquisition_generation
            .unwrap_or(crate::fairness::FairPermitGeneration::FIRST),
    }
}
