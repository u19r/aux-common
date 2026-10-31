//! Selection pass orchestration for the fair ledger.

#[cfg(test)]
use std::cell::Cell;
use std::collections::BTreeSet;

use super::{
    super::super::state::FairnessLedger,
    state::{CandidatePreparation, SelectionPass},
};
use crate::{
    fairness::{FairPermit, FairnessRejection},
    ids::JobId,
    time::Timestamp,
};

#[cfg(test)]
thread_local! {
    static SELECTION_SCAN_VISITS: Cell<usize> = const { Cell::new(0) };
    static SELECTION_SCOPE_VISITS: Cell<usize> = const { Cell::new(0) };
}

pub(in crate::fairness::fairness_ledger::admission) type SelectionScore =
    (u8, u128, u32, u128, Timestamp, JobId);

struct DueCandidateSearch<'a> {
    best: Option<(JobId, &'a CandidatePreparation, SelectionScore)>,
    first_rejection: Option<FairnessRejection>,
    priority_rejected: bool,
}

impl FairnessLedger {
    #[cfg(test)]
    pub(crate) fn reset_selection_scan_visits() {
        SELECTION_SCAN_VISITS.with(|visits| visits.set(0));
        SELECTION_SCOPE_VISITS.with(|visits| visits.set(0));
    }

    #[cfg(test)]
    pub(crate) fn selection_scan_visits() -> usize {
        SELECTION_SCAN_VISITS.with(Cell::get)
    }

    #[cfg(test)]
    pub(crate) fn selection_scope_visits() -> usize {
        SELECTION_SCOPE_VISITS.with(Cell::get)
    }

    /// Selects one candidate and charges both its child scope and primary
    /// scope. Selection is all-or-nothing: no counters change on rejection.
    #[cfg(any(test, feature = "test-support"))]
    pub fn select(&mut self, job_id: JobId) -> Result<FairPermit, FairnessRejection> {
        let pass = self.prepare_selection_pass(None, None);
        let bulk_ready = self.has_admissible_bulk(&pass);
        let Some(target_index) = pass.candidates.iter().position(|candidate| {
            #[cfg(test)]
            record_selection_scan_visit();
            candidate.job_id == job_id
        }) else {
            return Err(FairnessRejection::UnknownScope);
        };
        let Some(target) = pass.candidates.get(target_index) else {
            return Err(FairnessRejection::UnknownScope);
        };
        let target_preparation = match self.check_selection(target, bulk_ready) {
            Ok(preparation) => preparation,
            Err(FairnessRejection::PriorityDeficit)
                if self.reset_exhausted_priority_window(&pass) =>
            {
                self.check_selection(target, self.has_admissible_bulk(&pass))?
            }
            Err(reason) => return Err(reason),
        };
        self.check_normalized_admission(target_preparation, &pass)?;
        let selection = self.prepare_candidate(job_id)?;
        Ok(self.settle_selection(selection, target_preparation, &pass))
    }

    /// Selects the best currently due candidate from the ledger. The caller
    /// supplies the authoritative wall-time snapshot used for due filtering;
    /// discovery order is never part of this decision.
    #[cfg(test)]
    pub(crate) fn select_next_due(
        &mut self,
        now: Timestamp,
    ) -> Result<Option<FairPermit>, FairnessRejection> {
        self.select_next_due_in_scope(now, None)
    }

    pub(crate) fn select_next_due_in(
        &mut self,
        now: Timestamp,
        eligible: &BTreeSet<JobId>,
    ) -> Result<Option<FairPermit>, FairnessRejection> {
        self.select_next_due_in_scope(now, Some(eligible))
    }

    fn select_next_due_in_scope(
        &mut self,
        now: Timestamp,
        eligible: Option<&BTreeSet<JobId>>,
    ) -> Result<Option<FairPermit>, FairnessRejection> {
        let pass = self.prepare_selection_pass(Some(now), eligible);
        let mut bulk_ready = self.has_admissible_bulk(&pass);
        loop {
            let search = self.find_due_candidate(&pass, bulk_ready);
            match search.best {
                Some((best_job_id, preparation, _)) => {
                    let selection = self.prepare_candidate(best_job_id)?;
                    return Ok(Some(self.settle_selection(selection, preparation, &pass)));
                }
                None if search.priority_rejected && self.reset_exhausted_priority_window(&pass) => {
                    bulk_ready = self.has_admissible_bulk(&pass);
                }
                None => return search.first_rejection.map_or(Ok(None), Err),
            }
        }
    }

    fn find_due_candidate<'a>(
        &self,
        pass: &'a SelectionPass,
        bulk_ready: bool,
    ) -> DueCandidateSearch<'a> {
        let mut search = DueCandidateSearch {
            best: None,
            first_rejection: None,
            priority_rejected: false,
        };
        for prepared in &pass.candidates {
            #[cfg(test)]
            record_selection_scan_visit();
            if !prepared.ready || !prepared.due {
                continue;
            }
            let preparation = match self.check_selection(prepared, bulk_ready) {
                Ok(preparation) => preparation,
                Err(reason) => {
                    search.priority_rejected |= reason == FairnessRejection::PriorityDeficit;
                    search.first_rejection.get_or_insert(reason);
                    continue;
                }
            };
            if self.check_normalized_admission(preparation, pass).is_err() {
                search
                    .first_rejection
                    .get_or_insert(FairnessRejection::NormalizedServiceBound);
                continue;
            }
            let score = Self::selection_score(prepared.job_id, preparation);
            if search
                .best
                .as_ref()
                .is_none_or(|(_, _, current)| score < *current)
            {
                search.best = Some((prepared.job_id, preparation, score));
            }
        }
        search
    }
}

#[cfg(test)]
pub(in crate::fairness::fairness_ledger::admission) fn record_selection_scan_visit() {
    SELECTION_SCAN_VISITS.with(|visits| visits.set(visits.get().saturating_add(1)));
}

#[cfg(test)]
pub(in crate::fairness::fairness_ledger::admission) fn record_selection_scope_visit() {
    SELECTION_SCOPE_VISITS.with(|visits| visits.set(visits.get().saturating_add(1)));
}
