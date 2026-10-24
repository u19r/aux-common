//! Internal values shared by fair-candidate selection passes.

use crate::{
    fairness::{FairCandidate, FairPermitGeneration, FairScope, FairnessRejection},
    ids::JobId,
    policy::Priority,
    time::Timestamp,
};

pub(in crate::fairness::fairness_ledger::admission) struct CandidateSelection {
    pub(in crate::fairness::fairness_ledger::admission) job_id: JobId,
    pub(in crate::fairness::fairness_ledger::admission) scope: FairScope,
    pub(in crate::fairness::fairness_ledger::admission) primary: Option<FairScope>,
    pub(in crate::fairness::fairness_ledger::admission) priority: Priority,
    pub(in crate::fairness::fairness_ledger::admission) cost_units: std::num::NonZeroU16,
    pub(in crate::fairness::fairness_ledger::admission) ordering_key:
        Option<crate::ids::OrderingKey>,
    pub(in crate::fairness::fairness_ledger::admission) ordering_position: u64,
    pub(in crate::fairness::fairness_ledger::admission) acquisition_generation:
        FairPermitGeneration,
}

pub(super) struct ValidatedCandidate<'a> {
    pub(super) candidate: &'a FairCandidate,
    pub(super) acquisition_generation: FairPermitGeneration,
}

pub(super) struct SelectionMetrics {
    pub(super) primary_index: usize,
    pub(super) primary_service: u128,
    pub(super) admission_service: u128,
    pub(super) child_service: u128,
    pub(super) child_service_lag: u128,
    pub(super) primary_candidate_count: u32,
}

#[derive(Clone, Copy)]
pub(super) struct CandidateFacts {
    pub(super) scheduled_at: Timestamp,
    pub(super) priority: Priority,
    pub(super) cost_units: std::num::NonZeroU16,
    pub(super) low_volume: bool,
}

pub(super) struct CandidatePreparation {
    pub(super) facts: CandidateFacts,
    pub(super) metrics: SelectionMetrics,
}

pub(super) struct PreparedCandidate {
    pub(super) job_id: JobId,
    pub(super) ready: bool,
    pub(super) due: bool,
    pub(super) preparation: Result<CandidatePreparation, FairnessRejection>,
}

#[derive(Default)]
pub(super) struct PrimaryStats {
    pub(super) candidate_count: u32,
    pub(super) eligible: bool,
    pub(super) normalized_service: u128,
    pub(super) child_minimum: Option<u128>,
}

#[derive(Default)]
pub(super) struct ServiceExtrema {
    // There is one entry per eligible primary. The second extrema preserve
    // the exclusion semantics when the candidate owns a tied minimum/maximum.
    pub(super) count: usize,
    pub(super) min: Option<(usize, u128)>,
    pub(super) second_min: Option<u128>,
    pub(super) max: Option<(usize, u128)>,
    pub(super) second_max: Option<u128>,
}

impl ServiceExtrema {
    pub(super) fn insert(&mut self, primary_index: usize, service: u128) {
        self.count = self.count.saturating_add(1);
        match self.min {
            None => self.min = Some((primary_index, service)),
            Some((_, min_service)) if service < min_service => {
                self.second_min = Some(min_service);
                self.min = Some((primary_index, service));
            }
            Some(_) => {
                self.second_min = match self.second_min {
                    None => Some(service),
                    Some(second_min) if service < second_min => Some(service),
                    Some(second_min) => Some(second_min),
                };
            }
        }
        match self.max {
            None => self.max = Some((primary_index, service)),
            Some((_, max_service)) if service > max_service => {
                self.second_max = Some(max_service);
                self.max = Some((primary_index, service));
            }
            Some(_) => {
                self.second_max = match self.second_max {
                    None => Some(service),
                    Some(second_max) if service > second_max => Some(service),
                    Some(second_max) => Some(second_max),
                };
            }
        }
    }

    pub(super) fn allows(&self, primary_index: usize, service: u128, bound: u128) -> bool {
        if self.count <= 1 {
            return true;
        }
        let minimum = match self.min {
            Some((index, value)) if index != primary_index => Some(value),
            Some(_) => self.second_min,
            None => None,
        };
        let maximum = match self.max {
            Some((index, value)) if index != primary_index => Some(value),
            Some(_) => self.second_max,
            None => None,
        };
        minimum.is_none_or(|value| service.abs_diff(value) <= bound)
            && maximum.is_none_or(|value| service.abs_diff(value) <= bound)
    }
}

pub(super) struct SelectionPass {
    pub(super) candidates: Vec<PreparedCandidate>,
    pub(super) service_extrema: ServiceExtrema,
}

pub(super) fn next_permit_generation(
    previous: Option<FairPermitGeneration>,
) -> Result<FairPermitGeneration, FairnessRejection> {
    previous
        .map_or(
            Some(FairPermitGeneration::FIRST),
            FairPermitGeneration::next,
        )
        .ok_or(FairnessRejection::PermitGenerationExhausted)
}
