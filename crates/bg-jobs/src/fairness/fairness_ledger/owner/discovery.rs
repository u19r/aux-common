//! Stable ordering assignments for authoritative discovery batches.

use std::collections::BTreeMap;

use super::state::{FairCandidateMetadata, FairDispatchOwner};
use crate::{fairness::FairCandidateInput, ids::OrderingKey};

impl FairDispatchOwner {
    /// Includes ready and leased work retained outside a partial discovery
    /// page. Terminal projections cannot constrain the current registration
    /// policy.
    pub(crate) fn active_registrations(
        &self,
    ) -> impl Iterator<Item = (&crate::fairness::FairScope, &FairCandidateMetadata)> {
        self.ledger
            .candidates
            .iter()
            .filter_map(|(job_id, record)| {
                let active = record.state.has_ready_route()
                    || record.state == crate::fairness::FairCandidateState::Leased;
                active
                    .then(|| {
                        self.metadata
                            .get(job_id)
                            .map(|metadata| (&record.candidate.scope, metadata))
                    })
                    .flatten()
            })
    }

    /// Retains ordered positions across discovery passes. New candidates join
    /// the tail without renumbering successors below a completed durable head.
    pub(crate) fn ensure_discovered_candidates(
        &mut self,
        candidates: impl IntoIterator<Item = (FairCandidateInput, FairCandidateMetadata)>,
    ) -> Result<(), crate::error::ValidationError> {
        let mut tails = self.collect_ordering_tails();
        for (mut input, metadata) in candidates {
            if let Some(key) = &input.ordering_key {
                let previous = self
                    .ledger
                    .candidates
                    .get(&input.job_id)
                    .filter(|record| record.candidate.ordering_key() == Some(key));
                input.ordering_position = match previous {
                    Some(record) => record.candidate.ordering_position(),
                    None => {
                        let tail = tails.entry(key.clone()).or_default();
                        *tail = tail.checked_add(1).ok_or(
                            crate::error::ValidationError::InvalidValue {
                                field: "ordering_position",
                            },
                        )?;
                        *tail
                    }
                };
            }
            self.ensure_candidate(input, metadata)?;
        }
        Ok(())
    }

    fn collect_ordering_tails(&self) -> BTreeMap<OrderingKey, u64> {
        let mut tails = BTreeMap::new();
        for record in self.ledger.candidates.values() {
            if let Some(key) = record.candidate.ordering_key() {
                let tail = tails.entry(key.clone()).or_insert(0);
                *tail = u64::max(*tail, record.candidate.ordering_position());
            }
        }
        tails
    }
}
