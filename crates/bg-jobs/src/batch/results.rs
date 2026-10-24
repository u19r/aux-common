//! Per-item batch result application and ordering barriers.

use std::collections::HashMap;

use super::{compatibility::BatchItem, formation::Batch};
use crate::{
    ids::{AttemptId, JobId},
    model::JobOutcome,
};

/// One result returned by a batch handler.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchResult {
    pub attempt_id: AttemptId,
    pub outcome: JobOutcome,
}

/// Per-item result application, preserving the item's own authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchApplication {
    /// One resolution for each item in the source batch, in batch order.
    pub resolutions: Vec<BatchItemResolution>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchItemResolution {
    pub job_id: JobId,
    pub attempt_id: AttemptId,
    pub outcome: BatchOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BatchOutcome {
    Provided(JobOutcome),
    RetryInvariant,
    MissingResult,
    DeferredOrdering,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BatchResultError {
    UnknownAttempt,
    DuplicateAttemptId,
}

impl Batch {
    /// Applies exactly one result to each item. Missing and duplicate results
    /// become retries for only the affected item; no sibling result is guessed.
    pub fn apply_results(
        &self,
        results: &[BatchResult],
    ) -> Result<BatchApplication, BatchResultError> {
        let by_attempt = attempt_indexes(&self.items)?;
        let mut resolutions = missing_resolutions(&self.items);
        for result in results {
            let Some(&index) = by_attempt.get(&result.attempt_id) else {
                return Err(BatchResultError::UnknownAttempt);
            };
            resolutions[index].outcome = match resolutions[index].outcome {
                BatchOutcome::Provided(_) => BatchOutcome::RetryInvariant,
                BatchOutcome::RetryInvariant => BatchOutcome::RetryInvariant,
                BatchOutcome::MissingResult => BatchOutcome::Provided(result.outcome.clone()),
                BatchOutcome::DeferredOrdering => BatchOutcome::RetryInvariant,
            };
        }
        apply_ordering_barrier(&self.items, &mut resolutions);
        Ok(BatchApplication { resolutions })
    }
}

fn attempt_indexes(items: &[BatchItem]) -> Result<HashMap<AttemptId, usize>, BatchResultError> {
    let mut indexes = HashMap::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if indexes.insert(item.attempt_id, index).is_some() {
            return Err(BatchResultError::DuplicateAttemptId);
        }
    }
    Ok(indexes)
}

fn missing_resolutions(items: &[BatchItem]) -> Vec<BatchItemResolution> {
    items
        .iter()
        .map(|item| BatchItemResolution {
            job_id: item.job_id,
            attempt_id: item.attempt_id,
            outcome: BatchOutcome::MissingResult,
        })
        .collect()
}

fn apply_ordering_barrier(items: &[BatchItem], resolutions: &mut [BatchItemResolution]) {
    let mut ordered = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        if let Some(key) = &item.ordering_key {
            ordered.push((key, item.ordering_position, index));
        }
    }
    ordered.sort_unstable_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(&right.1)));
    let mut group_start = 0;
    while group_start < ordered.len() {
        let key = ordered[group_start].0;
        let mut group_end = group_start + 1;
        while group_end < ordered.len() && ordered[group_end].0 == key {
            group_end += 1;
        }
        let mut unresolved = false;
        for (_, _, index) in &ordered[group_start..group_end] {
            if unresolved {
                resolutions[*index].outcome = BatchOutcome::DeferredOrdering;
            } else if !outcome_is_terminal(&resolutions[*index].outcome) {
                unresolved = true;
            }
        }
        group_start = group_end;
    }
}

fn outcome_is_terminal(outcome: &BatchOutcome) -> bool {
    match outcome {
        BatchOutcome::Provided(JobOutcome::Complete(_))
        | BatchOutcome::Provided(JobOutcome::DeadLetter { .. })
        | BatchOutcome::Provided(JobOutcome::Cancelled) => true,
        BatchOutcome::Provided(JobOutcome::Continue { .. })
        | BatchOutcome::Provided(JobOutcome::Retry { .. })
        | BatchOutcome::RetryInvariant
        | BatchOutcome::MissingResult
        | BatchOutcome::DeferredOrdering => false,
    }
}
