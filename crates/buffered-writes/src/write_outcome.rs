use std::collections::BTreeMap;

use crate::{OperationId, SinkError};

/// Per-operation outcome in a partial write response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperationStatus {
    Completed,
    Retryable { reason: &'static str },
    Permanent { reason: &'static str },
    Unknown,
}

/// Destination write outcome for a write attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteOutcome {
    Complete,
    Partial(BTreeMap<OperationId, OperationStatus>),
}

pub(crate) enum ClassifiedWriteOutcome {
    Complete,
    Incomplete(WriteFailure),
}

pub(crate) struct WriteFailure {
    pub(crate) completed_ids: Vec<OperationId>,
    pub(crate) error: SinkError,
}

impl From<SinkError> for WriteFailure {
    fn from(error: SinkError) -> Self {
        Self {
            error,
            completed_ids: Vec::new(),
        }
    }
}

impl WriteOutcome {
    /// Validate one response against exactly the operations dispatched by this
    /// attempt. Missing outcomes remain unknown; success requires the full set.
    pub(crate) fn classify(
        self,
        pending: &[OperationId],
    ) -> Result<ClassifiedWriteOutcome, SinkError> {
        let Self::Partial(outcomes) = self else {
            return Ok(ClassifiedWriteOutcome::Complete);
        };
        if outcomes.len() > pending.len() || outcomes.keys().any(|id| !pending.contains(id)) {
            return Err(SinkError::invalid_outcome("unexpected operation identity"));
        }
        let completed_ids: Vec<_> = outcomes
            .iter()
            .filter(|(_, status)| matches!(status, OperationStatus::Completed))
            .map(|(id, _)| id.clone())
            .collect();
        if completed_ids.len() == pending.len() {
            return Ok(ClassifiedWriteOutcome::Complete);
        }
        let error = Self::classify_partial_failure(&outcomes, pending.len());
        Ok(ClassifiedWriteOutcome::Incomplete(WriteFailure {
            completed_ids,
            error,
        }))
    }

    fn classify_partial_failure(
        outcomes: &BTreeMap<OperationId, OperationStatus>,
        expected: usize,
    ) -> SinkError {
        if outcomes
            .values()
            .any(|status| matches!(status, OperationStatus::Permanent { .. }))
        {
            return SinkError::permanent("partial write permanently rejected");
        }
        let unknown = outcomes.len() < expected
            || outcomes
                .values()
                .any(|status| matches!(status, OperationStatus::Unknown));
        if unknown {
            SinkError::unknown_outcome("incomplete partial write outcome")
        } else {
            SinkError::retryable("partial write requires retry")
        }
    }
}
