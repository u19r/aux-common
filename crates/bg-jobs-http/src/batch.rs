use std::{collections::HashMap, fmt, future::Future, pin::Pin, time::SystemTime};

use bg_jobs::{AttemptId, ExecutionId, JobOutcome, Timestamp};
use http::{HeaderMap, StatusCode};

use crate::{HttpClassification, HttpJobError, HttpRequest, classify_status};

/// One individually claimed item presented to a batch handler.
#[derive(Clone, Copy)]
pub struct BatchItemContext<'a> {
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub request: &'a HttpRequest,
}

impl fmt::Debug for BatchItemContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItemContext")
            .field("execution_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("request", &"[REDACTED]")
            .finish()
    }
}

/// A response carrying one HTTP status per attempt.
#[derive(Clone, PartialEq, Eq)]
pub struct BatchItemResponse {
    pub attempt_id: AttemptId,
    pub status: StatusCode,
    pub headers: HeaderMap,
}

impl fmt::Debug for BatchItemResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItemResponse")
            .field("attempt_id", &"[REDACTED]")
            .field("status", &self.status)
            .field("header_count", &self.headers.len())
            .finish()
    }
}

/// A standard batch protocol can report item results or one status for all
/// items. The latter is applied independently and never invents a partial
/// success.
#[derive(Clone, PartialEq, Eq)]
pub enum BatchResponse {
    PerItem(Vec<BatchItemResponse>),
    BatchWide {
        status: StatusCode,
        headers: HeaderMap,
    },
}

impl fmt::Debug for BatchResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerItem(items) => formatter
                .debug_struct("BatchResponse")
                .field("kind", &"per_item")
                .field("item_count", &items.len())
                .finish(),
            Self::BatchWide { status, headers } => formatter
                .debug_struct("BatchResponse")
                .field("kind", &"batch_wide")
                .field("status", status)
                .field("header_count", &headers.len())
                .finish(),
        }
    }
}

/// One per-item durable outcome keyed by its own attempt identity.
#[derive(Clone, PartialEq, Eq)]
pub struct BatchItemOutcome {
    pub attempt_id: AttemptId,
    pub outcome: JobOutcome,
}

impl fmt::Debug for BatchItemOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchItemOutcome")
            .field("attempt_id", &"[REDACTED]")
            .field("outcome", &self.outcome)
            .finish()
    }
}

/// Validated one-to-one result set for a batch.
#[derive(Clone, PartialEq, Eq)]
pub struct BatchResultSet {
    outcomes: Vec<BatchItemOutcome>,
}

impl fmt::Debug for BatchResultSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BatchResultSet")
            .field("outcome_count", &self.outcomes.len())
            .finish()
    }
}

impl BatchResultSet {
    pub fn from_response(
        items: &[BatchItemContext<'_>],
        response: BatchResponse,
        limits: BatchClassificationLimits,
        now: SystemTime,
        outcome_now: Timestamp,
    ) -> Result<Self, HttpJobError> {
        let classifications = classify_batch_response(items, response, limits, now)?;
        let outcomes = into_outcomes(classifications, outcome_now)?;
        Ok(Self { outcomes })
    }

    pub fn outcomes(&self) -> &[BatchItemOutcome] {
        &self.outcomes
    }

    pub fn into_outcomes(self) -> Vec<BatchItemOutcome> {
        self.outcomes
    }
}

fn classify_batch_response(
    items: &[BatchItemContext<'_>],
    response: BatchResponse,
    limits: BatchClassificationLimits,
    now: SystemTime,
) -> Result<Vec<(AttemptId, HttpClassification)>, HttpJobError> {
    match response {
        BatchResponse::PerItem(responses) => classify_items(items, responses, limits, now),
        BatchResponse::BatchWide { status, headers } => Ok(items
            .iter()
            .map(|item| {
                (
                    item.attempt_id,
                    classify_status(
                        status,
                        &headers,
                        limits.retry_after_max,
                        limits.retry_after_fallback,
                        now,
                    ),
                )
            })
            .collect()),
    }
}

fn into_outcomes(
    classifications: Vec<(AttemptId, HttpClassification)>,
    now: Timestamp,
) -> Result<Vec<BatchItemOutcome>, HttpJobError> {
    classifications
        .into_iter()
        .map(|(attempt_id, classification)| {
            classification
                .to_job_outcome(now)
                .map(|outcome| BatchItemOutcome {
                    attempt_id,
                    outcome,
                })
                .map_err(HttpJobError::Validation)
        })
        .collect()
}

/// Bounds used to classify every item without retaining a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchClassificationLimits {
    pub retry_after_max: std::time::Duration,
    pub retry_after_fallback: std::time::Duration,
}

/// A typed batch handler contract. Implementations return one result per
/// active attempt; the validator below turns omissions and duplicates into
/// retries only for the affected item.
pub trait BatchJobHandler: Send + Sync + 'static {
    fn execute<'a>(&'a self, items: &'a [BatchItemContext<'a>]) -> BatchHandlerFuture<'a>;
}

pub type BatchHandlerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BatchResultSet, BatchHandlerError>> + Send + 'a>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchHandlerError {
    RequestRejected,
    TransportFailure,
    ResponseInvariant,
}

fn classify_items(
    items: &[BatchItemContext<'_>],
    responses: Vec<BatchItemResponse>,
    limits: BatchClassificationLimits,
    now: SystemTime,
) -> Result<Vec<(AttemptId, HttpClassification)>, HttpJobError> {
    let results = classify_responses(items, responses, limits, now)?;
    Ok(items
        .iter()
        .map(|item| {
            let classification = match results.get(&item.attempt_id).copied().flatten() {
                Some(classification) => classification,
                None => invariant_retry(),
            };
            (item.attempt_id, classification)
        })
        .collect())
}

fn classify_responses(
    items: &[BatchItemContext<'_>],
    responses: Vec<BatchItemResponse>,
    limits: BatchClassificationLimits,
    now: SystemTime,
) -> Result<HashMap<AttemptId, Option<HttpClassification>>, HttpJobError> {
    let mut results = HashMap::with_capacity(items.len());
    for item in items {
        if results.insert(item.attempt_id, None).is_some() {
            return Err(HttpJobError::BatchInvariant);
        }
    }
    for response in responses {
        let Some(result) = results.get_mut(&response.attempt_id) else {
            return Err(HttpJobError::BatchInvariant);
        };
        let classification = classify_status(
            response.status,
            &response.headers,
            limits.retry_after_max,
            limits.retry_after_fallback,
            now,
        );
        *result = Some(match *result {
            Some(_) => invariant_retry(),
            None => classification,
        });
    }
    Ok(results)
}

fn invariant_retry() -> HttpClassification {
    HttpClassification::retry_invariant()
}
