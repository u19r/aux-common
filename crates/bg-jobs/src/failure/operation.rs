//! Dispatches validated handler outcomes to their owning transitions.

use crate::{
    engine::JobSystem,
    error::JobResult,
    failure::{OutcomeResult, cancel_claim_commit, continue_claim, dead_letter_claim, retry_claim},
    lifecycle::ClaimedJob,
    model::JobOutcome,
    store::JobStore,
    time::Timestamp,
};

/// Applies one handler outcome after validating it at the lifecycle boundary.
pub(crate) async fn apply_outcome<S: JobStore>(
    system: &JobSystem<S>,
    claim: ClaimedJob,
    outcome: JobOutcome,
    now: Timestamp,
) -> JobResult<OutcomeResult, S::Error> {
    outcome.validate()?;
    match outcome {
        JobOutcome::Complete(code) => Ok(OutcomeResult::Completed(
            crate::lifecycle::complete(system, claim, JobOutcome::Complete(code), now).await?,
        )),
        JobOutcome::Continue {
            not_before,
            checkpoint,
        } => continue_claim(system, claim, not_before, checkpoint, now).await,
        JobOutcome::Retry {
            class,
            not_before,
            code,
        } => retry_claim(system, claim, class, not_before, code, now).await,
        JobOutcome::DeadLetter { code } => dead_letter_claim(system, claim, code, now).await,
        JobOutcome::Cancelled => cancel_claim_commit(system, claim, now).await,
    }
}
