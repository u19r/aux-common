use bytes::Bytes;

use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    failure::{OutcomeResult, dead_letter_claim},
    keys,
    lifecycle::ClaimedJob,
    model::JobState,
    observer::AttemptBucket,
    policy::{OutcomeCode, RetryClass},
    store::JobStore,
    time::Timestamp,
    transition::{
        code, commit_record, current_lease, fresh_operation, jitter_duration, next_revision,
        scheduled_transaction,
    },
};

pub(crate) async fn continue_claim<S: JobStore>(
    system: &JobSystem<S>,
    mut claim: ClaimedJob,
    not_before: Timestamp,
    checkpoint: Bytes,
    now: Timestamp,
) -> JobResult<OutcomeResult, S::Error> {
    claim.record().validate_continuation_schedule(not_before)?;
    if claim
        .record()
        .expires_at
        .is_some_and(|expiry| not_before.max(now) >= expiry)
    {
        return dead_letter_claim(system, claim, ExhaustionReason::Age.outcome_code()?, now).await;
    }
    if let Err(error) = current_lease(system, &claim, now) {
        claim.lose_authority();
        return Err(error);
    }
    let not_before = not_before.max(claim.record().scheduled_at);
    let retention_deadline = match claim.record().expires_at {
        Some(_) => claim.record().retention_deadline,
        None => not_before
            .max(now)
            .checked_add(claim.record().policy.retry_policy.maximum_age())?,
    };
    {
        let record = claim.record_mut();
        record.state = JobState::Scheduled;
        record.scheduled_at = not_before;
        record.checkpoint = Some(checkpoint);
        record.attempts = None;
        record.retention_deadline = retention_deadline;
    }
    let queue = claim.record().queue.clone();
    let kind = claim.record().kind.clone();
    commit_scheduled_transition(system, claim).await?;
    system.observe(crate::observer::JobEvent::Continued { queue, kind });
    Ok(OutcomeResult::Continued { not_before })
}

impl crate::model::JobRecordV1 {
    fn validate_continuation_schedule<E>(
        &self,
        not_before: Timestamp,
    ) -> Result<(), crate::error::JobSystemError<E>> {
        let claimed_at = self
            .attempts
            .as_ref()
            .ok_or(JobSystemError::LeaseLost)?
            .last_attempt_at;
        if not_before < claimed_at {
            return Err(JobSystemError::Validation(
                crate::error::ValidationError::Ordering {
                    field: "continuation schedule",
                },
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExhaustionReason {
    Age,
    Attempts,
}

impl ExhaustionReason {
    fn outcome_code(self) -> Result<OutcomeCode, crate::error::ValidationError> {
        code(match self {
            Self::Age => "age_exhausted",
            Self::Attempts => "attempts_exhausted",
        })
    }
}

fn exhaustion_reason(claim: &ClaimedJob, now: Timestamp) -> Option<ExhaustionReason> {
    let attempts = claim.record().attempts.as_ref()?;
    let policy = claim.record().policy.retry_policy;
    if now >= claim.record().retention_deadline
        || now
            .duration_since(attempts.first_attempt_at)
            .is_ok_and(|age| age >= policy.maximum_age())
    {
        return Some(ExhaustionReason::Age);
    }
    if claim.record().has_exhausted_attempts() {
        return Some(ExhaustionReason::Attempts);
    }
    None
}

async fn commit_scheduled_transition<S: JobStore>(
    system: &JobSystem<S>,
    mut claim: ClaimedJob,
) -> JobResult<(), S::Error> {
    let revision = next_revision(system, claim.record())?;
    claim.record_mut().revision = revision;
    let operation_id = fresh_operation(system)?;
    let new_encoded = encode_job_record(claim.record())?;
    let due_key = keys::due_key(
        system.namespace(),
        &claim.record().queue,
        claim.record().scheduled_at,
        &claim.record().job_id,
    )?;
    let transaction = scheduled_transaction(
        system,
        &claim,
        claim.record(),
        &new_encoded,
        operation_id,
        due_key,
    )
    .await?;
    commit_record(system, transaction, &claim, &new_encoded).await
}

pub(crate) async fn retry_claim<S: JobStore>(
    system: &JobSystem<S>,
    mut claim: ClaimedJob,
    class: RetryClass,
    hint: Option<Timestamp>,
    outcome_code: OutcomeCode,
    now: Timestamp,
) -> JobResult<OutcomeResult, S::Error> {
    let attempt = claim
        .record()
        .attempts
        .as_ref()
        .ok_or(JobSystemError::LeaseLost)?
        .attempts
        .get();
    if let Some(reason) = exhaustion_reason(&claim, now) {
        return dead_letter_claim(system, claim, reason.outcome_code()?, now).await;
    }
    let (_attempt, not_before) = retry_timing(system, &claim, hint, now)?;
    if claim
        .record()
        .expires_at
        .is_some_and(|expiry| not_before >= expiry)
    {
        let exhausted = code("age_exhausted")?;
        return dead_letter_claim(system, claim, exhausted, now).await;
    }
    prepare_retry_record(&mut claim, now, not_before, outcome_code);
    let queue = claim.record().queue.clone();
    let attempt = AttemptBucket::from_attempt(attempt);
    commit_scheduled_transition(system, claim).await?;
    system.observe(crate::observer::JobEvent::Retried {
        queue,
        class,
        attempt,
    });
    Ok(OutcomeResult::Retried { class, not_before })
}

fn prepare_retry_record(
    claim: &mut ClaimedJob,
    now: Timestamp,
    not_before: Timestamp,
    outcome_code: OutcomeCode,
) {
    let record = claim.record_mut();
    if let Some(attempts) = &mut record.attempts {
        attempts.last_attempt_at = now;
        attempts.last_outcome = Some(outcome_code);
    }
    record.state = JobState::Scheduled;
    record.scheduled_at = not_before;
}

fn retry_timing<S: JobStore>(
    _system: &JobSystem<S>,
    claim: &ClaimedJob,
    hint: Option<Timestamp>,
    now: Timestamp,
) -> JobResult<(std::num::NonZeroU16, Timestamp), S::Error> {
    let attempts = claim
        .record()
        .attempts
        .as_ref()
        .ok_or(JobSystemError::LeaseLost)?;
    let attempt_u16 = u16::try_from(attempts.attempts.get()).unwrap_or(u16::MAX);
    let attempt = std::num::NonZeroU16::new(attempt_u16.max(1)).ok_or(JobSystemError::LeaseLost)?;
    let cap = claim.record().policy.retry_policy.backoff_cap(attempt);
    let jitter = jitter_duration(&claim.record().execution_id, attempt, now, cap);
    let mut not_before = now.checked_add(jitter)?.max(claim.record().scheduled_at);
    if let Some(hint) = hint.filter(|hint| *hint > now) {
        let capped = now.checked_add(cap)?;
        not_before = hint.min(capped).max(not_before);
    }
    Ok((attempt, not_before))
}
