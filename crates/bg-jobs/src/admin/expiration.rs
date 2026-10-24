use bytes::Bytes;

use super::repository::{LeaseMarkers, load_job, load_lease_markers, load_scheduled_markers};
use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    failure::ExpiryResult,
    ids::{JobId, OperationId},
    keys,
    model::{JobRecordV1, JobState},
    policy::OutcomeCode,
    store::{Check, JobStore, Mutation, StoreKey},
    time::Timestamp,
    transition::{
        checked_transaction, commit_record_without_claim, fresh_operation, next_revision,
        wake_mutation,
    },
};

/// Applies the expiration policy to one job and returns only after its
/// transition is known to have committed.
pub(crate) async fn expire_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
    now: Timestamp,
) -> JobResult<ExpiryResult, S::Error> {
    let (_, encoded, record) = load_job(system, job_id).await?;
    let expired =
        record.expires_at.is_some_and(|expiry| expiry <= now) || record.retention_deadline <= now;
    match record.state.clone() {
        JobState::Leased(lease) if lease.expires_at <= now => {
            LeaseExpiration::load(system, encoded, record, now)
                .await?
                .commit(system)
                .await
        }
        JobState::Scheduled if expired => expire_scheduled(system, encoded, record, now).await,
        JobState::Scheduled
        | JobState::Leased(_)
        | JobState::DeadLettered
        | JobState::Cancelled
        | JobState::Suspended => Ok(ExpiryResult::Unchanged),
    }
}

async fn expire_scheduled<S: JobStore>(
    system: &JobSystem<S>,
    encoded: Bytes,
    mut record: JobRecordV1,
    now: Timestamp,
) -> JobResult<ExpiryResult, S::Error> {
    let (transaction, new_encoded) =
        expired_transaction(system, &encoded, &mut record, now).await?;
    commit_record_without_claim(system, transaction, &record.job_id, &encoded, &new_encoded)
        .await?;
    system.observe(crate::observer::JobEvent::DeadLettered {
        queue: record.queue,
        outcome: OutcomeCode::try_new("expired").map_err(JobSystemError::Validation)?,
    });
    Ok(ExpiryResult::DeadLettered)
}

// Expiration is control-plane recovery of an exact durable snapshot. An
// expired worker cannot acknowledge cancellation, so the expiry transaction
// consumes its canonical marker instead of rescheduling cancelled work.
enum LeaseRecovery {
    Retry(StoreKey),
    Cancelled(Bytes),
    DeadLettered { key: StoreKey, code: OutcomeCode },
}

impl LeaseRecovery {
    async fn load<S: JobStore>(
        system: &JobSystem<S>,
        record: &JobRecordV1,
        now: Timestamp,
    ) -> JobResult<Self, S::Error> {
        let cancellation = system
            .store()
            .get(keys::cancellation_key(system.namespace(), &record.job_id)?)
            .await
            .map_err(JobSystemError::Store)?;
        if let Some(marker) = cancellation {
            keys::validate_empty_marker(&marker, crate::codec::ValueTag::Cancellation)
                .map_err(|_| JobSystemError::PayloadCorrupt)?;
            return Ok(Self::Cancelled(marker));
        }
        if let Some(code) = exhaustion_code(record, now) {
            return Ok(Self::DeadLettered {
                key: keys::dead_letter_key(system.namespace(), &record.queue, &record.job_id)?,
                code: OutcomeCode::try_new(code)?,
            });
        }
        Ok(Self::Retry(keys::due_key(
            system.namespace(),
            &record.queue,
            now,
            &record.job_id,
        )?))
    }

    fn prepare_record(&self, record: &mut JobRecordV1, now: Timestamp) {
        match self {
            Self::Retry(_) => {
                record.state = JobState::Scheduled;
                record.scheduled_at = now;
            }
            Self::Cancelled(_) => record.state = JobState::Cancelled,
            Self::DeadLettered { code, .. } => {
                record.state = JobState::DeadLettered;
                if let Some(attempts) = &mut record.attempts {
                    attempts.last_attempt_at = now;
                    attempts.last_outcome = Some(code.clone());
                }
            }
        }
    }

    fn mutations(
        &self,
        record: &JobRecordV1,
        fair_key: &StoreKey,
        cancellation_key: &StoreKey,
    ) -> Result<Vec<Mutation>, crate::error::StoreDataError> {
        Ok(match self {
            Self::Retry(due_key) => vec![
                Mutation::Put(due_key.clone(), keys::due_value(record.scheduled_at)?),
                Mutation::Put(fair_key.clone(), keys::fair_value(&record.job_id)?),
            ],
            Self::Cancelled(_) => vec![
                Mutation::Delete(fair_key.clone()),
                Mutation::Delete(cancellation_key.clone()),
            ],
            Self::DeadLettered { key, .. } => vec![
                Mutation::Delete(fair_key.clone()),
                Mutation::Put(key.clone(), keys::dead_letter_value(&record.job_id)?),
            ],
        })
    }

    fn cancellation_check(&self, key: &StoreKey) -> Check {
        match self {
            Self::Cancelled(marker) => Check::Value(key.clone(), marker.clone()),
            Self::Retry(_) | Self::DeadLettered { .. } => Check::Absent(key.clone()),
        }
    }

    fn next_due(&self) -> Option<&StoreKey> {
        match self {
            Self::Retry(key) => Some(key),
            Self::Cancelled(_) | Self::DeadLettered { .. } => None,
        }
    }

    fn result<S: JobStore>(&self, system: &JobSystem<S>, record: &JobRecordV1) -> ExpiryResult {
        match self {
            Self::Retry(_) => ExpiryResult::LeaseExpired,
            Self::Cancelled(_) => {
                system.observe(crate::observer::JobEvent::Cancelled {
                    queue: record.queue.clone(),
                });
                ExpiryResult::Cancelled
            }
            Self::DeadLettered { code, .. } => {
                system.observe(crate::observer::JobEvent::DeadLettered {
                    queue: record.queue.clone(),
                    outcome: code.clone(),
                });
                ExpiryResult::DeadLettered
            }
        }
    }
}

fn exhaustion_code(record: &JobRecordV1, now: Timestamp) -> Option<&'static str> {
    if record.expires_at.is_some_and(|expiry| expiry <= now) || record.retention_deadline <= now {
        Some("expired")
    } else if record.has_exhausted_attempts() {
        Some("attempts_exhausted")
    } else {
        None
    }
}

struct LeaseExpiration {
    job_key: StoreKey,
    old_encoded: Bytes,
    record: JobRecordV1,
    new_encoded: Bytes,
    markers: LeaseMarkers,
    new_operation: OperationId,
    permit_keys: Vec<StoreKey>,
    permit_value: Bytes,
    fair_key: StoreKey,
    cancellation_key: StoreKey,
    recovery: LeaseRecovery,
}

impl LeaseExpiration {
    async fn load<S: JobStore>(
        system: &JobSystem<S>,
        old_encoded: Bytes,
        mut record: JobRecordV1,
        now: Timestamp,
    ) -> JobResult<Self, S::Error> {
        let recovery = LeaseRecovery::load(system, &record, now).await?;
        let permit_keys = crate::fairness::find_owned_permit_keys(system, &record).await?;
        let permit_value = keys::permit_value_for_record(&record)?;
        let markers = load_lease_markers(system, &record.queue, record.job_id).await?;
        recovery.prepare_record(&mut record, now);
        record.revision = next_revision(system, &record)?;
        Ok(Self {
            job_key: keys::job_key(system.namespace(), &record.job_id)?,
            old_encoded,
            new_encoded: encode_job_record(&record)?,
            fair_key: keys::fair_key(system.namespace(), &record.queue, &record.job_id)?,
            cancellation_key: keys::cancellation_key(system.namespace(), &record.job_id)?,
            record,
            markers,
            new_operation: fresh_operation(system)?,
            permit_keys,
            permit_value,
            recovery,
        })
    }

    fn mutations(&self) -> Result<Vec<Mutation>, crate::error::StoreDataError> {
        let mut mutations = vec![
            Mutation::Put(self.job_key.clone(), self.new_encoded.clone()),
            Mutation::Delete(self.markers.lease_key.clone()),
            Mutation::Put(
                self.markers.operation_key.clone(),
                keys::operation_value(
                    &self.record.job_id,
                    &self.new_operation,
                    self.markers.fence_high_water,
                )?,
            ),
        ];
        mutations.extend(self.recovery.mutations(
            &self.record,
            &self.fair_key,
            &self.cancellation_key,
        )?);
        mutations.extend(self.permit_keys.iter().cloned().map(Mutation::Delete));
        Ok(mutations)
    }

    fn checks(&self) -> Vec<Check> {
        let mut checks = vec![
            Check::Value(self.job_key.clone(), self.old_encoded.clone()),
            Check::Value(
                self.markers.lease_key.clone(),
                self.markers.lease_value.clone(),
            ),
            Check::Value(
                self.markers.operation_key.clone(),
                self.markers.operation_value.clone(),
            ),
            self.recovery.cancellation_check(&self.cancellation_key),
        ];
        checks.extend(
            self.permit_keys
                .iter()
                .cloned()
                .map(|key| Check::Value(key, self.permit_value.clone())),
        );
        checks
    }

    async fn commit<S: JobStore>(self, system: &JobSystem<S>) -> JobResult<ExpiryResult, S::Error> {
        let mut mutations = self.mutations()?;
        let wake_check = wake_mutation(
            system,
            &self.record.queue,
            None,
            self.recovery.next_due(),
            &mut mutations,
        )
        .await?;
        let mut checks = self.checks();
        if let Some(wake_check) = wake_check {
            checks.push(wake_check);
        }
        let transaction = checked_transaction(system, checks, mutations)?;
        commit_record_without_claim(
            system,
            transaction,
            &self.record.job_id,
            &self.old_encoded,
            &self.new_encoded,
        )
        .await?;
        Ok(self.recovery.result(system, &self.record))
    }
}

fn prepare_expired<S: JobStore>(
    system: &JobSystem<S>,
    record: &mut JobRecordV1,
    now: Timestamp,
) -> JobResult<(Bytes, OperationId), S::Error> {
    record.state = JobState::DeadLettered;
    record.revision = next_revision(system, record)?;
    let outcome =
        crate::policy::OutcomeCode::try_new("expired").map_err(JobSystemError::Validation)?;
    if let Some(attempts) = &mut record.attempts {
        attempts.last_attempt_at = now;
        attempts.last_outcome = Some(outcome);
    }
    let operation = fresh_operation(system)?;
    let new_encoded = encode_job_record(record)?;
    Ok((new_encoded, operation))
}

async fn expired_transaction<S: JobStore>(
    system: &JobSystem<S>,
    encoded: &Bytes,
    record: &mut JobRecordV1,
    now: Timestamp,
) -> JobResult<(crate::store::StoreTransaction, Bytes), S::Error> {
    let (due_key, fair_key, markers) = load_scheduled_markers(system, record).await?;
    let job_id = record.job_id;
    let job_key = keys::job_key(system.namespace(), &job_id)?;
    let (new_encoded, operation) = prepare_expired(system, record, now)?;
    let dlq_key = keys::dead_letter_key(system.namespace(), &record.queue, &job_id)?;
    let mut mutations = vec![
        Mutation::Put(job_key.clone(), new_encoded.clone()),
        Mutation::Delete(due_key.clone()),
        Mutation::Delete(fair_key.clone()),
        Mutation::Put(dlq_key, keys::dead_letter_value(&job_id)?),
        Mutation::Put(
            keys::operation_key(system.namespace(), &job_id)?,
            keys::operation_value(&job_id, &operation, markers.fence_high_water)?,
        ),
    ];
    let wake_check =
        wake_mutation(system, &record.queue, Some(&due_key), None, &mut mutations).await?;
    let operation_key = keys::operation_key(system.namespace(), &job_id)?;
    let mut checks = vec![
        Check::Value(job_key, encoded.clone()),
        Check::Value(due_key, markers.due_value),
        Check::Value(fair_key, markers.fair_value),
        Check::Absent(keys::cancellation_key(system.namespace(), &job_id)?),
    ];
    checks.push(match markers.operation_value {
        Some(value) => Check::Value(operation_key, value),
        None => Check::Absent(operation_key),
    });
    if let Some(wake_check) = wake_check {
        checks.push(wake_check);
    }
    Ok((checked_transaction(system, checks, mutations)?, new_encoded))
}
