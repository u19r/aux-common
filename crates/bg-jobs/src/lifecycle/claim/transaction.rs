//! Atomic claim checks and mutations.

use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    keys,
    lifecycle::claim::types::ClaimTransactionInput,
    model::{AttemptHistory, JobRecordV1, JobState},
    store::{Check, JobStore, Mutation, StoreKey, StoreTransaction},
    time::Timestamp,
};

impl ClaimTransactionInput<'_> {
    pub(super) fn build_transaction<S: JobStore>(
        self,
        system: &JobSystem<S>,
    ) -> JobResult<(StoreKey, StoreKey, StoreTransaction), S::Error> {
        let (job_key, fair_key, lease_key, mut mutations) = self.build_mutations(system)?;
        let mut checks = self.build_checks(system, job_key)?;
        let next = match &self.record.state {
            JobState::Leased(lease) => lease.fence,
            _ => return Err(JobSystemError::LeaseLost),
        };
        let (check, mutation) = self.fence.advance(next);
        checks.push(check);
        mutations.push(mutation);
        let transaction = crate::transition::checked_transaction(system, checks, mutations)?;
        Ok((fair_key, lease_key, transaction))
    }

    fn build_checks<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        job_key: StoreKey,
    ) -> JobResult<Vec<Check>, S::Error> {
        let mut checks = vec![
            Check::Value(job_key, self.encoded.clone()),
            Check::Value(self.route.key().clone(), self.route.value().clone()),
        ];
        checks.extend(self.permit_keys.iter().cloned().map(
            |key| match &self.existing_permit_value {
                Some(value) => Check::Value(key, value.clone()),
                None => Check::Absent(key),
            },
        ));
        // Cancellation and claim race in the same native transaction: a
        // committed cancellation cannot hand an expired lease to a new handler.
        checks.push(Check::Absent(keys::cancellation_key(
            system.namespace(),
            &self.record.job_id,
        )?));
        Ok(checks)
    }

    fn build_mutations<S: JobStore>(
        &self,
        system: &JobSystem<S>,
    ) -> JobResult<(StoreKey, StoreKey, StoreKey, Vec<Mutation>), S::Error> {
        let record = self.record;
        let job_key = keys::job_key(system.namespace(), &record.job_id)?;
        let fair_key = keys::fair_key(system.namespace(), &record.queue, &record.job_id)?;
        let lease_key = keys::lease_key(system.namespace(), &record.queue, &record.job_id)?;
        let fence_high_water = match &record.state {
            JobState::Leased(lease) => lease.fence.get(),
            _ => return Err(JobSystemError::LeaseLost),
        };
        let mut mutations = vec![
            Mutation::Put(job_key.clone(), self.new_encoded.clone()),
            Mutation::Delete(fair_key.clone()),
            Mutation::Put(lease_key.clone(), keys::lease_value(&record.job_id)?),
            Mutation::Put(
                keys::operation_key(system.namespace(), &record.job_id)?,
                keys::operation_value(&record.job_id, &self.operation_id, fence_high_water)?,
            ),
        ];
        if self.route.removes_route() {
            mutations.push(Mutation::Delete(self.route.key().clone()));
        }
        let permit_value = keys::permit_value_for_record(record)?;
        mutations.extend(
            self.permit_keys
                .iter()
                .cloned()
                .map(|key| Mutation::Put(key, permit_value.clone())),
        );
        Ok((job_key, fair_key, lease_key, mutations))
    }
}

pub(super) fn claimable(record: &JobRecordV1, now: Timestamp) -> bool {
    match &record.state {
        JobState::Scheduled => true,
        JobState::Leased(lease) => lease.expires_at <= now,
        JobState::DeadLettered | JobState::Cancelled | JobState::Suspended => false,
    }
}

pub(super) fn next_attempt(record: &JobRecordV1, now: Timestamp) -> Result<AttemptHistory, ()> {
    let history = match &record.attempts {
        None => AttemptHistory {
            attempts: std::num::NonZeroU32::MIN,
            first_attempt_at: now,
            last_attempt_at: now,
            last_outcome: None,
        },
        Some(history) => AttemptHistory {
            attempts: history
                .attempts
                .get()
                .checked_add(1)
                .and_then(std::num::NonZeroU32::new)
                .ok_or(())?,
            first_attempt_at: history.first_attempt_at,
            last_attempt_at: now,
            last_outcome: history.last_outcome.clone(),
        },
    };
    Ok(history)
}
