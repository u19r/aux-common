//! Suspension removes scheduling indexes while preserving the logical
//! execution.

use bytes::Bytes;

use super::{
    cancellation::{ScheduledInactivation, inactivate_scheduled},
    repository::{JobOperation, load_job, load_job_operation},
};
use crate::{
    codec::encode_job_record,
    engine::JobSystem,
    error::{JobResult, JobSystemError},
    ids::JobId,
    keys,
    model::JobState,
    store::{Check, JobStore, Mutation, StoreTransaction},
    transition::{
        checked_transaction, commit_record_without_claim, fresh_operation, next_revision,
        wake_mutation,
    },
};

pub(crate) async fn suspend_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<(), S::Error> {
    let (_, encoded, record) = load_job(system, job_id).await?;
    match record.state {
        JobState::Scheduled => {
            inactivate_scheduled(system, record, encoded, ScheduledInactivation::Suspend).await
        }
        JobState::Suspended => Ok(()),
        JobState::Leased(_) | JobState::DeadLettered | JobState::Cancelled => {
            Err(JobSystemError::LeaseConflict)
        }
    }
}

pub(crate) async fn resume_job<S: JobStore>(
    system: &JobSystem<S>,
    job_id: JobId,
) -> JobResult<(), S::Error> {
    let mut authority = load_job_operation(system, job_id).await?;
    match authority.record.state {
        JobState::Suspended => {}
        JobState::Scheduled => return Ok(()),
        JobState::Leased(_) | JobState::DeadLettered | JobState::Cancelled => {
            return Err(JobSystemError::LeaseConflict);
        }
    }
    authority.record.state = JobState::Scheduled;
    authority.record.revision = next_revision(system, &authority.record)?;
    let encoded = encode_job_record(&authority.record)?;
    let transaction = authority.resume_transaction(system, &encoded).await?;
    commit_record_without_claim(system, transaction, &job_id, &authority.encoded, &encoded).await?;
    system.observe(crate::observer::JobEvent::Resumed {
        queue: authority.record.queue,
    });
    Ok(())
}

impl JobOperation {
    async fn resume_transaction<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        encoded: &Bytes,
    ) -> JobResult<StoreTransaction, S::Error> {
        let record = &self.record;
        let due = keys::due_key(
            system.namespace(),
            &record.queue,
            record.scheduled_at,
            &record.job_id,
        )?;
        let fair = keys::fair_key(system.namespace(), &record.queue, &record.job_id)?;
        let mut mutations = self.resume_mutations(system, encoded, &due)?;
        let mut checks = self.resume_checks(system, due.clone(), fair)?;
        if let Some(check) =
            wake_mutation(system, &record.queue, None, Some(&due), &mut mutations).await?
        {
            checks.push(check);
        }
        checked_transaction(system, checks, mutations)
    }

    fn resume_checks<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        due: crate::store::StoreKey,
        fair: crate::store::StoreKey,
    ) -> JobResult<Vec<Check>, S::Error> {
        Ok(vec![
            Check::Value(self.job_key.clone(), self.encoded.clone()),
            Check::Absent(due),
            Check::Absent(fair),
            Check::Absent(keys::cancellation_key(
                system.namespace(),
                &self.record.job_id,
            )?),
            match &self.operation_value {
                Some(value) => Check::Value(self.operation_key.clone(), value.clone()),
                None => Check::Absent(self.operation_key.clone()),
            },
        ])
    }

    fn resume_mutations<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        encoded: &Bytes,
        due: &crate::store::StoreKey,
    ) -> JobResult<Vec<Mutation>, S::Error> {
        let record = &self.record;
        let (_, _, fence_high_water) = self.active_operation()?;
        let operation = fresh_operation(system)?;
        Ok(vec![
            Mutation::Put(self.job_key.clone(), encoded.clone()),
            Mutation::Put(due.clone(), keys::due_value(record.scheduled_at)?),
            Mutation::Put(
                keys::fair_key(system.namespace(), &record.queue, &record.job_id)?,
                keys::fair_value(&record.job_id)?,
            ),
            Mutation::Put(
                self.operation_key.clone(),
                keys::operation_value(&record.job_id, &operation, fence_high_water)?,
            ),
        ])
    }
}
