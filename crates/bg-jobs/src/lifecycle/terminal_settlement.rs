//! Explicit retirement after the caller durably reconciles terminal work.

use crate::{
    engine::JobSystem,
    error::{JobResult, JobSystemError, StoreDataError},
    keys,
    model::{JobRecordV1, JobState, JobTerminalAuthority},
    store::{Check, JobStore, Mutation, StoreKey},
    transition::{self, TransitionConflict},
};

impl<S: JobStore> JobSystem<S> {
    /// Deletes a cancelled or dead-lettered job after durable business
    /// reconciliation. Redrive or any snapshot change rejects settlement.
    /// Missing state alone never authorizes a successful business outcome.
    pub async fn settle_terminal(
        &self,
        authority: JobTerminalAuthority,
    ) -> JobResult<(), S::Error> {
        let (job_key, encoded) = authority.into_snapshot();
        let record = crate::codec::decode_job_record(&encoded)?;
        super::validate_persisted_identity(self, record.job_id, &record)?;
        if job_key != keys::job_key(self.namespace(), &record.job_id)? {
            return Err(JobSystemError::PayloadCorrupt);
        }
        match record.state {
            JobState::Cancelled | JobState::DeadLettered => {}
            JobState::Scheduled | JobState::Leased(_) | JobState::Suspended => {
                return Err(JobSystemError::LeaseLost);
            }
        }
        let due_key = keys::due_key(
            self.namespace(),
            &record.queue,
            record.scheduled_at,
            &record.job_id,
        )?;
        let mut mutations = record.build_retirement_mutations(job_key.clone(), due_key.clone())?;
        let mut checks = vec![Check::Value(job_key, encoded)];
        if let Some(check) =
            transition::wake_mutation(self, &record.queue, Some(&due_key), None, &mut mutations)
                .await?
        {
            checks.push(check);
        }
        let transaction = transition::checked_transaction(self, checks, mutations)?;
        self.commit_terminal_transition(transaction, TransitionConflict::LeaseLost)
            .await
    }
}

impl JobRecordV1 {
    fn build_retirement_mutations(
        &self,
        job_key: StoreKey,
        due_key: StoreKey,
    ) -> Result<Vec<Mutation>, StoreDataError> {
        let namespace = &self.namespace;
        let job_id = &self.job_id;
        let queue = &self.queue;
        let mut mutations = self
            .payload
            .chunk_keys
            .iter()
            .cloned()
            .map(Mutation::Delete)
            .collect::<Vec<_>>();
        mutations.extend(
            [
                job_key,
                keys::operation_key(namespace, job_id)?,
                keys::cancellation_key(namespace, job_id)?,
                keys::dead_letter_key(namespace, queue, job_id)?,
                keys::fair_key(namespace, queue, job_id)?,
                keys::lease_key(namespace, queue, job_id)?,
                due_key,
            ]
            .map(Mutation::Delete),
        );
        Ok(mutations)
    }
}
