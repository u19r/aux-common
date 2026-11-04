use super::operation::ValidatedEnqueue;
use crate::{
    codec::{ValueCodec, ValueTag, encode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError, ValidationError},
    keys,
    model::{JobPolicySnapshot, JobRecordV1, JobState, NewJob, PayloadManifest},
    store::{JobStore, Mutation, StoreKey},
    time::Timestamp,
};

impl ValidatedEnqueue<'_> {
    pub(super) fn build_state<S: JobStore>(
        &self,
        system: &JobSystem<S>,
    ) -> JobResult<(JobRecordV1, Vec<Mutation>), S::Error> {
        let chunk_capacity = payload_chunk_capacity(system)?;
        let (chunk_keys, mut mutations) = build_payload_chunks(system, &self.job, chunk_capacity)?;
        let record = self.build_record(system, chunk_keys)?;
        record.append_enqueue_indexes(&mut mutations)?;
        Ok((record, mutations))
    }
}

fn payload_chunk_capacity<S: JobStore>(system: &JobSystem<S>) -> JobResult<usize, S::Error> {
    let capacity = system
        .store()
        .capabilities()
        .max_value_bytes()
        .get()
        .checked_sub(6)
        .ok_or(JobSystemError::StoreContract(
            crate::error::StoreContractError::CapabilityExceeded("payload chunk bytes"),
        ))?;
    Ok(capacity)
}

fn build_payload_chunks<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    chunk_capacity: usize,
) -> JobResult<(Vec<StoreKey>, Vec<Mutation>), S::Error> {
    if chunk_capacity == 0 && !job.payload.is_empty() {
        return Err(JobSystemError::StoreContract(
            crate::error::StoreContractError::CapabilityExceeded("payload chunk bytes"),
        ));
    }
    let mut chunk_keys = Vec::new();
    let mut mutations = Vec::new();
    for (index, chunk) in job.payload.chunks(chunk_capacity.max(1)).enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            JobSystemError::Validation(ValidationError::Overflow {
                field: "payload chunk index",
            })
        })?;
        let key = keys::payload_key(system.namespace(), &job.job_id, index)?;
        let value = ValueCodec::encode(ValueTag::PayloadChunk, chunk)?;
        chunk_keys.push(key.clone());
        mutations.push(Mutation::Put(key, value));
    }
    Ok((chunk_keys, mutations))
}

impl ValidatedEnqueue<'_> {
    fn build_payload_manifest(
        &self,
        chunk_keys: Vec<StoreKey>,
    ) -> Result<PayloadManifest, ValidationError> {
        let total_length =
            u32::try_from(self.job.payload.len()).map_err(|_| ValidationError::TooLong {
                field: "payload",
                maximum: crate::model::MAX_INLINE_PAYLOAD_BYTES,
                actual: self.job.payload.len(),
            })?;
        PayloadManifest::try_new(total_length, self.digest, chunk_keys)
    }

    fn derive_retention_deadline(
        &self,
        policy: &JobPolicySnapshot,
    ) -> Result<Timestamp, ValidationError> {
        match self.job.expires_at {
            Some(expiry) => Ok(expiry.max(self.now)),
            None => self
                .job
                .scheduled_at
                .max(self.now)
                .checked_add(policy.retry_policy.maximum_age()),
        }
    }

    fn build_record<S: JobStore>(
        &self,
        system: &JobSystem<S>,
        chunk_keys: Vec<StoreKey>,
    ) -> JobResult<JobRecordV1, S::Error> {
        let job = &self.job;
        let policy = self.registration.policy_with_retry(job.retry_override);
        let execution_id =
            crate::ids::ExecutionId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
        let payload = self.build_payload_manifest(chunk_keys)?;
        let retention_deadline = self.derive_retention_deadline(&policy)?;
        Ok(JobRecordV1 {
            job_id: job.job_id,
            namespace: system.namespace().clone(),
            queue: self.registration.queue().clone(),
            kind: job.kind.clone(),
            schema_version: job.schema_version,
            generation: 0,
            execution_id,
            payload,
            fairness: job.fairness.clone(),
            ordering_key: job.ordering_key.clone(),
            priority: job.priority,
            created_at: self.now,
            scheduled_at: job.scheduled_at,
            expires_at: job.expires_at,
            policy,
            attempts: None,
            state: JobState::Scheduled,
            checkpoint: None,
            retention_deadline,
            deduplication: job.deduplication.clone(),
            revision: 0,
        })
    }
}

impl JobRecordV1 {
    fn append_enqueue_indexes(
        &self,
        mutations: &mut Vec<Mutation>,
    ) -> Result<(), crate::error::StoreDataError> {
        mutations.push(Mutation::Put(
            keys::job_key(&self.namespace, &self.job_id)?,
            encode_job_record(self)?,
        ));
        mutations.push(Mutation::Put(
            keys::due_key(
                &self.namespace,
                &self.queue,
                self.scheduled_at,
                &self.job_id,
            )?,
            keys::due_value(self.scheduled_at)?,
        ));
        mutations.push(Mutation::Put(
            keys::fair_key(&self.namespace, &self.queue, &self.job_id)?,
            keys::fair_value(&self.job_id)?,
        ));
        Ok(())
    }
}
