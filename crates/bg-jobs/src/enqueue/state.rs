use super::authority::PriorFenceAuthority;
use crate::{
    codec::{ValueCodec, ValueTag, encode_job_record},
    engine::JobSystem,
    error::{JobResult, JobSystemError, ValidationError},
    keys,
    model::{JobPolicySnapshot, JobRecordV1, JobState, NewJob, PayloadManifest},
    store::{JobStore, Mutation, StoreKey},
    time::Timestamp,
};

pub(super) fn build_enqueue_state<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    registration: &crate::registry::HandlerRegistration,
    digest: [u8; 32],
    now: Timestamp,
    prior_fence: Option<&PriorFenceAuthority>,
) -> JobResult<(JobRecordV1, Vec<Mutation>), S::Error> {
    let chunk_capacity = payload_chunk_capacity(system)?;
    let (chunk_keys, mut mutations) = build_payload_chunks(system, job, chunk_capacity)?;
    let record = build_job_record(system, job, registration, digest, now, chunk_keys)?;
    append_enqueue_indexes(
        system,
        job,
        registration,
        &record,
        &mut mutations,
        prior_fence,
    )?;
    Ok((record, mutations))
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

fn build_job_record<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    registration: &crate::registry::HandlerRegistration,
    digest: [u8; 32],
    now: Timestamp,
    chunk_keys: Vec<StoreKey>,
) -> JobResult<JobRecordV1, S::Error> {
    let policy = build_policy(job, registration);
    let execution_id =
        crate::ids::ExecutionId::generate().map_err(|_| JobSystemError::EntropyUnavailable)?;
    let total_length = u32::try_from(job.payload.len()).map_err(|_| {
        JobSystemError::Validation(ValidationError::TooLong {
            field: "payload",
            maximum: crate::model::MAX_INLINE_PAYLOAD_BYTES,
            actual: job.payload.len(),
        })
    })?;
    let payload = PayloadManifest::try_new(total_length, digest, chunk_keys)?;
    scheduled_record(
        system,
        job,
        registration,
        now,
        policy,
        execution_id,
        payload,
    )
}

pub(super) fn build_policy(
    job: &NewJob,
    registration: &crate::registry::HandlerRegistration,
) -> JobPolicySnapshot {
    JobPolicySnapshot {
        effect_mode: registration.effect_mode(),
        cost_units: registration.cost_units(),
        execution_timeout: Some(registration.default_timeout()),
        retry_policy: job
            .retry_override
            .unwrap_or(registration.default_retry())
            .into(),
    }
}

fn scheduled_record<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    registration: &crate::registry::HandlerRegistration,
    now: Timestamp,
    policy: JobPolicySnapshot,
    execution_id: crate::ids::ExecutionId,
    payload: PayloadManifest,
) -> JobResult<JobRecordV1, S::Error> {
    let retention_deadline = match job.expires_at {
        Some(expiry) => expiry.max(now),
        None => job
            .scheduled_at
            .max(now)
            .checked_add(policy.retry_policy.maximum_age())?,
    };
    Ok(JobRecordV1 {
        job_id: job.job_id,
        namespace: system.namespace().clone(),
        queue: registration.queue().clone(),
        kind: job.kind.clone(),
        schema_version: job.schema_version,
        generation: 0,
        execution_id,
        payload,
        fairness: job.fairness.clone(),
        ordering_key: job.ordering_key.clone(),
        priority: job.priority,
        created_at: now,
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

fn append_enqueue_indexes<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    registration: &crate::registry::HandlerRegistration,
    record: &JobRecordV1,
    mutations: &mut Vec<Mutation>,
    prior_fence: Option<&PriorFenceAuthority>,
) -> JobResult<(), S::Error> {
    mutations.push(Mutation::Put(
        keys::job_key(system.namespace(), &job.job_id)?,
        encode_job_record(record)?,
    ));
    append_due_and_fair_indexes(system, job, registration, mutations)?;
    if let Some(prior_fence) = prior_fence {
        mutations.push(Mutation::Put(
            keys::operation_key(system.namespace(), &job.job_id)?,
            keys::operation_watermark_value(&job.job_id, prior_fence.fence_high_water)?,
        ));
    }
    append_dedupe_index(system, job, mutations)
}

fn append_due_and_fair_indexes<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    registration: &crate::registry::HandlerRegistration,
    mutations: &mut Vec<Mutation>,
) -> JobResult<(), S::Error> {
    mutations.push(Mutation::Put(
        keys::due_key(
            system.namespace(),
            registration.queue(),
            job.scheduled_at,
            &job.job_id,
        )?,
        keys::due_value(job.scheduled_at)?,
    ));
    mutations.push(Mutation::Put(
        keys::fair_key(system.namespace(), registration.queue(), &job.job_id)?,
        keys::fair_value(&job.job_id)?,
    ));
    Ok(())
}

fn append_dedupe_index<S: JobStore>(
    system: &JobSystem<S>,
    job: &NewJob,
    mutations: &mut Vec<Mutation>,
) -> JobResult<(), S::Error> {
    let Some(deduplication) = &job.deduplication else {
        return Ok(());
    };
    mutations.push(Mutation::Put(
        keys::dedupe_key(system.namespace(), deduplication.key())?,
        keys::dedupe_value(&job.job_id, deduplication.retain_until())?,
    ));
    Ok(())
}
