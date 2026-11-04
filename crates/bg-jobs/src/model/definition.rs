use std::num::NonZeroU16;

use crate::{
    ids::{JobId, JobKind, Namespace, OrderingKey, QueueName},
    model::{JobPolicySnapshot, JobRecordV1},
    policy::{Deduplication, FairnessClass, Priority},
    time::Timestamp,
};

/// Immutable enqueue identity, excluding the schedule that a controller can
/// change. The current catalog retains its bounded digest after payload
/// cleanup.
#[derive(PartialEq, Eq)]
pub(crate) struct JobDefinition<'a> {
    pub job_id: JobId,
    pub namespace: &'a Namespace,
    pub queue: &'a QueueName,
    pub kind: &'a JobKind,
    pub schema_version: NonZeroU16,
    pub payload_length: u32,
    pub payload_digest: [u8; 32],
    pub fairness: &'a FairnessClass,
    pub ordering_key: Option<&'a OrderingKey>,
    pub priority: Priority,
    pub expires_at: Option<Timestamp>,
    pub policy: JobPolicySnapshot,
    pub deduplication: Option<&'a Deduplication>,
}

impl<'a> JobDefinition<'a> {
    pub(crate) fn try_from_request(
        job: &'a super::NewJob,
        namespace: &'a Namespace,
        registration: &'a crate::registry::HandlerRegistration,
        payload_digest: [u8; 32],
    ) -> Result<Self, crate::error::StoreDataError> {
        Ok(Self {
            job_id: job.job_id,
            namespace,
            queue: registration.queue(),
            kind: &job.kind,
            schema_version: job.schema_version,
            payload_length: u32::try_from(job.payload.len())
                .map_err(|_| crate::error::StoreDataError::LengthOverflow)?,
            payload_digest,
            fairness: &job.fairness,
            ordering_key: job.ordering_key.as_ref(),
            priority: job.priority,
            expires_at: job.expires_at,
            policy: registration.policy_with_retry(job.retry_override),
            deduplication: job.deduplication.as_ref(),
        })
    }
}

impl<'a> From<&'a JobRecordV1> for JobDefinition<'a> {
    fn from(record: &'a JobRecordV1) -> Self {
        Self {
            job_id: record.job_id,
            namespace: &record.namespace,
            queue: &record.queue,
            kind: &record.kind,
            schema_version: record.schema_version,
            payload_length: record.payload.total_length,
            payload_digest: record.payload.digest,
            fairness: &record.fairness,
            ordering_key: record.ordering_key.as_ref(),
            priority: record.priority,
            expires_at: record.expires_at,
            policy: record.policy,
            deduplication: record.deduplication.as_ref(),
        }
    }
}
