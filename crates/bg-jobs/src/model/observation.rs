use std::num::NonZeroU16;

use super::{
    constants::PAYLOAD_DIGEST_BYTES,
    record::{AttemptHistory, JobPolicySnapshot, JobState, OperationReceipt},
};
use crate::{
    ids::{ExecutionId, JobId, JobKind, OperationId, OrderingKey, QueueName},
    policy::{Deduplication, FairnessClass, Priority},
    time::Timestamp,
};

/// A payload summary returned by lifecycle inspection.
///
/// The persisted manifest's store-owned chunk keys are intentionally omitted
/// from this public projection. `complete` is true only when every referenced
/// chunk is present, decodes as a payload chunk, and matches the persisted
/// length and digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecyclePayload {
    pub total_length: u32,
    pub digest: [u8; PAYLOAD_DIGEST_BYTES],
    pub chunk_count: usize,
    pub complete: bool,
}

/// The durable route presence observed alongside a live job record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LifecycleRoutes {
    pub due: bool,
    pub fair: bool,
    pub lease: bool,
    pub wake: bool,
}

/// Classification of a lifecycle record read.
///
/// `Current` observations are `Valid`; the other values are returned in an
/// [`LifecycleObservation::Invalid`] result so callers can quarantine one
/// unreadable item without treating it as an ordinary store outage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleRecordStatus {
    Valid,
    Corrupt,
    UnknownVersion,
}

/// A public lifecycle projection that does not expose persistence keys,
/// encoded values, payload bytes, or checkpoint bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LifecycleRecord {
    pub job_id: JobId,
    pub queue: QueueName,
    pub kind: JobKind,
    pub schema_version: NonZeroU16,
    pub generation: u32,
    pub execution_id: ExecutionId,
    pub payload: LifecyclePayload,
    pub fairness: FairnessClass,
    pub ordering_key: Option<OrderingKey>,
    pub priority: Priority,
    pub created_at: Timestamp,
    pub scheduled_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub policy: JobPolicySnapshot,
    pub attempts: Option<AttemptHistory>,
    pub state: JobState,
    pub checkpoint_bytes: usize,
    pub retention_deadline: Timestamp,
    pub deduplication: Option<Deduplication>,
    pub revision: u64,
}

/// Observation of one job's authoritative live record or terminal receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LifecycleObservation {
    Current {
        record: LifecycleRecord,
        operation_id: Option<OperationId>,
        routes: LifecycleRoutes,
        cancellation_requested: bool,
        status: LifecycleRecordStatus,
    },
    Terminal(OperationReceipt),
    Invalid {
        status: LifecycleRecordStatus,
        routes: LifecycleRoutes,
        /// A record can decode even when its operation marker is unknown or
        /// malformed. Preserve that public durable record so callers can
        /// quarantine it without losing state needed for reconciliation.
        record: Option<LifecycleRecord>,
    },
    Missing,
}
