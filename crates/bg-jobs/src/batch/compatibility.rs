//! Registration-owned batch compatibility and claimed item shapes.

#[cfg(any(test, feature = "test-support"))]
use std::{num::NonZeroU16, time::Duration};

#[cfg(any(test, feature = "test-support"))]
use bytes::Bytes;

#[cfg(any(test, feature = "test-support"))]
use crate::{
    ids::JobKind,
    ids::{AttemptId, ExecutionId, JobId, OrderingKey},
    policy::{EffectMode, FairnessClass, Priority, RetryPolicy},
    time::Timestamp,
};

/// Registration-owned opaque batch compatibility identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct BatchKey(u64);

impl BatchKey {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Registration-owned opaque authorisation configuration identity.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct AuthConfigId(u64);

impl AuthConfigId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Immutable fields that must match before two jobs can share a batch.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchCompatibility {
    pub handler_kind: JobKind,
    pub schema_version: NonZeroU16,
    pub batch_key: BatchKey,
    pub auth_config: AuthConfigId,
    pub effect_mode: EffectMode,
    pub retry_policy: RetryPolicy,
    pub timeout: Duration,
    pub priority: Priority,
    pub fairness: FairnessClass,
}

/// One individually claimed item retained by a bounded batch.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchItem {
    pub job_id: JobId,
    pub execution_id: ExecutionId,
    pub attempt_id: AttemptId,
    pub payload: Bytes,
    pub compatibility: BatchCompatibility,
    pub ordering_key: Option<OrderingKey>,
    pub ordering_position: u64,
    pub enqueued_at: Timestamp,
    pub batch_deadline: Timestamp,
}
