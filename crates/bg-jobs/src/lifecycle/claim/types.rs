//! Claim authority and claim-side lifecycle orchestration.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI64, Ordering},
};

use bytes::Bytes;

use crate::{
    error::ValidationError,
    ids::{AttemptId, OperationId},
    model::{CancellationToken, ExecutionContext, ExecutionContextInput, JobRecordV1, JobState},
    store::StoreKey,
    time::{MonotonicDeadline, Timestamp},
};

/// A claimed job and the immutable payload loaded for one handler invocation.
pub struct ClaimedJob {
    pub(in crate::lifecycle::claim) record: JobRecordV1,
    pub(in crate::lifecycle::claim) encoded: Bytes,
    pub(in crate::lifecycle::claim) payload: Bytes,
    pub(in crate::lifecycle::claim) due_key: Option<StoreKey>,
    pub(in crate::lifecycle::claim) fair_key: StoreKey,
    pub(in crate::lifecycle::claim) lease_key: StoreKey,
    pub(in crate::lifecycle::claim) permit_keys: Vec<StoreKey>,
    pub(in crate::lifecycle::claim) attempt_id: AttemptId,
    pub(in crate::lifecycle::claim) operation_id: OperationId,
    pub(in crate::lifecycle::claim) fence_high_water: u64,
    pub(in crate::lifecycle::claim) cancellation: CancellationToken,
    pub(in crate::lifecycle::claim) authority_lost: AtomicBool,
    pub(in crate::lifecycle::claim) poll_work_found: AtomicBool,
    pub(in crate::lifecycle::claim) last_heartbeat: Arc<AtomicI64>,
    pub(crate) execution_deadline: Option<Timestamp>,
}

impl ClaimedJob {
    pub fn record(&self) -> &JobRecordV1 {
        &self.record
    }

    pub(crate) fn record_mut(&mut self) -> &mut JobRecordV1 {
        &mut self.record
    }

    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    pub const fn attempt_id(&self) -> AttemptId {
        self.attempt_id
    }

    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    pub const fn fence_high_water(&self) -> u64 {
        self.fence_high_water
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }

    pub fn authority(&self) -> Option<crate::transition::TransitionAuthority> {
        match &self.record.state {
            JobState::Leased(lease) => Some(crate::transition::TransitionAuthority {
                owner: lease.owner,
                token: lease.token,
                generation: self.record.generation,
                fence: lease.fence,
            }),
            _ => None,
        }
    }

    pub(crate) fn encoded(&self) -> &Bytes {
        &self.encoded
    }

    pub(crate) fn due_key(&self) -> Option<&StoreKey> {
        self.due_key.as_ref()
    }

    pub(crate) fn fair_key(&self) -> &StoreKey {
        &self.fair_key
    }

    pub(crate) fn lease_key(&self) -> &StoreKey {
        &self.lease_key
    }

    pub(crate) fn permit_keys(&self) -> &[StoreKey] {
        &self.permit_keys
    }

    pub(crate) fn last_heartbeat(&self) -> &AtomicI64 {
        &self.last_heartbeat
    }

    pub(crate) fn replace_encoded_authority(&mut self, encoded: Bytes, operation_id: OperationId) {
        self.encoded = encoded;
        self.operation_id = operation_id;
    }

    pub(crate) fn lose_authority(&self) {
        self.authority_lost.store(true, Ordering::Release);
        self.cancellation.cancel();
    }

    pub(crate) fn authority_lost(&self) -> bool {
        self.authority_lost.load(Ordering::Acquire)
    }

    pub(crate) fn lease_at(&self, now: Timestamp) -> Option<&crate::model::Lease> {
        match &self.record.state {
            JobState::Leased(lease) if lease.expires_at > now => Some(lease),
            _ => None,
        }
    }

    pub fn context(&self) -> Option<ExecutionContext<'_>> {
        self.context_with_deadline(MonotonicDeadline::ZERO)
    }

    pub(crate) fn context_with_deadline(
        &self,
        deadline: MonotonicDeadline,
    ) -> Option<ExecutionContext<'_>> {
        if self.authority_lost() {
            return None;
        }
        let lease = match &self.record.state {
            JobState::Leased(lease) => lease,
            _ => return None,
        };
        let attempts = self.record.attempts.as_ref()?;
        Some(ExecutionContext::with_cancellation(
            ExecutionContextInput {
                job_id: self.record.job_id,
                namespace: &self.record.namespace,
                execution_id: self.record.execution_id,
                attempt_id: self.attempt_id,
                attempt: attempts.attempts,
                generation: self.record.generation,
                fence: lease.fence,
                token: &lease.token,
                owner: lease.owner,
                queue: &self.record.queue,
                wall_now: attempts.last_attempt_at,
                deadline,
                cancelled: false,
                operation_id: self.operation_id,
                checkpoint: self.record.checkpoint.as_deref(),
                poll_work_found: &self.poll_work_found,
                payload: &self.payload,
            },
            self.cancellation.clone(),
        ))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ClaimDeadline<'a> {
    pub(crate) until: Timestamp,
    pub(crate) wall_now: &'a (dyn Fn() -> Result<Timestamp, ValidationError> + Send + Sync),
}

pub(crate) struct ClaimRecordInput<'a> {
    pub(crate) record: JobRecordV1,
    pub(crate) encoded: Bytes,
    pub(crate) route: ClaimRoute,
    pub(crate) now: Timestamp,
    pub(crate) capacity: std::num::NonZeroU16,
    pub(crate) deadline: Option<ClaimDeadline<'a>>,
}

#[derive(Clone)]
pub(crate) enum ClaimRoute {
    Due { key: StoreKey, value: Bytes },
    ExpiredLease { key: StoreKey, value: Bytes },
}

impl ClaimRoute {
    pub(super) fn key(&self) -> &StoreKey {
        match self {
            Self::Due { key, .. } | Self::ExpiredLease { key, .. } => key,
        }
    }

    pub(super) fn value(&self) -> &Bytes {
        match self {
            Self::Due { value, .. } | Self::ExpiredLease { value, .. } => value,
        }
    }

    pub(super) const fn removes_route(&self) -> bool {
        matches!(self, Self::Due { .. })
    }

    pub(super) const fn replaces_permits(&self) -> bool {
        matches!(self, Self::ExpiredLease { .. })
    }
}

pub(super) struct ClaimTransactionInput<'a> {
    pub(super) record: &'a JobRecordV1,
    pub(super) encoded: &'a Bytes,
    pub(super) route: ClaimRoute,
    pub(super) new_encoded: Bytes,
    pub(super) operation_id: OperationId,
    pub(super) permit_keys: Vec<StoreKey>,
    pub(super) existing_permit_value: Option<Bytes>,
}
