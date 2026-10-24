//! Durable owner state and registration metadata.

use std::{
    collections::{BTreeMap, BTreeSet},
    num::NonZeroU16,
    time::Duration,
};

use bytes::Bytes;

use super::super::state::FairnessLedger;
#[cfg(all(test, not(target_family = "wasm")))]
use crate::fairness::FairCandidateState;
use crate::{
    batch::{AuthConfigId, BatchKey},
    fairness::{FairScope, FairnessBudget},
    ids::{FairnessKey, JobId, JobKind},
    model::JobRecordV1,
    policy::{EffectMode, RetryPolicy},
    time::Timestamp,
};
#[cfg(all(test, not(target_family = "wasm")))]
use crate::{ids::OrderingKey, policy::Priority};

/// Registration-owned information used by batch compatibility. The job record
/// remains authoritative for lifecycle state and payload; this value only
/// fills batch contract fields that are opaque to the queue codec.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FairCandidateMetadata {
    pub(crate) handler_kind: JobKind,
    pub(crate) schema_version: NonZeroU16,
    pub(crate) batch_key: BatchKey,
    pub(crate) auth_config: AuthConfigId,
    pub(crate) effect_mode: EffectMode,
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) timeout: Duration,
    pub(crate) enqueued_at: Timestamp,
    pub(crate) batch_deadline: Timestamp,
}

/// Read-only candidate values needed by adapters to report actual owner state.
#[cfg(all(test, not(target_family = "wasm")))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FairCandidateSnapshot {
    pub(crate) job_id: JobId,
    pub(crate) scope: FairScope,
    pub(crate) priority: Priority,
    pub(crate) cost_units: NonZeroU16,
    pub(crate) scheduled_at: Timestamp,
    pub(crate) payload_bytes: usize,
    pub(crate) ordering_key: Option<OrderingKey>,
    pub(crate) ordering_position: u64,
    pub(crate) block: Option<crate::fairness::CandidateBlock>,
    pub(crate) state: FairCandidateState,
    pub(crate) service_transitions: u64,
}

/// The last selection metadata exposed by the fair command boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FairSelectionSnapshot {
    pub(crate) job_id: JobId,
    pub(crate) scope: FairScope,
    pub(crate) cost_units: u16,
}

#[cfg(all(test, not(target_family = "wasm")))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FairOrderSnapshot {
    pub(crate) head: u64,
    pub(crate) owner: JobId,
    pub(crate) in_flight: bool,
    pub(crate) acquisitions: u64,
    pub(crate) releases: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FairBatchItemState {
    Missing,
    Success,
    Retry,
    DeadLetter,
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FairBatchState {
    pub(crate) active: bool,
    pub(crate) scope: FairScope,
    pub(crate) auth_config: AuthConfigId,
    pub(crate) members: BTreeSet<JobId>,
    pub(crate) results: BTreeMap<JobId, FairBatchItemState>,
    pub(crate) scratch_size: usize,
    pub(crate) scratch_capacity: usize,
    pub(crate) payload_bytes: usize,
    pub(crate) formed_at: Timestamp,
    pub(crate) deadline: Timestamp,
}

impl FairBatchState {
    pub(super) fn try_default() -> Result<Self, crate::error::ValidationError> {
        Ok(Self {
            active: false,
            scope: FairScope::Scoped {
                primary: FairnessKey::try_new(b"a")?,
                secondary: None,
            },
            auth_config: AuthConfigId::new(1),
            members: BTreeSet::new(),
            results: BTreeMap::new(),
            scratch_size: 0,
            scratch_capacity: 3,
            payload_bytes: 0,
            formed_at: Timestamp::ZERO,
            deadline: Timestamp::ZERO,
        })
    }
}

impl FairCandidateMetadata {
    pub(crate) fn for_record(record: &JobRecordV1) -> Self {
        Self {
            handler_kind: record.kind.clone(),
            schema_version: record.schema_version,
            batch_key: BatchKey::new(1),
            auth_config: AuthConfigId::new(1),
            effect_mode: record.policy.effect_mode,
            retry_policy: record.policy.retry_policy,
            timeout: record.policy.execution_timeout.unwrap_or_default(),
            enqueued_at: record.created_at,
            batch_deadline: record.scheduled_at,
        }
    }
}

/// Canonical fair-dispatch state for one namespace and owner.
#[derive(Clone, Debug)]
pub(crate) struct FairDispatchOwner {
    pub(super) ledger: FairnessLedger,
    pub(super) metadata: BTreeMap<JobId, FairCandidateMetadata>,
    pub(super) batch: FairBatchState,
    pub(super) hol_escapes: u64,
    pub(super) selected: FairSelectionSnapshot,
    /// Exact durable bytes read by `load`; `None` means this owner expects an
    /// absent state because it was created before the first save.
    pub(super) loaded_value: Option<Bytes>,
}

impl FairDispatchOwner {
    pub(crate) fn try_new(budget: FairnessBudget) -> Result<Self, crate::error::ValidationError> {
        let batch = FairBatchState::try_default()?;
        Ok(Self {
            ledger: FairnessLedger::new(budget),
            metadata: BTreeMap::new(),
            selected: FairSelectionSnapshot {
                job_id: JobId::from([1; 16]),
                scope: batch.scope.clone(),
                cost_units: 0,
            },
            batch,
            hol_escapes: 0,
            loaded_value: None,
        })
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn budget(&self) -> FairnessBudget {
        self.ledger.budget()
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn ledger(&self) -> &FairnessLedger {
        &self.ledger
    }

    pub(crate) fn metadata(&self, job_id: JobId) -> Option<&FairCandidateMetadata> {
        self.metadata.get(&job_id)
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn batch(&self) -> &FairBatchState {
        &self.batch
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) const fn hol_escapes(&self) -> u64 {
        self.hol_escapes
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn selected(&self) -> FairSelectionSnapshot {
        self.selected.clone()
    }

    #[cfg(all(test, not(target_family = "wasm")))]
    pub(crate) fn restore_selected(&mut self, selected: FairSelectionSnapshot) {
        self.selected = selected;
    }
}
