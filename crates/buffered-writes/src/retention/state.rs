use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    time::Instant,
};

use crate::{
    batch::{AdmittedRecord, SealedBatch},
    configuration::{BatchId, FencingToken, OperationId, TenantScope},
};

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct OpenRecordEntry {
    pub record: AdmittedRecord,
    pub reserved_bytes: usize,
    pub watermark: u64,
    pub leased_fence: Option<FencingToken>,
    pub lease_expires_at_ms: i64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct SealedBatchEntry {
    pub batch: SealedBatch,
    pub completed_operations: BTreeSet<OperationId>,
    pub fencing_token: FencingToken,
    pub lease_expires_at_ms: Option<i64>,
    pub next_retry_at_ms: i64,
    pub retry_scheduled_at_ms: i64,
    #[serde(skip)]
    pub created_mono: Option<Instant>,
}

impl SealedBatchEntry {
    pub(super) fn validate_lease(
        &self,
        fence: FencingToken,
        now_utc_ms: i64,
    ) -> Result<(), crate::BufferError> {
        if self.fencing_token != fence || !self.is_leased_at(now_utc_ms) {
            return Err(crate::BufferError::StaleFence {
                generation: fence.generation(),
            });
        }
        Ok(())
    }

    pub(crate) fn pending_operation_ids(&self) -> Vec<OperationId> {
        self.batch
            .operation_ids()
            .iter()
            .filter(|op_id| !self.completed_operations.contains(*op_id))
            .cloned()
            .collect()
    }

    pub(crate) fn unsettled_record_count(&self) -> usize {
        self.batch.records().len()
    }

    pub(crate) fn retry_is_due(&self, now_utc_ms: i64) -> bool {
        crate::batch::retry_is_due(
            self.retry_scheduled_at_ms,
            self.next_retry_at_ms,
            now_utc_ms,
        )
    }

    pub(crate) fn is_leased_at(&self, now_utc_ms: i64) -> bool {
        self.lease_expires_at_ms
            .is_some_and(|expires| expires > now_utc_ms)
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoredAdmissionReceipt {
    pub status: crate::AdmissionStatus,
    pub scope: TenantScope,
    pub codec_version: String,
    pub payload_digest: [u8; 32],
    pub watermark: u64,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct RetentionState {
    pub next_watermark: u64,
    pub next_generation: u64,
    pub open_records: VecDeque<OpenRecordEntry>,
    pub sealed_batches: BTreeMap<BatchId, SealedBatchEntry>,
    pub admission_receipts: BTreeMap<OperationId, StoredAdmissionReceipt>,
    pub completed_receipt_order: VecDeque<OperationId>,
    pub quarantined_records: usize,
    pub quarantined_items: BTreeMap<OperationId, AdmittedRecord>,
    pub quarantined_batches: BTreeMap<BatchId, SealedBatchEntry>,
}

#[cfg(any(feature = "disk", feature = "valkey"))]
impl RetentionState {
    pub(crate) fn validate_recovery(
        &self,
        namespace: &crate::Namespace,
    ) -> Result<(), crate::BufferError> {
        for (id, entry) in self.sealed_batches.iter().chain(&self.quarantined_batches) {
            if entry.batch.namespace() != namespace
                || *id != entry.batch.batch_id()
                || entry
                    .completed_operations
                    .iter()
                    .any(|id| !entry.batch.operation_ids().contains(id))
            {
                return Err(crate::BufferError::CorruptStorage {
                    reason: "invalid persisted batch ownership",
                });
            }
        }
        Ok(())
    }
}
