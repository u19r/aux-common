use std::{collections::BTreeSet, time::Instant};

use super::state::{RetentionState, SealedBatchEntry};
use crate::{
    buffer::{
        BufferClaimRequest, BufferRenewRequest, BufferSealAction, BufferSealRequest, ClaimedWork,
        LeasedSealedBatch, OpenBatchCandidate,
    },
    configuration::{FencingToken, OperationId},
    error::BufferError,
};
impl RetentionState {
    #[cfg(feature = "valkey")]
    pub(crate) fn next_active_lease_expiry(&self, now: i64) -> Option<i64> {
        self.open_records
            .iter()
            .filter(|entry| entry.leased_fence.is_some())
            .map(|entry| entry.lease_expires_at_ms)
            .chain(
                self.sealed_batches
                    .values()
                    .filter_map(|entry| entry.lease_expires_at_ms),
            )
            .filter(|expiry| *expiry > now)
            .min()
    }

    pub(crate) fn claim_work(&mut self, request: BufferClaimRequest) -> ClaimedWork {
        self.expire_open_leases(request.now_utc_ms);
        let lease_ms = i64::try_from(request.lease_duration.as_millis()).unwrap_or(i64::MAX);
        let lease_until = request.now_utc_ms.saturating_add(lease_ms);

        let due_batch_id = self
            .sealed_batches
            .iter()
            .filter(|(_, entry)| {
                !entry.is_leased_at(request.now_utc_ms)
                    && (request.force_all_ages || entry.retry_is_due(request.now_utc_ms))
            })
            .min_by_key(|(_, entry)| entry.batch.first_item_time_ms())
            .map(|(id, _)| *id);

        if let Some(batch_id) = due_batch_id {
            let fence = self.allocate_fence();
            if let Some(entry) = self.sealed_batches.get_mut(&batch_id) {
                entry.fencing_token = fence;
                entry.lease_expires_at_ms = Some(lease_until);
                return ClaimedWork::ExistingSealed(LeasedSealedBatch {
                    batch: entry.batch.clone(),
                    pending_operation_ids: entry.pending_operation_ids(),
                    fencing_token: fence,
                    unsettled_record_count: entry.unsettled_record_count(),
                });
            }
        }
        if !request.allow_open_claim && !request.force_all_ages {
            return ClaimedWork::None;
        }
        self.claim_open_candidate(&request, lease_until)
    }

    pub(crate) fn seal_candidate(
        &mut self,
        request: BufferSealRequest,
        now_mono: Option<Instant>,
        namespace: &crate::Namespace,
    ) -> Result<Option<LeasedSealedBatch>, BufferError> {
        self.expire_open_leases(request.now_utc_ms);
        if !self
            .open_records
            .iter()
            .any(|e| e.leased_fence == Some(request.fencing_token))
        {
            return Err(BufferError::StaleFence {
                generation: request.fencing_token.generation(),
            });
        }
        self.check_seal_capacity(&request, namespace)?;
        match request.action {
            BufferSealAction::ReleaseCandidate => {
                self.release_candidate_fence(request.fencing_token);
                Ok(None)
            }
            BufferSealAction::QuarantineSingleton {
                operation_id,
                reason: _,
            } => {
                self.quarantine_singleton(operation_id, request.fencing_token)?;
                Ok(None)
            }
            BufferSealAction::InstallBatch(batch) => {
                let sealed_ids: BTreeSet<&OperationId> =
                    batch.records().iter().map(|r| &r.operation_id).collect();
                self.open_records.retain(|e| {
                    !(e.leased_fence == Some(request.fencing_token)
                        && sealed_ids.contains(&e.record.operation_id))
                });
                self.release_candidate_fence(request.fencing_token);
                let lease_ms =
                    i64::try_from(request.lease_duration.as_millis()).unwrap_or(i64::MAX);
                let lease_until = request.now_utc_ms.saturating_add(lease_ms);
                let pending_ids = batch.operation_ids().to_vec();
                let record_count = batch.records().len();
                self.sealed_batches.insert(
                    batch.batch_id(),
                    SealedBatchEntry {
                        batch: batch.clone(),
                        completed_operations: BTreeSet::new(),
                        fencing_token: request.fencing_token,
                        lease_expires_at_ms: Some(lease_until),
                        next_retry_at_ms: request.now_utc_ms,
                        retry_scheduled_at_ms: request.now_utc_ms,
                        created_mono: now_mono,
                    },
                );
                Ok(Some(LeasedSealedBatch {
                    batch,
                    pending_operation_ids: pending_ids,
                    fencing_token: request.fencing_token,
                    unsettled_record_count: record_count,
                }))
            }
        }
    }

    fn quarantine_singleton(
        &mut self,
        operation_id: OperationId,
        fence: FencingToken,
    ) -> Result<(), BufferError> {
        let index = self
            .open_records
            .iter()
            .position(|entry| {
                entry.leased_fence == Some(fence) && entry.record.operation_id == operation_id
            })
            .ok_or(BufferError::BatchNotFound)?;
        let entry = self
            .open_records
            .remove(index)
            .ok_or(BufferError::BatchNotFound)?;
        self.quarantined_items.insert(operation_id, entry.record);
        self.release_candidate_fence(fence);
        Ok(())
    }

    pub(crate) fn renew_lease(&mut self, request: BufferRenewRequest) -> Result<(), BufferError> {
        let Some(entry) = self.sealed_batches.get_mut(&request.batch_id) else {
            return Err(BufferError::BatchNotFound);
        };
        entry.validate_lease(request.fencing_token, request.now_utc_ms)?;
        let lease_ms = i64::try_from(request.lease_duration.as_millis()).unwrap_or(i64::MAX);
        entry.lease_expires_at_ms = Some(request.now_utc_ms.saturating_add(lease_ms));
        Ok(())
    }

    pub(super) fn release_candidate_fence(&mut self, fence: FencingToken) {
        for entry in &mut self.open_records {
            if entry.leased_fence == Some(fence) {
                entry.leased_fence = None;
            }
        }
    }
    pub(super) fn claim_open_candidate(
        &mut self,
        request: &BufferClaimRequest,
        lease_until: i64,
    ) -> ClaimedWork {
        let target_scope = self.find_open_scope(request.max_watermark);
        let Some(scope) = target_scope else {
            return ClaimedWork::None;
        };
        let fence = self.allocate_fence();
        let mut selected = Vec::new();
        let mut reserved_bytes = Vec::new();
        let mut bytes = 0usize;
        for entry in &mut self.open_records {
            if entry.leased_fence.is_some()
                || entry.record.scope != scope
                || request.max_watermark.is_some_and(|wm| entry.watermark > wm)
            {
                continue;
            }
            let record_bytes = entry.record.payload.len();
            if selected.len() >= request.max_items
                || (!selected.is_empty() && bytes.saturating_add(record_bytes) > request.max_bytes)
            {
                break;
            }
            bytes = bytes.saturating_add(record_bytes);
            entry.leased_fence = Some(fence);
            entry.lease_expires_at_ms = lease_until;
            selected.push(entry.record.clone());
            reserved_bytes.push(entry.accounted_bytes());
        }
        if selected.is_empty() {
            return ClaimedWork::None;
        }
        ClaimedWork::OpenCandidate(OpenBatchCandidate {
            records: selected,
            reserved_bytes,
            fencing_token: fence,
        })
    }
    fn find_open_scope(
        &self,
        max_watermark: Option<u64>,
    ) -> Option<crate::configuration::TenantScope> {
        self.open_records
            .iter()
            .find(|entry| {
                entry.leased_fence.is_none() && max_watermark.is_none_or(|wm| entry.watermark <= wm)
            })
            .map(|entry| entry.record.scope.clone())
    }
}
