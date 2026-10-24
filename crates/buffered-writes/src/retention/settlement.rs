use std::collections::btree_map::Entry;

use super::state::{RetentionState, SealedBatchEntry};
use crate::{
    buffer::{BufferSettleRequest, SettleDisposition},
    configuration::AdmissionStatus,
    error::BufferError,
};

impl RetentionState {
    pub(crate) fn settle_batch(&mut self, request: BufferSettleRequest) -> Result<(), BufferError> {
        let Entry::Occupied(occupied) = self.sealed_batches.entry(request.batch_id) else {
            return Err(BufferError::BatchNotFound);
        };
        occupied.get().validate_settlement(&request)?;
        let mut entry = occupied.remove();
        entry.schedule_retry(&request);
        match request.disposition {
            SettleDisposition::Delivered => {
                self.complete_batch_receipts(&entry.batch, AdmissionStatus::Written)
            }
            SettleDisposition::HandedOffToQueue => {
                self.complete_batch_receipts(&entry.batch, AdmissionStatus::Queued)
            }
            SettleDisposition::PartialProgress { completed_ids, .. } => {
                self.retain_partial_progress(entry, completed_ids);
            }
            SettleDisposition::ReleaseForRetry { .. } => self.retain_for_retry(entry),
            SettleDisposition::Quarantine { completed_ids, .. } => {
                entry.completed_operations.extend(completed_ids);
                self.quarantined_batches.insert(request.batch_id, entry);
            }
        }
        Ok(())
    }

    fn retain_partial_progress(
        &mut self,
        mut entry: SealedBatchEntry,
        completed_ids: Vec<crate::OperationId>,
    ) {
        entry.completed_operations.extend(completed_ids);
        if entry.pending_operation_ids().is_empty() {
            self.complete_batch_receipts(&entry.batch, AdmissionStatus::Written);
        } else {
            self.sealed_batches.insert(entry.batch.batch_id(), entry);
        }
    }

    fn retain_for_retry(&mut self, mut entry: SealedBatchEntry) {
        entry.lease_expires_at_ms = None;
        self.sealed_batches.insert(entry.batch.batch_id(), entry);
    }
}

impl SealedBatchEntry {
    fn schedule_retry(&mut self, request: &BufferSettleRequest) {
        let delay = match &request.disposition {
            SettleDisposition::PartialProgress { retry_delay, .. }
            | SettleDisposition::ReleaseForRetry { retry_delay } => retry_delay,
            SettleDisposition::Delivered
            | SettleDisposition::HandedOffToQueue
            | SettleDisposition::Quarantine { .. } => return,
        };
        self.retry_scheduled_at_ms = request.now_utc_ms;
        let millis = i64::try_from(delay.as_millis()).unwrap_or(i64::MAX);
        self.next_retry_at_ms = request.now_utc_ms.saturating_add(millis);
    }

    fn validate_settlement(&self, request: &BufferSettleRequest) -> Result<(), BufferError> {
        self.validate_lease(request.fencing_token, request.now_utc_ms)?;
        let completed_ids = match &request.disposition {
            SettleDisposition::PartialProgress { completed_ids, .. }
            | SettleDisposition::Quarantine { completed_ids, .. } => completed_ids,
            SettleDisposition::Delivered
            | SettleDisposition::HandedOffToQueue
            | SettleDisposition::ReleaseForRetry { .. } => return Ok(()),
        };
        if completed_ids.len() > self.batch.operation_ids().len()
            || completed_ids
                .iter()
                .any(|id| !self.batch.operation_ids().contains(id))
        {
            return Err(BufferError::InvalidRequest {
                reason: "completion identities exceed sealed batch membership",
            });
        }
        Ok(())
    }
}
