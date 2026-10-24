use super::state::{RetentionState, StoredAdmissionReceipt};
use crate::{
    configuration::{OperationId, TenantScope},
    constants::{MAX_COMPLETED_OPERATION_RECEIPTS, RETENTION_ENTRY_OVERHEAD_BYTES},
};

impl StoredAdmissionReceipt {
    pub(crate) fn observation(&self, id: &OperationId) -> crate::buffer::AdmissionReceipt {
        crate::buffer::AdmissionReceipt {
            status: self.status,
            fingerprint: crate::batch::AdmissionFingerprint::from_stored_parts(
                id,
                &self.scope,
                &self.codec_version,
                &self.payload_digest,
            ),
        }
    }

    pub(super) fn is_completed(&self) -> bool {
        matches!(
            self.status,
            crate::AdmissionStatus::Written | crate::AdmissionStatus::Queued
        )
    }

    pub(super) fn verify_record(
        &self,
        record: &crate::AdmittedRecord,
        digest: [u8; 32],
    ) -> Result<(), crate::BufferError> {
        if self.payload_digest == digest
            && self.scope == record.scope
            && self.codec_version == record.codec_version
        {
            return Ok(());
        }
        Err(crate::BufferError::DuplicateIdentityConflict {
            operation_id: record.operation_id.clone(),
        })
    }

    pub(super) fn accounted_bytes(&self, id: &OperationId) -> usize {
        Self::metadata_bytes(id, &self.scope, &self.codec_version)
    }

    pub(super) fn metadata_bytes(id: &OperationId, scope: &TenantScope, codec: &str) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(id.accounted_bytes().saturating_mul(2))
            .saturating_add(scope.as_str().len())
            .saturating_add(codec.len())
            .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
    }
}

impl RetentionState {
    pub(super) fn find_admission_receipt(
        &self,
        id: &OperationId,
    ) -> Option<crate::buffer::AdmissionReceipt> {
        self.admission_receipts
            .get(id)
            .map(|receipt| receipt.observation(id))
    }

    pub(crate) fn insert_receipt(&mut self, op_id: OperationId, receipt: StoredAdmissionReceipt) {
        let was_completed = self
            .admission_receipts
            .get(&op_id)
            .is_some_and(StoredAdmissionReceipt::is_completed);
        if receipt.is_completed() && !was_completed {
            self.completed_receipt_order.push_back(op_id.clone());
        }
        self.admission_receipts.insert(op_id, receipt);
        self.trim_completed_receipts();
    }

    pub(super) fn trim_completed_receipts(&mut self) {
        while self.completed_receipt_order.len() > MAX_COMPLETED_OPERATION_RECEIPTS {
            let _ = self.evict_oldest_completed();
        }
    }

    pub(super) fn complete_batch_receipts(
        &mut self,
        batch: &crate::SealedBatch,
        status: crate::AdmissionStatus,
    ) {
        for record in batch.records() {
            if let Some(receipt) = self.admission_receipts.get_mut(&record.operation_id) {
                if !receipt.is_completed() {
                    self.completed_receipt_order
                        .push_back(record.operation_id.clone());
                }
                receipt.status = status;
            }
        }
        self.trim_completed_receipts();
    }

    pub(super) fn receipt_bytes(&self) -> usize {
        self.admission_receipts
            .iter()
            .map(|(id, receipt)| receipt.accounted_bytes(id))
            .fold(0, usize::saturating_add)
    }

    pub(super) fn completed_receipt_bytes(&self) -> usize {
        self.admission_receipts
            .iter()
            .filter(|(_, receipt)| receipt.is_completed())
            .map(|(id, receipt)| receipt.accounted_bytes(id))
            .fold(0, usize::saturating_add)
    }

    pub(super) fn reclaim_completed_receipts(
        &mut self,
        target_bytes: usize,
    ) -> Result<(), crate::BufferError> {
        let mut bytes = self.total_accounted_bytes();
        while bytes > target_bytes {
            let reclaimed = self
                .evict_oldest_completed()
                .ok_or(crate::BufferError::Full)?;
            bytes = bytes.saturating_sub(reclaimed);
        }
        Ok(())
    }

    fn evict_oldest_completed(&mut self) -> Option<usize> {
        let id = self.completed_receipt_order.pop_front()?;
        let bytes = self
            .admission_receipts
            .get(&id)
            .filter(|receipt| receipt.is_completed())
            .map_or(0, |receipt| receipt.accounted_bytes(&id));
        if bytes > 0 {
            self.admission_receipts.remove(&id);
        }
        Some(bytes)
    }
}
