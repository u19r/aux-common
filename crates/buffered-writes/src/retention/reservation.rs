use super::state::{OpenRecordEntry, RetentionState, SealedBatchEntry, StoredAdmissionReceipt};
use crate::{
    batch::{AdmittedRecord, PersistedRecord, SealedBatch},
    configuration::Namespace,
};

impl RetentionState {
    pub(crate) fn admission_reserved_bytes(record: &AdmittedRecord, requested: usize) -> usize {
        requested.max(OpenRecordEntry::record_bytes(record))
    }

    pub(crate) fn preparation_base_bytes(
        records: &[AdmittedRecord],
        namespace: &Namespace,
        strategy: &str,
    ) -> usize {
        let Some(first) = records.first() else {
            return 0;
        };
        let records_bytes = records.iter().fold(0usize, |total, record| {
            total.saturating_add(PersistedRecord::record_bytes(
                &record.operation_id,
                record.payload.len(),
            ))
        });
        SealedBatch::header_bytes(namespace, &first.scope, &first.codec_version, strategy)
            .saturating_add(SealedBatchEntry::overhead_bytes())
            .saturating_add(records_bytes)
    }

    pub(crate) fn admission_receipt_bytes(record: &AdmittedRecord) -> usize {
        StoredAdmissionReceipt::metadata_bytes(
            &record.operation_id,
            &record.scope,
            &record.codec_version,
        )
    }

    pub(crate) fn sealed_batch_bytes(batch: &SealedBatch) -> usize {
        SealedBatchEntry::batch_bytes(batch)
    }

    pub(super) fn check_seal_capacity(
        &self,
        request: &crate::buffer::BufferSealRequest,
        namespace: &Namespace,
    ) -> Result<(), crate::BufferError> {
        let (released, retained) = match &request.action {
            crate::buffer::BufferSealAction::ReleaseCandidate => return Ok(()),
            crate::buffer::BufferSealAction::QuarantineSingleton { operation_id, .. } => {
                let entry = self
                    .open_records
                    .iter()
                    .find(|entry| {
                        entry.leased_fence == Some(request.fencing_token)
                            && &entry.record.operation_id == operation_id
                    })
                    .ok_or(crate::BufferError::BatchNotFound)?;
                (
                    entry.accounted_bytes(),
                    OpenRecordEntry::quarantine_bytes(&entry.record),
                )
            }
            crate::buffer::BufferSealAction::InstallBatch(batch) => {
                if batch.namespace() != namespace {
                    return Err(crate::BufferError::NamespaceMismatch);
                }
                let released = self.claimed_batch_bytes(request.fencing_token, batch)?;
                (released, Self::sealed_batch_bytes(batch))
            }
        };
        let remaining = self.total_accounted_bytes().saturating_sub(released);
        if remaining
            .checked_add(retained)
            .is_none_or(|bytes| bytes > request.capacity.byte_limit())
        {
            return Err(crate::BufferError::Full);
        }
        Ok(())
    }

    fn claimed_batch_bytes(
        &self,
        fence: crate::configuration::FencingToken,
        batch: &SealedBatch,
    ) -> Result<usize, crate::BufferError> {
        if self.sealed_batches.contains_key(&batch.batch_id())
            || self.quarantined_batches.contains_key(&batch.batch_id())
        {
            return Err(crate::BufferError::InvalidRequest {
                reason: "batch identity is already retained",
            });
        }
        let mut bytes = 0usize;
        for record in batch.records() {
            let entry = self
                .open_records
                .iter()
                .find(|entry| {
                    entry.leased_fence == Some(fence)
                        && entry.record.operation_id == record.operation_id
                })
                .ok_or(crate::BufferError::BatchNotFound)?;
            if entry.record.scope != *batch.scope()
                || entry.record.codec_version != batch.codec_version()
                || entry.record.payload != record.payload
                || entry.record.admitted_at_utc_ms != record.admitted_at_utc_ms
            {
                return Err(crate::BufferError::InvalidRequest {
                    reason: "sealed records differ from the claimed records",
                });
            }
            bytes = bytes.saturating_add(entry.accounted_bytes());
        }
        Ok(bytes)
    }
}
