use super::state::{OpenRecordEntry, RetentionState, StoredAdmissionReceipt};
use crate::{
    buffer::{BufferAppendRequest, BufferAppendResult},
    configuration::{DurabilityClass, FencingToken},
    error::BufferError,
};
impl RetentionState {
    pub(crate) fn allocate_fence(&mut self) -> FencingToken {
        self.next_generation = self.next_generation.saturating_add(1);
        FencingToken::new(self.next_generation)
    }

    pub(crate) fn expire_open_leases(&mut self, now_utc_ms: i64) {
        for entry in &mut self.open_records {
            if entry.leased_fence.is_some() && entry.lease_expires_at_ms <= now_utc_ms {
                entry.leased_fence = None;
            }
        }
    }

    pub(crate) fn append_record(
        &mut self,
        request: BufferAppendRequest,
        durability: DurabilityClass,
    ) -> Result<BufferAppendResult, BufferError> {
        let digest = request.record.digest_record();
        if let Some(existing) = self.admission_receipts.get(&request.record.operation_id) {
            existing.verify_record(&request.record, digest)?;
            return Ok(BufferAppendResult {
                durability,
                duplicate: true,
                watermark: existing.watermark,
            });
        }
        let watermark = self.next_watermark.saturating_add(1);
        let receipt = StoredAdmissionReceipt {
            status: crate::AdmissionStatus::Buffered,
            scope: request.record.scope.clone(),
            codec_version: request.record.codec_version.clone(),
            payload_digest: digest,
            watermark,
        };
        let reserved_bytes =
            Self::admission_reserved_bytes(&request.record, request.reserved_bytes);
        let item_bytes = reserved_bytes
            .checked_add(receipt.accounted_bytes(&request.record.operation_id))
            .ok_or(BufferError::Full)?;
        self.check_append_capacity(&request, item_bytes)?;
        self.reclaim_completed_receipts(request.capacity.byte_limit().saturating_sub(item_bytes))?;
        self.next_watermark = watermark;
        self.insert_receipt(request.record.operation_id.clone(), receipt);
        self.open_records.push_back(OpenRecordEntry {
            record: request.record,
            reserved_bytes,
            watermark,
            leased_fence: None,
            lease_expires_at_ms: 0,
        });
        Ok(BufferAppendResult {
            durability,
            duplicate: false,
            watermark,
        })
    }
    fn check_append_capacity(
        &self,
        request: &BufferAppendRequest,
        item_bytes: usize,
    ) -> Result<(), BufferError> {
        if item_bytes > request.capacity.byte_limit() {
            return Err(BufferError::OversizedItem {
                size: item_bytes,
                limit: request.capacity.byte_limit(),
            });
        }
        let protected = self
            .total_accounted_bytes()
            .saturating_sub(self.completed_receipt_bytes());
        if self.total_accounted_items().saturating_add(1) > request.capacity.item_limit()
            || protected
                .checked_add(item_bytes)
                .is_none_or(|bytes| bytes > request.capacity.byte_limit())
        {
            return Err(BufferError::Full);
        }
        Ok(())
    }
}
