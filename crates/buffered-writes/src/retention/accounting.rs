use std::time::{Duration, Instant};

use super::state::{OpenRecordEntry, RetentionState, SealedBatchEntry};
use crate::{
    batch::{AdmittedRecord, conservative_age},
    buffer::{BufferInspectRequest, BufferSnapshot},
    configuration::{BatchId, BufferStats, DurabilityClass},
    constants::RETENTION_ENTRY_OVERHEAD_BYTES,
};
impl RetentionState {
    pub(crate) fn quarantine_count(&self) -> usize {
        self.quarantined_records
            .saturating_add(self.quarantined_items.len())
            .saturating_add(
                self.quarantined_batches
                    .values()
                    .map(|entry| entry.batch.records().len())
                    .sum::<usize>(),
            )
    }

    pub(crate) fn total_accounted_items(&self) -> usize {
        let sealed_items: usize = self
            .sealed_batches
            .values()
            .map(SealedBatchEntry::unsettled_record_count)
            .fold(0, usize::saturating_add);
        self.open_records
            .len()
            .saturating_add(sealed_items)
            .saturating_add(self.quarantine_count())
    }

    pub(crate) fn total_accounted_bytes(&self) -> usize {
        let open_bytes: usize = self
            .open_records
            .iter()
            .map(OpenRecordEntry::accounted_bytes)
            .fold(0, usize::saturating_add);
        let sealed_bytes: usize = self
            .sealed_batches
            .values()
            .map(SealedBatchEntry::accounted_bytes)
            .sum();
        let quarantined_bytes = self
            .quarantined_items
            .iter()
            .map(|(id, record)| {
                record
                    .accounted_bytes()
                    .saturating_add(id.accounted_bytes())
                    .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
            })
            .chain(
                self.quarantined_batches
                    .values()
                    .map(SealedBatchEntry::accounted_bytes),
            )
            .fold(0usize, usize::saturating_add);
        open_bytes
            .saturating_add(sealed_bytes)
            .saturating_add(quarantined_bytes)
            .saturating_add(self.receipt_bytes())
    }

    pub(crate) fn oldest_age(&self, now_instant: Instant, now_utc_ms: i64) -> Duration {
        let open_max = self
            .open_records
            .iter()
            .map(|entry| {
                now_instant
                    .saturating_duration_since(entry.record.admitted_at_mono)
                    .max(conservative_age(
                        entry.record.admitted_at_utc_ms,
                        now_utc_ms,
                    ))
            })
            .max()
            .unwrap_or(Duration::ZERO);
        let sealed_max = self
            .sealed_batches
            .values()
            .map(|entry| {
                let utc_age = conservative_age(entry.batch.first_item_time_ms(), now_utc_ms);
                entry.created_mono.map_or(utc_age, |m| {
                    now_instant.saturating_duration_since(m).max(utc_age)
                })
            })
            .max()
            .unwrap_or(Duration::ZERO);
        open_max.max(sealed_max)
    }

    pub(crate) fn inspect_state(
        &mut self,
        request: BufferInspectRequest,
        durability: DurabilityClass,
    ) -> BufferSnapshot {
        self.expire_open_leases(request.now_utc_ms);
        let items = self.total_accounted_items();
        let bytes = self.total_accounted_bytes();
        let oldest_age = self.oldest_age(request.now_instant, request.now_utc_ms);
        let claimable_open_items = self
            .open_records
            .iter()
            .filter(|e| e.leased_fence.is_none())
            .count();
        let claimable_sealed_batches = self
            .sealed_batches
            .values()
            .filter(|e| !e.is_leased_at(request.now_utc_ms) && e.retry_is_due(request.now_utc_ms))
            .count();
        let in_flight_batches = self
            .sealed_batches
            .values()
            .filter(|e| e.is_leased_at(request.now_utc_ms))
            .count();
        BufferSnapshot {
            reclaimable_bytes: self.completed_receipt_bytes(),
            admission: request
                .operation_id
                .as_ref()
                .and_then(|id| self.find_admission_receipt(id)),
            stats: BufferStats::new(items, bytes, oldest_age),
            claimable_open_items,
            claimable_sealed_batches,
            in_flight_batches,
            unsettled_items: items,
            quarantined_items: self.quarantine_count(),
            unresolved_batch_ids: self.sealed_batches.keys().copied().collect(),
            watermark: self.next_watermark,
            durability,
        }
    }
}
impl OpenRecordEntry {
    pub(super) fn accounted_bytes(&self) -> usize {
        self.reserved_bytes.max(Self::record_bytes(&self.record))
    }

    pub(super) fn record_bytes(record: &AdmittedRecord) -> usize {
        let open = record.accounted_bytes().saturating_add(
            std::mem::size_of::<Self>().saturating_sub(std::mem::size_of::<AdmittedRecord>()),
        );
        open.max(Self::quarantine_bytes(record))
    }

    pub(super) fn quarantine_bytes(record: &AdmittedRecord) -> usize {
        record
            .accounted_bytes()
            .saturating_add(record.operation_id.accounted_bytes())
            .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
    }
}

impl SealedBatchEntry {
    pub(super) fn overhead_bytes() -> usize {
        std::mem::size_of::<Self>()
            .saturating_sub(std::mem::size_of::<crate::SealedBatch>())
            .saturating_add(std::mem::size_of::<BatchId>())
            .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
    }

    pub(super) fn accounted_bytes(&self) -> usize {
        Self::batch_bytes(&self.batch)
    }

    pub(super) fn batch_bytes(batch: &crate::SealedBatch) -> usize {
        // Reserve every possible completion entry before delivery can add one.
        // Partial progress and quarantine must not increase the retained
        // charge.
        let completion_reservation = batch
            .operation_ids()
            .iter()
            .map(|id| {
                id.accounted_bytes()
                    .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
            })
            .fold(0, usize::saturating_add);
        batch
            .accounted_bytes()
            .saturating_add(Self::overhead_bytes())
            .saturating_add(completion_reservation)
    }
}
