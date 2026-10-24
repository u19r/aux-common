use super::state::Engine;
use crate::{BufferError, BufferSnapshot, ConfigurationError, OpenBatchCandidate};

impl<T: Send + Sync + 'static> Engine<T> {
    pub(super) fn validate_retained_capacity(
        &self,
        snapshot: &BufferSnapshot,
    ) -> Result<(), ConfigurationError> {
        let retained_items = snapshot.stats.items();
        let retained_bytes = snapshot
            .stats
            .bytes()
            .saturating_sub(snapshot.reclaimable_bytes);
        let item_limit = self.cfg.capacity.item_limit();
        let byte_limit = self.cfg.capacity.byte_limit();
        if retained_items > item_limit || retained_bytes > byte_limit {
            return Err(ConfigurationError::InsufficientRecoveryCapacity {
                retained_items,
                retained_bytes,
                item_limit,
                byte_limit,
            });
        }
        Ok(())
    }

    pub(super) fn validate_candidate_configuration(
        &self,
        candidate: &OpenBatchCandidate,
    ) -> Result<(), BufferError> {
        if candidate.records.is_empty() || candidate.reserved_bytes.len() != candidate.records.len()
        {
            return Err(BufferError::InvalidRequest {
                reason: "claimed record reservations do not match a nonempty record group",
            });
        }
        for (record, reserved) in candidate.records.iter().zip(&candidate.reserved_bytes) {
            let required = self.admission_reserved_bytes(record);
            if *reserved < required {
                return Err(ConfigurationError::InsufficientPreparationCredit {
                    reserved: *reserved,
                    required,
                }
                .into());
            }
        }
        Ok(())
    }
}
