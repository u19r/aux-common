use super::preparation::{PreparedPayload, PreparedWrites};
use crate::{
    configuration::{BufferCapacity, Namespace, SinkLimits},
    constants::{ARC_ALLOCATION_HEADER_BYTES, RETENTION_ENTRY_OVERHEAD_BYTES},
    error::{EncodeError, PrepareError, WriteError},
    retention::RetentionState,
};

/// Representation contract used to budget canonical input before preparation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationLayout {
    /// One unchanged canonical record per prepared operation.
    Records,
    /// Arbitrary preparation, including packed or multiple commands.
    Custom,
}

pub(crate) struct PreparationLimits {
    layout: PreparationLayout,
    max_input_items: usize,
    max_input_bytes: usize,
    retention_limit: usize,
    output_reservation: usize,
}

impl PreparationLimits {
    pub(crate) fn new(
        layout: PreparationLayout,
        capacity: &BufferCapacity,
        sink: &SinkLimits,
    ) -> Self {
        let (max_input_items, max_input_bytes) = match layout {
            PreparationLayout::Records => (
                capacity.item_limit().min(sink.max_operations()),
                sink.raw_payload_limit(),
            ),
            PreparationLayout::Custom => (capacity.item_limit(), capacity.byte_limit()),
        };
        Self {
            layout,
            max_input_items,
            max_input_bytes,
            retention_limit: capacity.byte_limit(),
            output_reservation: sink
                .raw_payload_limit()
                .saturating_add(
                    sink.max_operations()
                        .saturating_mul(super::PreparedOperation::maximum_metadata_bytes()),
                )
                .saturating_add(2 * ARC_ALLOCATION_HEADER_BYTES),
        }
    }

    pub(crate) fn retained_reservation(
        &self,
        record: &super::AdmittedRecord,
        namespace: &Namespace,
        strategy: &str,
    ) -> usize {
        let base = RetentionState::preparation_base_bytes(
            std::slice::from_ref(record),
            namespace,
            strategy,
        );
        let output = match self.layout {
            PreparationLayout::Records => record
                .operation_id
                .accounted_bytes()
                .saturating_mul(2)
                .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES),
            PreparationLayout::Custom => self.output_reservation.min(
                self.retention_limit
                    .saturating_sub(RetentionState::admission_receipt_bytes(record))
                    .saturating_sub(base),
            ),
        };
        base.saturating_add(output)
    }

    pub(crate) const fn input_items(&self) -> usize {
        self.max_input_items
    }
    pub(crate) const fn input_bytes(&self) -> usize {
        self.max_input_bytes
    }

    pub(crate) fn admission_error(
        &self,
        error: EncodeError,
        sink: &SinkLimits,
        input_limit: usize,
    ) -> WriteError {
        let EncodeError::PayloadTooLarge { size, .. } = error else {
            return WriteError::Encode(error);
        };
        if input_limit < self.max_input_bytes {
            return WriteError::OversizedItem {
                size,
                limit: input_limit,
            };
        }
        match self.layout {
            PreparationLayout::Records => WriteError::OversizedItem {
                size: sink.expanded_payload_bytes(size),
                limit: sink.max_payload_bytes(),
            },
            PreparationLayout::Custom => WriteError::OversizedItem {
                size,
                limit: self.max_input_bytes,
            },
        }
    }

    pub(crate) fn validate_prepared(&self, prepared: &PreparedWrites) -> Result<(), PrepareError> {
        if self.layout == PreparationLayout::Records
            && !matches!(prepared.payload, PreparedPayload::SharedRecords)
        {
            return Err(PrepareError::permanent(
                "record layout cannot replace canonical writes with commands",
            ));
        }
        Ok(())
    }
}
