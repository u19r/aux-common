use super::{PersistedRecord, PreparedOperation, PreparedPayload, SealedBatch};
use crate::{
    configuration::{Namespace, OperationId, TenantScope},
    constants::{
        ARC_ALLOCATION_HEADER_BYTES, MAX_OPERATION_ID_BYTES, RETENTION_ENTRY_OVERHEAD_BYTES,
    },
};

impl SealedBatch {
    /// Modeled retained bytes, including metadata and canonical replay records.
    /// This is independent of native write payload and queue envelope limits.
    #[must_use]
    pub fn accounted_bytes(&self) -> usize {
        let records = self
            .records()
            .iter()
            .map(PersistedRecord::accounted_bytes)
            .fold(0, usize::saturating_add);
        let ids = self
            .operation_ids()
            .iter()
            .map(OperationId::accounted_bytes)
            .fold(0, usize::saturating_add);
        let prepared = match self.prepared() {
            PreparedPayload::SharedRecords => 0,
            PreparedPayload::CustomOperations(operations) => operations
                .iter()
                .map(PreparedOperation::accounted_bytes)
                .fold(0, usize::saturating_add)
                .saturating_add(ARC_ALLOCATION_HEADER_BYTES),
        };
        Self::header_bytes(
            self.namespace(),
            self.scope(),
            self.codec_version(),
            self.strategy_version(),
        )
        .saturating_add(records)
        .saturating_add(ids)
        .saturating_add(prepared)
    }

    pub(crate) fn header_bytes(
        namespace: &Namespace,
        scope: &TenantScope,
        codec: &str,
        strategy: &str,
    ) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(namespace.as_str().len())
            .saturating_add(scope.as_str().len())
            .saturating_add(codec.len())
            .saturating_add(strategy.len())
            .saturating_add(2 * ARC_ALLOCATION_HEADER_BYTES)
    }
}

impl PersistedRecord {
    fn accounted_bytes(&self) -> usize {
        Self::record_bytes(&self.operation_id, self.payload.len())
    }

    pub(crate) fn record_bytes(id: &OperationId, payload_bytes: usize) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(id.as_str().len())
            .saturating_add(payload_bytes)
    }
}

impl PreparedOperation {
    pub(crate) fn maximum_metadata_bytes() -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(MAX_OPERATION_ID_BYTES)
            .saturating_add(2 * (std::mem::size_of::<OperationId>() + MAX_OPERATION_ID_BYTES))
            .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
    }

    pub(super) fn retained_bytes(&self) -> usize {
        self.accounted_bytes()
            .saturating_add(self.operation_id.accounted_bytes().saturating_mul(2))
            .saturating_add(RETENTION_ENTRY_OVERHEAD_BYTES)
    }

    fn accounted_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            .saturating_add(self.operation_id.as_str().len())
            .saturating_add(self.payload.len())
    }
}
