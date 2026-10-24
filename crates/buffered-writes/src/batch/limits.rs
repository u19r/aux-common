use super::{preparation::PreparedPayload, sealed::SealedBatch};
use crate::{configuration::SinkLimits, error::PrepareError};

impl SealedBatch {
    pub(crate) fn validate_sink_limits(&self, limits: &SinkLimits) -> Result<(), PrepareError> {
        limits.validate_prepared_size(self.operation_ids().len(), self.write_payload_bytes())
    }

    fn write_payload_bytes(&self) -> usize {
        match self.prepared() {
            PreparedPayload::SharedRecords => self
                .records()
                .iter()
                .map(|record| record.payload.len())
                .fold(0, usize::saturating_add),
            PreparedPayload::CustomOperations(operations) => operations
                .iter()
                .map(|operation| operation.payload.len())
                .fold(0, usize::saturating_add),
        }
    }
}
