use serde::Serialize;

use super::{
    encoding::encode_json,
    preparation::{PreparedOperation, PreparedPayload, PreparedWrites},
};
use crate::{
    configuration::{OperationId, SinkLimits},
    constants::ARC_ALLOCATION_HEADER_BYTES,
    error::{EncodeError, PrepareError},
};

pub(super) struct OperationBuilder<'a> {
    limits: &'a SinkLimits,
    max_prepared_bytes: usize,
    payload_bytes: usize,
    prepared_bytes: usize,
    operations: Vec<PreparedOperation>,
}

struct OperationBudget {
    metadata_bytes: usize,
    payload_bytes: usize,
}

impl<'a> OperationBuilder<'a> {
    pub(super) fn new(limits: &'a SinkLimits, max_prepared_bytes: usize) -> Self {
        Self {
            limits,
            max_prepared_bytes,
            payload_bytes: 0,
            prepared_bytes: 2 * ARC_ALLOCATION_HEADER_BYTES,
            operations: Vec::new(),
        }
    }

    pub(super) fn push<P: Serialize>(
        &mut self,
        id: OperationId,
        value: &P,
    ) -> Result<(), PrepareError> {
        let mut operation = PreparedOperation {
            operation_id: id,
            payload: bytes::Bytes::new(),
        };
        let budget = self.operation_budget(&operation)?;
        operation.payload = encode_json(value, budget.payload_bytes)
            .map_err(|error| self.encoding_error(error, budget.metadata_bytes))?;
        self.payload_bytes = self.payload_bytes.saturating_add(operation.payload.len());
        self.prepared_bytes = budget
            .metadata_bytes
            .saturating_add(operation.payload.len());
        self.operations.push(operation);
        Ok(())
    }

    fn operation_budget(
        &self,
        operation: &PreparedOperation,
    ) -> Result<OperationBudget, PrepareError> {
        if self.operations.len() >= self.limits.max_operations() {
            return Err(PrepareError::TooManyOperations {
                count: self.operations.len().saturating_add(1),
                limit: self.limits.max_operations(),
            });
        }
        let metadata = self
            .prepared_bytes
            .saturating_add(operation.retained_bytes());
        if metadata > self.max_prepared_bytes {
            return Err(PrepareError::CandidateTooLarge {
                size: metadata,
                limit: self.max_prepared_bytes,
            });
        }
        let remaining = self
            .limits
            .raw_payload_limit()
            .saturating_sub(self.payload_bytes)
            .min(self.max_prepared_bytes.saturating_sub(metadata));
        Ok(OperationBudget {
            metadata_bytes: metadata,
            payload_bytes: remaining,
        })
    }

    fn encoding_error(&self, error: EncodeError, metadata: usize) -> PrepareError {
        let EncodeError::PayloadTooLarge { size, .. } = error else {
            return PrepareError::Encode(error);
        };
        let native_bytes = self
            .limits
            .expanded_payload_bytes(self.payload_bytes.saturating_add(size));
        if native_bytes > self.limits.max_payload_bytes() {
            PrepareError::CandidateTooLarge {
                size: native_bytes,
                limit: self.limits.max_payload_bytes(),
            }
        } else {
            PrepareError::CandidateTooLarge {
                size: metadata.saturating_add(size),
                limit: self.max_prepared_bytes,
            }
        }
    }

    pub(super) fn finish(self) -> Result<PreparedWrites, PrepareError> {
        if self.operations.is_empty() {
            return Err(PrepareError::EmptyOperations);
        }
        let operation_ids = self
            .operations
            .iter()
            .map(|operation| operation.operation_id.clone())
            .collect();
        Ok(PreparedWrites {
            payload: PreparedPayload::CustomOperations(self.operations.into()),
            operation_ids,
        })
    }
}
