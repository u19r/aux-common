use std::collections::BTreeSet;

use serde::Deserialize;

use super::{PreparedPayload, SealedBatch, SealedBatchInput};
use crate::{configuration::validate_version, error::EncodeError};

/// Untrusted wire data. All deserialization enters the validated batch
/// boundary.
#[derive(Deserialize)]
pub(super) struct BatchEnvelope {
    #[serde(flatten)]
    input: SealedBatchInput,
    digest: [u8; 32],
}

impl TryFrom<BatchEnvelope> for SealedBatch {
    type Error = EncodeError;

    fn try_from(envelope: BatchEnvelope) -> Result<Self, Self::Error> {
        let batch = Self::try_new(envelope.input)?;
        if batch.digest() != &envelope.digest {
            return Err(EncodeError::invalid_input(
                "sealed batch digest verification failed",
            ));
        }
        Ok(batch)
    }
}

impl SealedBatchInput {
    pub(super) fn validate(&self) -> Result<(), EncodeError> {
        self.validate_versions()?;
        let mut record_ids = BTreeSet::new();
        if self.records.is_empty()
            || self
                .records
                .iter()
                .any(|record| !record_ids.insert(&record.operation_id))
        {
            return Err(EncodeError::invalid_input(
                "batch records must be nonempty and unique",
            ));
        }
        if self
            .records
            .iter()
            .map(|record| record.admitted_at_utc_ms)
            .min()
            != Some(self.first_item_time_ms)
        {
            return Err(EncodeError::invalid_input(
                "batch age does not match records",
            ));
        }
        self.validate_operations()
    }

    fn validate_versions(&self) -> Result<(), EncodeError> {
        for version in [&self.codec_version, &self.strategy_version] {
            validate_version(version)
                .map_err(|_| EncodeError::invalid_input("invalid batch version"))?;
        }
        Ok(())
    }

    fn validate_operations(&self) -> Result<(), EncodeError> {
        let unique: BTreeSet<_> = self.operation_ids.iter().collect();
        if unique.is_empty() || unique.len() != self.operation_ids.len() {
            return Err(EncodeError::invalid_input(
                "batch operations must be nonempty and unique",
            ));
        }
        let matches = match &self.prepared {
            PreparedPayload::SharedRecords => self
                .records
                .iter()
                .map(|record| &record.operation_id)
                .eq(self.operation_ids.iter()),
            PreparedPayload::CustomOperations(operations) => operations
                .iter()
                .map(|operation| &operation.operation_id)
                .eq(self.operation_ids.iter()),
        };
        if !matches {
            return Err(EncodeError::invalid_input(
                "batch operation membership mismatch",
            ));
        }
        Ok(())
    }
}
