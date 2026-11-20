use std::{collections::BTreeSet, sync::Arc};

use serde::Deserialize;

use super::{PreparedPayload, SealedBatch, SealedBatchInput, record::PersistedRecord};
use crate::{
    configuration::{BatchId, Namespace, OperationId, TenantScope, validate_version},
    error::EncodeError,
};

/// Untrusted wire data. All deserialization enters the validated batch
/// boundary. Fields are listed explicitly: `#[serde(flatten)]` would buffer the
/// whole envelope as generic content (about 16x on byte arrays) before
/// validation.
#[derive(Deserialize)]
pub(super) struct BatchEnvelope {
    batch_id: BatchId,
    namespace: Namespace,
    scope: TenantScope,
    codec_version: String,
    strategy_version: String,
    first_item_time_ms: i64,
    records: Arc<[PersistedRecord]>,
    prepared: PreparedPayload,
    operation_ids: Arc<[OperationId]>,
    digest: [u8; 32],
}

impl TryFrom<BatchEnvelope> for SealedBatch {
    type Error = EncodeError;

    fn try_from(envelope: BatchEnvelope) -> Result<Self, Self::Error> {
        let batch = Self::try_new(SealedBatchInput {
            batch_id: envelope.batch_id,
            namespace: envelope.namespace,
            scope: envelope.scope,
            codec_version: envelope.codec_version,
            strategy_version: envelope.strategy_version,
            first_item_time_ms: envelope.first_item_time_ms,
            records: envelope.records,
            prepared: envelope.prepared,
            operation_ids: envelope.operation_ids,
        })?;
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
