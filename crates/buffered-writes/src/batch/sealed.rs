use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::{envelope::BatchEnvelope, preparation::PreparedPayload, record::PersistedRecord};
use crate::{
    configuration::{BatchId, Namespace, OperationId, TenantScope},
    error::EncodeError,
};
/// Input parameters for constructing a [`SealedBatch`].
#[derive(Deserialize)]
pub struct SealedBatchInput {
    pub batch_id: BatchId,
    pub namespace: Namespace,
    pub scope: TenantScope,
    pub codec_version: String,
    pub strategy_version: String,
    pub first_item_time_ms: i64,
    pub records: Arc<[PersistedRecord]>,
    pub prepared: PreparedPayload,
    pub operation_ids: Arc<[OperationId]>,
}

/// Immutable sealed batch with stable UUIDv7 identity and SHA-256 digest.
///
/// Construction and deserialization validate membership, versions, age, and
/// digest. Callers can inspect the sealed contents but cannot change them.
///
/// ```compile_fail
/// fn change_digest(batch: &mut buffered_writes::SealedBatch) {
///     batch.digest = [0; 32];
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "BatchEnvelope")]
pub struct SealedBatch {
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

impl SealedBatch {
    pub fn try_new(input: SealedBatchInput) -> Result<Self, EncodeError> {
        input.validate()?;
        let mut batch = Self {
            batch_id: input.batch_id,
            namespace: input.namespace,
            scope: input.scope,
            codec_version: input.codec_version,
            strategy_version: input.strategy_version,
            first_item_time_ms: input.first_item_time_ms,
            records: input.records,
            prepared: input.prepared,
            operation_ids: input.operation_ids,
            digest: [0; 32],
        };
        batch.digest = batch.calculate_digest();
        Ok(batch)
    }

    #[must_use]
    pub const fn batch_id(&self) -> BatchId {
        self.batch_id
    }

    #[must_use]
    pub const fn namespace(&self) -> &Namespace {
        &self.namespace
    }

    #[must_use]
    pub const fn scope(&self) -> &TenantScope {
        &self.scope
    }

    #[must_use]
    pub fn codec_version(&self) -> &str {
        &self.codec_version
    }

    #[must_use]
    pub fn strategy_version(&self) -> &str {
        &self.strategy_version
    }

    #[must_use]
    pub const fn first_item_time_ms(&self) -> i64 {
        self.first_item_time_ms
    }

    #[must_use]
    pub fn records(&self) -> &[PersistedRecord] {
        &self.records
    }

    #[must_use]
    pub const fn prepared(&self) -> &PreparedPayload {
        &self.prepared
    }

    #[must_use]
    pub fn operation_ids(&self) -> &[OperationId] {
        &self.operation_ids
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub fn verify_digest(&self) -> bool {
        self.digest == self.calculate_digest()
    }

    pub(crate) fn validate_compatibility(
        &self,
        namespace: &Namespace,
        codec_version: &str,
        strategy_version: &str,
    ) -> Result<(), EncodeError> {
        if self.codec_version != codec_version {
            return Err(EncodeError::UnsupportedCodecVersion);
        }
        if &self.namespace != namespace || self.strategy_version != strategy_version {
            return Err(EncodeError::invalid_input(
                "incompatible sealed batch namespace or strategy",
            ));
        }
        Ok(())
    }

    pub(crate) fn age_at_utc_ms(&self, now_ms: i64) -> Duration {
        super::age::conservative_age(self.first_item_time_ms, now_ms)
    }

    pub fn to_envelope_bytes(&self) -> Result<Bytes, EncodeError> {
        serde_json::to_vec(self)
            .map(Bytes::from)
            .map_err(|_| EncodeError::SerializationFailed)
    }

    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, EncodeError> {
        serde_json::from_slice(bytes).map_err(|_| EncodeError::DeserializationFailed)
    }
}
