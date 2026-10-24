use std::{fmt, time::Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::codec::RecordCodec;
use crate::{
    configuration::{OperationId, TenantScope},
    error::EncodeError,
};

/// Immutable persisted record stored in a batch envelope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedRecord {
    pub operation_id: OperationId,
    pub admitted_at_utc_ms: i64,
    pub payload: Bytes,
}

impl fmt::Debug for PersistedRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedRecord")
            .field("operation_id", &self.operation_id)
            .field("admitted_at_utc_ms", &self.admitted_at_utc_ms)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// Admitted record with monotonic age tracking for active in-process buffers.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdmittedRecord {
    pub operation_id: OperationId,
    pub scope: TenantScope,
    pub codec_version: String,
    pub admitted_at_utc_ms: i64,
    #[serde(skip, default = "Instant::now")]
    pub admitted_at_mono: Instant,
    pub payload: Bytes,
}

impl fmt::Debug for AdmittedRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdmittedRecord")
            .field("operation_id", &self.operation_id)
            .field("scope", &self.scope)
            .field("codec_version", &self.codec_version)
            .field("admitted_at_utc_ms", &self.admitted_at_utc_ms)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl AdmittedRecord {
    pub(crate) fn decode<T: 'static>(&self, codec: &dyn RecordCodec<T>) -> Result<T, EncodeError> {
        if self.codec_version != codec.version() {
            return Err(EncodeError::UnsupportedCodecVersion);
        }
        codec.decode(&self.payload)
    }

    #[must_use]
    pub fn accounted_bytes(&self) -> usize {
        self.payload
            .len()
            .saturating_add(self.operation_id.as_str().len())
            .saturating_add(self.scope.as_str().len())
            .saturating_add(self.codec_version.len())
            .saturating_add(std::mem::size_of::<Self>())
    }

    #[must_use]
    pub fn to_persisted(&self) -> PersistedRecord {
        PersistedRecord {
            operation_id: self.operation_id.clone(),
            admitted_at_utc_ms: self.admitted_at_utc_ms,
            payload: self.payload.clone(),
        }
    }
}
