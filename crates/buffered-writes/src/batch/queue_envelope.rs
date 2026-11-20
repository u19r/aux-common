use bytes::Bytes;
use hmac::{Hmac, KeyInit as _, Mac as _};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::SealedBatch;
use crate::{
    constants::{BATCH_ENVELOPE_MAC_DOMAIN, MIN_ENVELOPE_KEY_BYTES},
    error::{ConfigurationError, EncodeError},
};

/// Secret that authenticates sealed batches on the outage queue.
///
/// The queue is spool storage that other principals may be able to write. The
/// batch digest only detects corruption, so the writer seals each queued batch
/// with this key and replay accepts only batches it can authenticate, including
/// their tenant scope. Writers and replay workers of one namespace share it.
#[derive(Clone)]
pub struct EnvelopeKey {
    mac: Hmac<Sha256>,
}

impl std::fmt::Debug for EnvelopeKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EnvelopeKey([REDACTED])")
    }
}

impl EnvelopeKey {
    /// Accepts a key of at least 32 bytes from the caller's secret store.
    pub fn try_new(secret: impl AsRef<[u8]>) -> Result<Self, ConfigurationError> {
        let secret = secret.as_ref();
        if secret.len() < MIN_ENVELOPE_KEY_BYTES {
            return Err(ConfigurationError::InvalidQueueConfiguration {
                reason: "envelope key must contain at least 32 bytes",
            });
        }
        let mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| {
            ConfigurationError::InvalidQueueConfiguration {
                reason: "envelope key is invalid",
            }
        })?;
        Ok(Self { mac })
    }

    /// Encodes `batch` as an authenticated queue envelope.
    pub fn seal(&self, batch: SealedBatch) -> Result<QueueEnvelope, EncodeError> {
        let bytes = serde_json::to_vec(&WireEnvelopeRef {
            mac: self.tag(&batch),
            batch: &batch,
        })
        .map_err(|_| EncodeError::SerializationFailed)?;
        Ok(QueueEnvelope {
            batch,
            bytes: Bytes::from(bytes),
        })
    }

    /// Decodes a queue envelope, verifying the batch digest and then its tag in
    /// constant time.
    pub fn open(&self, bytes: &[u8]) -> Result<SealedBatch, EncodeError> {
        let envelope: WireEnvelope =
            serde_json::from_slice(bytes).map_err(|_| EncodeError::DeserializationFailed)?;
        self.mac_for(&envelope.batch)
            .verify_slice(&envelope.mac)
            .map_err(|_| EncodeError::invalid_input("sealed batch envelope is not authentic"))?;
        Ok(envelope.batch)
    }

    fn tag(&self, batch: &SealedBatch) -> [u8; 32] {
        self.mac_for(batch).finalize().into_bytes().into()
    }

    /// The digest already binds every batch field, so the tag covers it alone.
    fn mac_for(&self, batch: &SealedBatch) -> Hmac<Sha256> {
        let mut mac = self.mac.clone();
        mac.update(BATCH_ENVELOPE_MAC_DOMAIN);
        mac.update(batch.digest());
        mac
    }
}

/// A sealed batch and its authenticated queue encoding.
#[derive(Clone)]
pub struct QueueEnvelope {
    batch: SealedBatch,
    bytes: Bytes,
}

impl std::fmt::Debug for QueueEnvelope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueueEnvelope")
            .field("batch_id", &self.batch.batch_id())
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

impl QueueEnvelope {
    #[must_use]
    pub const fn batch(&self) -> &SealedBatch {
        &self.batch
    }

    #[must_use]
    pub const fn bytes(&self) -> &Bytes {
        &self.bytes
    }
}

#[derive(Serialize)]
struct WireEnvelopeRef<'a> {
    mac: [u8; 32],
    batch: &'a SealedBatch,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEnvelope {
    mac: [u8; 32],
    batch: SealedBatch,
}
