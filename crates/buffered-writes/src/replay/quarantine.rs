use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{OperationId, QuarantineReason, QueueError, ReceivedEnvelope};

/// A quarantine publication preserves immutable input and known sink progress.
pub(super) struct ReplayQuarantine<'a> {
    pub envelope: &'a ReceivedEnvelope,
    pub reason: QuarantineReason,
    pub completed_ids: Vec<OperationId>,
}

#[derive(Serialize)]
struct QuarantineRecord<'a> {
    version: u16,
    reason: QuarantineReason,
    envelope_bytes: usize,
    envelope_sha256: &'a str,
    envelope_base64: String,
    truncated: bool,
    completed_operation_ids: &'a [OperationId],
}

impl<'a> From<(&'a ReceivedEnvelope, QuarantineReason)> for ReplayQuarantine<'a> {
    fn from((envelope, reason): (&'a ReceivedEnvelope, QuarantineReason)) -> Self {
        Self {
            envelope,
            reason,
            completed_ids: Vec::new(),
        }
    }
}

impl ReplayQuarantine<'_> {
    pub(super) fn with_completed(mut self, completed_ids: Vec<OperationId>) -> Self {
        self.completed_ids = completed_ids;
        self
    }

    /// Encodes a record no larger than `limit`. Base64 expands the envelope by
    /// a third, so an envelope near the queue limit keeps only the prefix that
    /// fits; its length and digest still identify it.
    pub(super) fn encode(&self, limit: usize) -> Result<Bytes, QueueError> {
        let envelope = &self.envelope.envelope_bytes;
        let digest = Sha256::digest(envelope);
        let envelope_sha256 = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let mut record = QuarantineRecord {
            version: crate::constants::REPLAY_QUARANTINE_VERSION,
            reason: self.reason,
            envelope_bytes: envelope.len(),
            envelope_sha256: &envelope_sha256,
            envelope_base64: String::new(),
            truncated: false,
            completed_operation_ids: &self.completed_ids,
        };
        // The flag's two spellings differ by one byte; measure the longer one.
        record.truncated = true;
        let overhead = encode_record(&record)?.len();
        let prefix_bytes = (limit.saturating_sub(overhead) / 4).saturating_mul(3);
        if prefix_bytes == 0 {
            return Err(QueueError::Permanent {
                reason: "replay quarantine record exceeds the queue limit",
            });
        }
        let kept = envelope.get(..prefix_bytes).unwrap_or(envelope);
        record.truncated = kept.len() < envelope.len();
        record.envelope_base64 = STANDARD.encode(kept);
        encode_record(&record).map(Bytes::from)
    }
}

fn encode_record(record: &QuarantineRecord<'_>) -> Result<Vec<u8>, QueueError> {
    serde_json::to_vec(record).map_err(|_| QueueError::Permanent {
        reason: "failed to encode replay quarantine record",
    })
}
