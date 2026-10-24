use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::Serialize;

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
    envelope_base64: String,
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

    pub(super) fn encode(&self) -> Result<Bytes, QueueError> {
        serde_json::to_vec(&QuarantineRecord {
            version: crate::constants::REPLAY_QUARANTINE_VERSION,
            reason: self.reason,
            envelope_base64: STANDARD.encode(&self.envelope.envelope_bytes),
            completed_operation_ids: &self.completed_ids,
        })
        .map(Bytes::from)
        .map_err(|_| QueueError::Permanent {
            reason: "failed to encode replay quarantine record",
        })
    }
}
