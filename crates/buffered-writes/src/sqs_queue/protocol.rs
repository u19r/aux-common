use serde::{Deserialize, Serialize};

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SendMessageRequest<'a> {
    pub(super) queue_url: &'a str,
    pub(super) message_body: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) message_deduplication_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) message_group_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SendMessageResponse {
    pub(super) message_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct ReceiveMessageRequest<'a> {
    pub(super) queue_url: &'a str,
    pub(super) max_number_of_messages: usize,
    pub(super) visibility_timeout: u32,
    pub(super) wait_time_seconds: u32,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub(super) struct ReceiveMessageResponse {
    #[serde(default)]
    pub(super) messages: Vec<SqsWireMessage>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct SqsWireMessage {
    pub(super) message_id: String,
    pub(super) receipt_handle: String,
    pub(super) body: String,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct DeleteMessageRequest<'a> {
    pub(super) queue_url: &'a str,
    pub(super) receipt_handle: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub(super) struct ChangeVisibilityRequest<'a> {
    pub(super) queue_url: &'a str,
    pub(super) receipt_handle: &'a str,
    pub(super) visibility_timeout: u32,
}

// Length framing keeps scope boundaries unambiguous and IDs bounded to 64 ASCII
// bytes.
pub(super) fn hash_message_identity(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

impl ReceiveMessageResponse {
    pub(super) fn into_envelopes(
        self,
        requested: usize,
    ) -> Result<Vec<crate::ReceivedEnvelope>, crate::QueueError> {
        if self.messages.len() > requested
            || self.messages.iter().any(|message| {
                message.message_id.is_empty()
                    || message.receipt_handle.is_empty()
                    || message.body.len() > crate::constants::SQS_MAX_MESSAGE_BYTES
            })
        {
            return Err(crate::QueueError::Unavailable {
                reason: "invalid SQS received message metadata",
            });
        }
        Ok(self
            .messages
            .into_iter()
            .map(|message| crate::ReceivedEnvelope {
                message_id: message.message_id,
                receipt_handle: message.receipt_handle,
                envelope_bytes: bytes::Bytes::from(message.body.into_bytes()),
            })
            .collect())
    }
}
