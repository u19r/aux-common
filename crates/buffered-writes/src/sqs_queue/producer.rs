use futures_util::future::BoxFuture;

use super::{
    connection::{SignedQueue, SqsQueue},
    protocol::{SendMessageRequest, SendMessageResponse, hash_message_identity},
};
use crate::{
    Deadline, QueueError, QueueLimits, QueueReceipt, SealedBatch, WriteQueue,
    constants::SQS_TARGET_SEND_MESSAGE,
};

impl WriteQueue for SqsQueue {
    fn limits(&self) -> &QueueLimits {
        &self.limits
    }

    fn publish(
        &self,
        batch: SealedBatch,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<QueueReceipt, QueueError>> {
        let queue = self.clone();
        Box::pin(async move {
            let bytes = batch
                .to_envelope_bytes()
                .map_err(|_| QueueError::Permanent {
                    reason: "failed to serialize sealed batch envelope",
                })?;
            let body = std::str::from_utf8(&bytes).map_err(|_| QueueError::Permanent {
                reason: "envelope must be valid UTF-8 JSON",
            })?;
            let delivery = queue.is_fifo.then(|| {
                (
                    batch.batch_id().to_string(),
                    queue.fifo_group_id.clone().unwrap_or_else(|| {
                        hash_message_identity(&[
                            &batch.namespace().to_string(),
                            &batch.scope().to_string(),
                        ])
                    }),
                )
            });
            queue
                .publish_message(&queue.primary, body, delivery, deadline)
                .await
        })
    }
}

impl SqsQueue {
    pub(super) async fn publish_message(
        &self,
        target: &SignedQueue,
        body: &str,
        delivery: Option<(String, String)>,
        deadline: Deadline,
    ) -> Result<QueueReceipt, QueueError> {
        validate_message_body(body, self.limits.max_envelope_bytes())?;
        let (message_deduplication_id, message_group_id) = match delivery {
            Some((identity, group)) => (Some(identity), Some(group)),
            None => (None, None),
        };
        let request = SendMessageRequest {
            queue_url: &target.url,
            message_body: body,
            message_deduplication_id,
            message_group_id,
        };
        let encoded = serde_json::to_string(&request).map_err(|_| QueueError::Permanent {
            reason: "failed to encode SendMessage request",
        })?;
        let text = self
            .send_signed_json(target, SQS_TARGET_SEND_MESSAGE, encoded, deadline)
            .await
            .map_err(classify_publish_error)?;
        let response: SendMessageResponse =
            serde_json::from_str(&text).map_err(|_| QueueError::AmbiguousPublish)?;
        if response.message_id.is_empty() {
            return Err(QueueError::AmbiguousPublish);
        }
        Ok(QueueReceipt {
            message_id: response.message_id,
        })
    }
}

fn validate_message_body(body: &str, limit: usize) -> Result<(), QueueError> {
    if body.len() > limit {
        return Err(QueueError::EnvelopeTooLarge {
            size: body.len(),
            limit,
        });
    }
    let is_allowed = |value: char| {
        matches!(value, '\t' | '\n' | '\r' | '\u{20}'..='\u{d7ff}'
        | '\u{e000}'..='\u{fffd}' | '\u{10000}'..='\u{10ffff}')
    };
    if body.is_empty() || !body.chars().all(is_allowed) {
        return Err(QueueError::Permanent {
            reason: "SQS message has unsupported content",
        });
    }
    Ok(())
}

fn classify_publish_error(error: QueueError) -> QueueError {
    match error {
        QueueError::Unavailable { .. } | QueueError::DeadlineExceeded => {
            QueueError::AmbiguousPublish
        }
        other => other,
    }
}
