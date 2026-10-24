use std::time::Duration;

use bytes::Bytes;
use futures_util::future::BoxFuture;

use super::{
    connection::SqsQueue,
    protocol::{
        ChangeVisibilityRequest, DeleteMessageRequest, ReceiveMessageRequest,
        ReceiveMessageResponse,
    },
};
use crate::{
    Deadline, QueueError, ReceivedEnvelope, ReplayQueue,
    constants::{
        SQS_DEFAULT_VISIBILITY_TIMEOUT_SECS, SQS_MAX_VISIBILITY_TIMEOUT_SECS,
        SQS_TARGET_CHANGE_VISIBILITY, SQS_TARGET_DELETE_MESSAGE, SQS_TARGET_RECEIVE_MESSAGE,
    },
};

impl ReplayQueue for SqsQueue {
    fn receive(
        &self,
        max_messages: usize,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<Vec<ReceivedEnvelope>, QueueError>> {
        if max_messages == 0 {
            return Box::pin(async { Ok(Vec::new()) });
        }
        let queue = self.clone();
        Box::pin(async move {
            let req = ReceiveMessageRequest {
                queue_url: &queue.primary.url,
                max_number_of_messages: max_messages.min(10),
                visibility_timeout: SQS_DEFAULT_VISIBILITY_TIMEOUT_SECS,
                wait_time_seconds: 0,
            };
            let body = serde_json::to_string(&req).map_err(|_| QueueError::Permanent {
                reason: "failed to encode ReceiveMessage request",
            })?;
            let text = queue
                .send_signed_json(&queue.primary, SQS_TARGET_RECEIVE_MESSAGE, body, deadline)
                .await?;
            let parsed: ReceiveMessageResponse =
                serde_json::from_str(&text).map_err(|_| QueueError::Unavailable {
                    reason: "invalid ReceiveMessage response JSON",
                })?;
            parsed.into_envelopes(max_messages.min(10))
        })
    }

    fn renew_visibility(
        &self,
        receipt_handle: &str,
        extension: Duration,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        let queue = self.clone();
        let handle = receipt_handle.to_owned();
        Box::pin(async move {
            let seconds = extension
                .as_secs()
                .saturating_add(u64::from(extension.subsec_nanos() > 0));
            if seconds == 0 || seconds > SQS_MAX_VISIBILITY_TIMEOUT_SECS {
                return Err(QueueError::Permanent {
                    reason: "SQS visibility extension must be at most 12 hours and positive",
                });
            }
            let secs = seconds as u32;
            let req = ChangeVisibilityRequest {
                queue_url: &queue.primary.url,
                receipt_handle: &handle,
                visibility_timeout: secs,
            };
            let body = serde_json::to_string(&req).map_err(|_| QueueError::Permanent {
                reason: "failed to encode ChangeMessageVisibility request",
            })?;
            let _ = queue
                .send_signed_json(&queue.primary, SQS_TARGET_CHANGE_VISIBILITY, body, deadline)
                .await?;
            Ok(())
        })
    }

    fn acknowledge(
        &self,
        receipt_handle: &str,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        let queue = self.clone();
        let handle = receipt_handle.to_owned();
        Box::pin(async move {
            let req = DeleteMessageRequest {
                queue_url: &queue.primary.url,
                receipt_handle: &handle,
            };
            let body = serde_json::to_string(&req).map_err(|_| QueueError::Permanent {
                reason: "failed to encode DeleteMessage request",
            })?;
            let _ = queue
                .send_signed_json(&queue.primary, SQS_TARGET_DELETE_MESSAGE, body, deadline)
                .await?;
            Ok(())
        })
    }

    fn quarantine(
        &self,
        receipt_handle: &str,
        envelope_bytes: Bytes,
        _reason: &'static str,
        deadline: Deadline,
    ) -> BoxFuture<'static, Result<(), QueueError>> {
        let queue = self.clone();
        let handle = receipt_handle.to_owned();
        Box::pin(async move {
            let Some(ref quarantine) = queue.quarantine else {
                return Err(QueueError::Permanent {
                    reason: "no quarantine queue URL configured for poison envelope",
                });
            };
            let body = std::str::from_utf8(&envelope_bytes).map_err(|_| QueueError::Permanent {
                reason: "quarantine record must be valid UTF-8 JSON",
            })?;
            let delivery = quarantine.url.ends_with(".fifo").then(|| {
                (
                    super::protocol::hash_message_identity(&[body]),
                    "quarantine".to_owned(),
                )
            });
            queue
                .publish_message(quarantine, body, delivery, deadline)
                .await?;
            queue.acknowledge(&handle, deadline).await
        })
    }
}
