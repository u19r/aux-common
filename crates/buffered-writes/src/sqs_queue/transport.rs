use std::{str::FromStr, time::Instant};

use aws_sigv4_signing::SignableBody;
use http::{HeaderMap, HeaderValue, Uri, header::CONTENT_TYPE};

use super::connection::{SignedQueue, SqsQueue};
use crate::{
    Deadline, QueueError,
    constants::{SQS_JSON_CONTENT_TYPE, SQS_MAX_RESPONSE_BYTES, SQS_TARGET_HEADER},
};

impl SqsQueue {
    pub(super) async fn send_signed_json(
        &self,
        target: &SignedQueue,
        action: &'static str,
        body: String,
        deadline: Deadline,
    ) -> Result<String, QueueError> {
        let remaining = deadline.remaining_at(Instant::now());
        if remaining.is_zero() {
            return Err(QueueError::DeadlineExceeded);
        }
        tokio::time::timeout(
            remaining,
            self.dispatch_request(target, action, body, deadline),
        )
        .await
        .unwrap_or(Err(QueueError::DeadlineExceeded))
    }

    async fn dispatch_request(
        &self,
        target: &SignedQueue,
        action: &'static str,
        body: String,
        deadline: Deadline,
    ) -> Result<String, QueueError> {
        let headers = self.sign_headers(target, action, &body).await?;
        let target = self
            .endpoint_override
            .as_deref()
            .unwrap_or(&target.endpoint);
        let mut request = self
            .client
            .post(target)
            .timeout(deadline.remaining_at(Instant::now()));
        for (name, value) in &headers {
            request = request.header(name, value);
        }
        let response = request
            .body(body)
            .send()
            .await
            .map_err(|_| QueueError::Unavailable {
                reason: "SQS HTTP transport outcome is unknown",
            })?;
        let status = response.status();
        let text = response
            .with_max_body_size(Some(SQS_MAX_RESPONSE_BYTES))
            .text()
            .await
            .map_err(|_| QueueError::Unavailable {
                reason: "SQS response body is unavailable",
            })?;
        if !status.is_success() {
            return Err(classify_response_error(status, &text));
        }
        Ok(text)
    }

    async fn sign_headers(
        &self,
        target: &SignedQueue,
        action: &'static str,
        body: &str,
    ) -> Result<HeaderMap, QueueError> {
        let signer = &target.signer;
        let target = self
            .endpoint_override
            .as_deref()
            .unwrap_or(&target.endpoint);
        let uri = Uri::from_str(target).map_err(|_| QueueError::Permanent {
            reason: "invalid SQS request URI",
        })?;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static(SQS_JSON_CONTENT_TYPE),
        );
        headers.insert(SQS_TARGET_HEADER, HeaderValue::from_static(action));
        signer
            .sign_request("POST", &uri, &headers, SignableBody::Bytes(body.as_bytes()))
            .await
            .map_err(|_| QueueError::Unavailable {
                reason: "SQS SigV4 signing failed",
            })
    }
}

fn classify_response_error(status: http::StatusCode, text: &str) -> QueueError {
    let error = serde_json::from_str::<serde_json::Value>(text).ok();
    let kind = error
        .as_ref()
        .and_then(|value| value.get("__type"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    let kind = kind.rsplit('#').next().unwrap_or("");
    match kind {
        "RequestThrottled" | "KmsThrottled" | "ThrottlingException" => QueueError::Unavailable {
            reason: "SQS throttled request",
        },
        "OverLimit" => QueueError::Unavailable {
            reason: "SQS queue capacity exceeded",
        },
        "ReceiptHandleIsInvalid" | "MessageNotInflight" => QueueError::InvalidReceipt,
        _ if status.is_server_error() || matches!(status.as_u16(), 408 | 423 | 425 | 429) => {
            QueueError::Unavailable {
                reason: "SQS returned retryable status",
            }
        }
        _ => QueueError::Permanent {
            reason: "SQS rejected request",
        },
    }
}
