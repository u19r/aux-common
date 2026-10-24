use buffered_writes::LambdaInvocation;
use http_request::{HttpResponse, header::HeaderValue};
use serde::Deserialize;

use crate::constants::{
    API_MAX_BODY_BYTES, API_OPERATION_TIMEOUT, ATTEMPT_ID_HEADER, REQUEST_ID_HEADER,
};

#[derive(Deserialize)]
pub(super) struct InvocationInput {
    value: u64,
    #[serde(default)]
    skip_marker: bool,
    #[serde(default)]
    exit_after_response: bool,
    #[serde(default)]
    hang_before_response: bool,
}

pub(super) struct Invocation {
    pub(super) request_id: String,
    pub(super) attempt_id: HeaderValue,
    pub(super) payload: Option<bytes::Bytes>,
}

pub(super) enum InvocationOutcome {
    Success(InvocationInput),
    Failure,
}

impl Invocation {
    pub(super) async fn read_response(
        response: HttpResponse,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .ok_or("missing Runtime API request ID")?
            .to_owned();
        if request_id.is_empty()
            || request_id.len() > 128
            || !request_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err("invalid Runtime API request ID".into());
        }
        let attempt_id = response
            .headers()
            .get(ATTEMPT_ID_HEADER)
            .cloned()
            .ok_or("Runtime API attempt ID is required")?;
        let payload = tokio::time::timeout(
            API_OPERATION_TIMEOUT,
            response
                .with_max_body_size(Some(API_MAX_BODY_BYTES))
                .bytes(),
        )
        .await
        .ok()
        .and_then(Result::ok);
        Ok(Self {
            request_id,
            attempt_id,
            payload,
        })
    }

    pub(super) async fn admit(&self, writes: &LambdaInvocation<u64>) -> InvocationOutcome {
        let Some(payload) = &self.payload else {
            return InvocationOutcome::Failure;
        };
        let Ok(input) = serde_json::from_slice::<InvocationInput>(payload) else {
            return InvocationOutcome::Failure;
        };
        if writes.add_write_item(input.value).await.is_err() {
            return InvocationOutcome::Failure;
        }
        if input.hang_before_response {
            std::future::pending::<()>().await;
        }
        InvocationOutcome::Success(input)
    }
}

impl InvocationOutcome {
    pub(super) fn response(&self) -> (&'static str, &'static str, serde_json::Value) {
        match self {
            Self::Success(input) => (
                "response",
                "application/json",
                serde_json::json!({"value":input.value}),
            ),
            Self::Failure => (
                "error",
                "application/vnd.aws.lambda.error+json",
                serde_json::json!({"errorType":"BufferedWritesInvocationError", "errorMessage":"Demonstration invocation failed"}),
            ),
        }
    }

    pub(super) fn should_mark_complete(&self) -> bool {
        !matches!(self, Self::Success(input) if input.skip_marker)
    }

    pub(super) fn should_exit(&self) -> bool {
        matches!(self, Self::Success(input) if input.exit_after_response)
    }
}
