use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use http_request::{HttpClient, HttpRequestBuilder, RetryConfig};

use crate::{
    Deadline, LifecycleError,
    constants::{
        IMDS_ACTION_PATH, IMDS_MAX_NOTICE_BYTES, IMDS_MAX_TOKEN_BYTES, IMDS_TOKEN_HEADER,
        IMDS_TOKEN_PATH, IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_SECONDS,
    },
};

#[derive(Clone)]
pub(super) struct ImdsTransport {
    endpoint: String,
    client: HttpClient,
}

impl ImdsTransport {
    pub(super) fn try_new(endpoint: String) -> Result<Self, LifecycleError> {
        let client = HttpClient::builder()
            .with_reqwest_builder(|builder| builder.no_proxy())
            .retry(RetryConfig {
                max_retries: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                retry_non_idempotent: false,
            })
            .build()
            .map_err(|_| LifecycleError::InvalidConfiguration {
                reason: "IMDS HTTP client could not be constructed",
            })?;
        Ok(Self { endpoint, client })
    }

    pub(super) async fn fetch_token(
        &self,
        deadline: Deadline,
    ) -> Result<HeaderValue, LifecycleError> {
        let request = self
            .client
            .put(format!("{}{IMDS_TOKEN_PATH}", self.endpoint))
            .header(IMDS_TOKEN_TTL_HEADER, IMDS_TOKEN_TTL_SECONDS)
            .timeout(deadline.remaining_at(Instant::now()));
        let (status, bytes) = read_response(request, IMDS_MAX_TOKEN_BYTES).await?;
        if status != StatusCode::OK || bytes.is_empty() || !bytes.is_ascii() {
            return Err(LifecycleError::SourceUnavailable {
                reason: "IMDS token response is invalid",
            });
        }
        let mut token =
            HeaderValue::from_bytes(&bytes).map_err(|_| LifecycleError::SourceUnavailable {
                reason: "IMDS token header is invalid",
            })?;
        token.set_sensitive(true);
        Ok(token)
    }

    pub(super) async fn fetch_action(
        &self,
        token: &HeaderValue,
        deadline: Deadline,
    ) -> Result<(StatusCode, Bytes), LifecycleError> {
        let request = self
            .client
            .get(format!("{}{IMDS_ACTION_PATH}", self.endpoint))
            .header(IMDS_TOKEN_HEADER, token)
            .timeout(deadline.remaining_at(Instant::now()));
        let response = request.send().await.map_err(classify_http_error)?;
        let status = response.status();
        if status != StatusCode::OK {
            return Ok((status, Bytes::new()));
        }
        let bytes = response
            .with_max_body_size(Some(IMDS_MAX_NOTICE_BYTES))
            .bytes()
            .await
            .map_err(classify_http_error)?;
        Ok((status, bytes))
    }
}

async fn read_response(
    request: HttpRequestBuilder,
    limit: usize,
) -> Result<(StatusCode, Bytes), LifecycleError> {
    let response = request.send().await.map_err(classify_http_error)?;
    let status = response.status();
    let bytes = response
        .with_max_body_size(Some(limit))
        .bytes()
        .await
        .map_err(classify_http_error)?;
    Ok((status, bytes))
}

fn classify_http_error(error: http_request::HttpRequestError) -> LifecycleError {
    match error.kind() {
        http_request::HttpRequestErrorKind::Timeout => LifecycleError::DeadlineExceeded,
        _ => LifecycleError::SourceUnavailable {
            reason: "IMDS request or response body failed",
        },
    }
}
