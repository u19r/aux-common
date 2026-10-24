use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use http::{HeaderValue, StatusCode};
use http_request::{HttpClient, HttpResponse, RetryConfig};

use super::protocol::LambdaExtensionEvent;
use crate::{
    Deadline, LifecycleError,
    constants::{
        LAMBDA_API_BODY_TIMEOUT, LAMBDA_API_INIT_TIMEOUT, LAMBDA_API_MAX_BODY_BYTES,
        LAMBDA_API_MAX_IDENTIFIER_BYTES, LAMBDA_EXTENSION_NEXT_PATH,
        LAMBDA_EXTENSION_REGISTER_BODY, LAMBDA_EXTENSION_REGISTER_PATH,
        LAMBDA_MAX_INVOCATION_ID_BYTES,
    },
};

pub(super) struct ExtensionsApi {
    origin: String,
    name: HeaderValue,
    client: HttpClient,
}

pub(super) struct RegisteredExtension {
    api: ExtensionsApi,
    identifier: HeaderValue,
}

impl ExtensionsApi {
    pub(super) fn try_new(endpoint: &str, name: &str) -> Result<Self, LifecycleError> {
        let address: SocketAddr = endpoint.parse().map_err(|_| invalid_configuration())?;
        if !local_runtime_address(address.ip())
            || name.is_empty()
            || name.len() > LAMBDA_MAX_INVOCATION_ID_BYTES
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(invalid_configuration());
        }
        let name = HeaderValue::from_str(name).map_err(|_| invalid_configuration())?;
        // The provider's Next long poll must have no request or idle-read
        // timeout. Keep shared transport policy, but replace its timed default
        // builder.
        let client = HttpClient::builder()
            .with_reqwest_builder(|_| {
                http_request::reqwest::Client::builder()
                    .no_proxy()
                    .connect_timeout(LAMBDA_API_INIT_TIMEOUT)
            })
            .retry(RetryConfig {
                max_retries: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                retry_non_idempotent: false,
            })
            .build()
            .map_err(|_| invalid_configuration())?;
        Ok(Self {
            origin: format!("http://{address}"),
            name,
            client,
        })
    }

    pub(super) async fn register(self) -> Result<RegisteredExtension, LifecycleError> {
        tokio::time::timeout(LAMBDA_API_INIT_TIMEOUT, self.register_inner())
            .await
            .unwrap_or(Err(LifecycleError::DeadlineExceeded))
    }

    async fn register_inner(self) -> Result<RegisteredExtension, LifecycleError> {
        let response = self
            .client
            .post(format!("{}{LAMBDA_EXTENSION_REGISTER_PATH}", self.origin))
            .header("lambda-extension-name", &self.name)
            .header("content-type", "application/json")
            .body(LAMBDA_EXTENSION_REGISTER_BODY)
            .send()
            .await
            .map_err(|_| api_failure())?;
        if response.status() != StatusCode::OK {
            return Err(api_failure());
        }
        let mut identifier = response
            .headers()
            .get("lambda-extension-identifier")
            .filter(|value| {
                !value.is_empty() && value.as_bytes().len() <= LAMBDA_API_MAX_IDENTIFIER_BYTES
            })
            .cloned()
            .ok_or_else(api_failure)?;
        identifier.set_sensitive(true);
        read_body(response).await?;
        Ok(RegisteredExtension {
            api: self,
            identifier,
        })
    }
}

pub(super) struct ProviderEvent {
    pub(super) identifier: String,
    pub(super) event: LambdaExtensionEvent,
}
impl RegisteredExtension {
    pub(super) async fn next(&self) -> Result<ProviderEvent, LifecycleError> {
        let response = self
            .api
            .client
            .get(format!("{}{LAMBDA_EXTENSION_NEXT_PATH}", self.api.origin))
            .header("lambda-extension-identifier", &self.identifier)
            .send()
            .await
            .map_err(|_| api_failure())?;
        if response.status() != StatusCode::OK {
            return Err(api_failure());
        }
        let identifier = response
            .headers()
            .get("lambda-extension-event-identifier")
            .and_then(|value| value.to_str().ok())
            .filter(|value| {
                value.len() <= LAMBDA_MAX_INVOCATION_ID_BYTES
                    && uuid::Uuid::parse_str(value).is_ok()
            })
            .ok_or_else(api_failure)?
            .to_owned();
        let bytes = read_body(response).await?;
        let event =
            serde_json::from_slice(&bytes).map_err(|_| LifecycleError::SourceUnavailable {
                reason: "Lambda Extensions API event is invalid",
            })?;
        Ok(ProviderEvent { identifier, event })
    }
}

impl LambdaExtensionEvent {
    pub(super) fn deadline(&self) -> Result<Deadline, LifecycleError> {
        let anchor = Instant::now();
        let now_ms =
            u64::try_from(chrono::Utc::now().timestamp_millis()).map_err(|_| api_failure())?;
        let (Self::Invoke { deadline_ms, .. } | Self::Shutdown { deadline_ms, .. }) = self;
        let remaining = Duration::from_millis(deadline_ms.saturating_sub(now_ms));
        anchor.checked_add(remaining).ok_or_else(api_failure)?;
        Ok(Deadline::from_anchor(anchor, remaining))
    }
}

async fn read_body(response: HttpResponse) -> Result<bytes::Bytes, LifecycleError> {
    tokio::time::timeout(
        LAMBDA_API_BODY_TIMEOUT,
        response
            .with_max_body_size(Some(LAMBDA_API_MAX_BODY_BYTES))
            .bytes(),
    )
    .await
    .map_err(|_| LifecycleError::DeadlineExceeded)?
    .map_err(|_| api_failure())
}

fn local_runtime_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_link_local(),
        IpAddr::V6(address) => address.is_loopback() || address.is_unicast_link_local(),
    }
}

fn invalid_configuration() -> LifecycleError {
    LifecycleError::InvalidConfiguration {
        reason: "Lambda requires a local runtime IP:port and extension filename",
    }
}

fn api_failure() -> LifecycleError {
    LifecycleError::SourceUnavailable {
        reason: "Lambda Extensions API request or response failed",
    }
}
