use std::time::Duration;

use aws_credentials::CredentialSource;
use aws_sigv4_signing::AwsRequestSigner;
use http_request::{HttpClient, RetryConfig};

use super::configuration::{QueueAddress, SqsConfiguration};
use crate::{ConfigurationError, QueueConfig, QueueLimits, constants::SQS_SERVICE_NAME};

/// SDK-free SQS outage spool and replay transport. Request bodies preserve the
/// configured queue URL while endpoint overrides select the signed HTTP
/// destination.
#[derive(Clone)]
pub struct SqsQueue {
    pub(super) primary: SignedQueue,
    pub(super) endpoint_override: Option<String>,
    pub(super) quarantine: Option<SignedQueue>,
    pub(super) fifo_group_id: Option<String>,
    pub(super) is_fifo: bool,
    pub(super) limits: QueueLimits,
    pub(super) client: HttpClient,
}

impl std::fmt::Debug for SqsQueue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqsQueue")
            .field("is_fifo", &self.is_fifo)
            .field("quarantine_configured", &self.quarantine.is_some())
            .finish()
    }
}

impl SqsQueue {
    pub fn try_new(config: QueueConfig) -> Result<Self, ConfigurationError> {
        let client = HttpClient::builder()
            .retry(RetryConfig {
                max_retries: 0,
                base_delay: Duration::ZERO,
                max_delay: Duration::ZERO,
                retry_non_idempotent: false,
            })
            .build()
            .map_err(|_| ConfigurationError::InvalidQueueConfiguration {
                reason: "failed to construct SQS HTTP client",
            })?;
        Self::try_new_with_client(config, CredentialSource::DefaultChain, client)
    }

    /// Supply caller-owned credentials and a redirect-disabled HTTP transport.
    pub fn try_new_with_client(
        config: QueueConfig,
        credentials: CredentialSource,
        client: HttpClient,
    ) -> Result<Self, ConfigurationError> {
        validate_http_client(&client)?;
        let config = SqsConfiguration::try_from(config)?;
        let quarantine = config
            .quarantine
            .map(|address| SignedQueue::try_new(address, credentials.clone()))
            .transpose()?;
        let primary = SignedQueue::try_new(config.primary, credentials)?;
        Ok(Self {
            primary,
            endpoint_override: config.endpoint_override,
            quarantine,
            fifo_group_id: config.fifo_group_id,
            is_fifo: config.is_fifo,
            limits: config.limits,
            client,
        })
    }
}

fn validate_http_client(client: &HttpClient) -> Result<(), ConfigurationError> {
    if !client.redirects_disabled() {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS HTTP client must disable redirects",
        });
    }
    if client.can_retry_method(&http::Method::POST) {
        return Err(ConfigurationError::InvalidQueueConfiguration {
            reason: "SQS HTTP client must disable transparent POST retries",
        });
    }
    Ok(())
}

#[derive(Clone)]
pub(super) struct SignedQueue {
    pub(super) url: String,
    pub(super) endpoint: String,
    pub(super) signer: AwsRequestSigner,
}

impl SignedQueue {
    fn try_new(
        address: QueueAddress,
        credentials: CredentialSource,
    ) -> Result<Self, ConfigurationError> {
        let signer = AwsRequestSigner::new(&address.region, credentials, SQS_SERVICE_NAME)
            .map_err(|_| ConfigurationError::InvalidQueueConfiguration {
                reason: "failed to initialize SQS SigV4 request signer",
            })?;
        Ok(Self {
            url: address.url,
            endpoint: address.endpoint,
            signer,
        })
    }
}
