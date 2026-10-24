use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use redis::aio::ConnectionManager;
use sha2::{Digest as _, Sha256};
use url::Url;

use crate::{
    BufferError, ConfigurationError, Namespace, ValkeyCredentials, constants::VALKEY_STATE_SCRIPT,
};

/// Bounded namespace snapshots committed atomically in one cluster hash slot.
/// Distribute load through explicit namespaces; this provider adds no shards.
#[derive(Clone)]
pub struct ValkeyBuffer {
    pub(super) namespace: Namespace,
    client: redis::Client,
    connection: Arc<tokio::sync::OnceCell<ConnectionManager>>,
    pub(super) state_key: String,
    pub(super) metadata_key: String,
    pub(super) protocol: Arc<redis::Script>,
    observed_state: Arc<AtomicBool>,
}

impl std::fmt::Debug for ValkeyBuffer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ValkeyBuffer")
    }
}

impl ValkeyBuffer {
    pub fn try_new(
        namespace: Namespace,
        endpoint: impl Into<String>,
        credentials: ValkeyCredentials,
    ) -> Result<Self, ConfigurationError> {
        let client = Self::configure_client(endpoint.into(), &credentials)?;
        let digest = Sha256::digest(namespace.as_str().as_bytes());
        let tag: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        Ok(Self {
            namespace,
            client,
            connection: Arc::new(tokio::sync::OnceCell::new()),
            protocol: Arc::new(redis::Script::new(VALKEY_STATE_SCRIPT)),
            observed_state: Arc::new(AtomicBool::new(false)),
            state_key: format!("aux-buffered-writes:{{{tag}}}:state"),
            metadata_key: format!("aux-buffered-writes:{{{tag}}}:metadata"),
        })
    }

    fn configure_client(
        endpoint: String,
        credentials: &ValkeyCredentials,
    ) -> Result<redis::Client, ConfigurationError> {
        let mut url = Self::parse_endpoint(&endpoint)?;
        if credentials.password().is_empty()
            || (credentials.is_tls_required() || credentials.tls_ca_pem().is_some())
                && url.scheme() != "rediss"
        {
            return Err(Self::invalid_endpoint());
        }
        url.set_username(credentials.username().unwrap_or(""))
            .map_err(|_| Self::invalid_endpoint())?;
        url.set_password(Some(credentials.password()))
            .map_err(|_| Self::invalid_endpoint())?;
        let result = match credentials.tls_ca_pem() {
            Some(pem) => redis::Client::build_with_tls(
                url.as_str(),
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: Some(pem.to_vec()),
                },
            ),
            None => redis::Client::open(url.as_str()),
        };
        result.map_err(|_| Self::invalid_endpoint())
    }

    fn parse_endpoint(endpoint: &str) -> Result<Url, ConfigurationError> {
        let url = Url::parse(endpoint).map_err(|_| Self::invalid_endpoint())?;
        if !matches!(url.scheme(), "redis" | "rediss")
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(Self::invalid_endpoint());
        }
        Ok(url)
    }

    fn invalid_endpoint() -> ConfigurationError {
        ConfigurationError::InvalidEndpoint {
            reason: "invalid Valkey endpoint or TLS configuration",
        }
    }

    pub(super) async fn connect(&self) -> Result<ConnectionManager, BufferError> {
        let connection = self
            .connection
            .get_or_try_init(|| async {
                ConnectionManager::new(self.client.clone())
                    .await
                    .map_err(Self::remote_error)
            })
            .await?;
        Ok(connection.clone())
    }

    pub(super) fn record_retention_presence(&self, present: bool) -> Result<(), BufferError> {
        if present {
            self.observed_state.store(true, Ordering::Release);
        } else if self.observed_state.load(Ordering::Acquire) {
            return Err(BufferError::CorruptStorage {
                reason: "previously observed Valkey retention is missing",
            });
        }
        Ok(())
    }

    pub(super) fn remote_error(error: redis::RedisError) -> BufferError {
        match error.code() {
            Some("AUX_BUFFER_CORRUPT") => Self::corrupt_state(),
            Some("AUX_BUFFER_FULL") => BufferError::Full,
            Some("AUX_BUFFER_POLICY") => BufferError::StorageUnavailable {
                reason: "Valkey requires noeviction",
            },
            _ => BufferError::StorageUnavailable {
                reason: "Valkey operation failed",
            },
        }
    }

    pub(super) fn corrupt_state() -> BufferError {
        BufferError::CorruptStorage {
            reason: "invalid persisted Valkey state",
        }
    }

    pub(super) async fn server_time(
        connection: &mut ConnectionManager,
    ) -> Result<i64, BufferError> {
        let (seconds, micros): (i64, i64) = redis::cmd("TIME")
            .query_async(connection)
            .await
            .map_err(Self::remote_error)?;
        Ok(seconds.saturating_mul(1_000).saturating_add(micros / 1_000))
    }
}
