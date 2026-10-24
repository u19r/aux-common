use std::{sync::Arc, time::Instant};

use futures_util::future::BoxFuture;
use http::{HeaderValue, StatusCode};
use tokio::sync::Mutex;

use super::{configuration::parse_endpoint, transport::ImdsTransport};
use crate::{
    Deadline, LifecycleError, SpotActionSource, SpotInstanceAction,
    constants::{DEFAULT_IMDS_ENDPOINT, DEFAULT_IMDS_POLL_TIMEOUT, IMDS_TOKEN_REFRESH_AFTER},
};

struct CachedToken {
    value: HeaderValue,
    refresh_at: Instant,
}

/// Bounded IMDSv2 Spot discovery. Construction performs no network I/O.
/// Tokens are cached across polls, never sent through environment proxies,
/// and invalidated on 401. A failed poll never falls back to IMDSv1.
#[derive(Clone)]
pub struct ImdsSpotSource {
    transport: ImdsTransport,
    token: Arc<Mutex<Option<CachedToken>>>,
}

impl std::fmt::Debug for ImdsSpotSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ImdsSpotSource")
    }
}

impl ImdsSpotSource {
    pub fn try_new() -> Result<Self, LifecycleError> {
        Self::try_new_with_endpoint(DEFAULT_IMDS_ENDPOINT)
    }

    /// Select the EC2 IPv6 metadata address or an explicit loopback test
    /// service.
    pub fn try_new_with_endpoint(endpoint: &str) -> Result<Self, LifecycleError> {
        Ok(Self {
            transport: ImdsTransport::try_new(parse_endpoint(endpoint)?)?,
            token: Arc::new(Mutex::new(None)),
        })
    }

    /// One token/action exchange with a total caller deadline, including
    /// contention.
    pub async fn poll_once(
        &self,
        deadline: impl Into<Deadline>,
    ) -> Result<Option<SpotInstanceAction>, LifecycleError> {
        let deadline = deadline.into();
        let remaining = deadline.remaining_at(Instant::now());
        if remaining.is_zero() {
            return Err(LifecycleError::DeadlineExceeded);
        }
        tokio::time::timeout(remaining, self.fetch_notice(deadline))
            .await
            .unwrap_or(Err(LifecycleError::DeadlineExceeded))
    }

    async fn fetch_notice(
        &self,
        deadline: Deadline,
    ) -> Result<Option<SpotInstanceAction>, LifecycleError> {
        let mut cache = self.token.lock().await;
        if cache
            .as_ref()
            .is_some_and(|token| token.refresh_at <= Instant::now())
        {
            *cache = None;
        }
        let token = match &*cache {
            Some(token) => token.value.clone(),
            None => {
                let anchor = Instant::now();
                let token = self.transport.fetch_token(deadline).await?;
                *cache = Some(CachedToken {
                    value: token.clone(),
                    refresh_at: anchor + IMDS_TOKEN_REFRESH_AFTER,
                });
                token
            }
        };
        let (status, body) = self.transport.fetch_action(&token, deadline).await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            StatusCode::UNAUTHORIZED => {
                *cache = None;
                Err(LifecycleError::SourceUnavailable {
                    reason: "IMDS rejected its session token",
                })
            }
            StatusCode::OK => serde_json::from_slice(&body).map(Some).map_err(|_| {
                LifecycleError::SourceUnavailable {
                    reason: "IMDS Spot notice is invalid",
                }
            }),
            _ => Err(LifecycleError::SourceUnavailable {
                reason: "IMDS Spot request was rejected",
            }),
        }
    }
}

impl SpotActionSource for ImdsSpotSource {
    fn poll_spot_action(
        &self,
    ) -> BoxFuture<'static, Result<Option<SpotInstanceAction>, LifecycleError>> {
        let source = self.clone();
        Box::pin(async move { source.poll_once(DEFAULT_IMDS_POLL_TIMEOUT).await })
    }
}
