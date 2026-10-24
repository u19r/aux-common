use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

use crate::{
    LifecycleError,
    constants::{LAMBDA_IPC_DEFAULT_TIMEOUT, LAMBDA_IPC_MAX_TOKEN_BYTES},
};

/// Shared function/extension connection settings. Tokens are never formatted.
#[derive(Clone)]
pub struct LambdaIpcConfig {
    pub(super) address: SocketAddr,
    pub(super) token: String,
    pub(super) timeout: Duration,
}

impl std::fmt::Debug for LambdaIpcConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LambdaIpcConfig")
    }
}

impl LambdaIpcConfig {
    pub fn try_new(address: SocketAddr, token: impl Into<String>) -> Result<Self, LifecycleError> {
        let token = token.into();
        if !address.ip().is_loopback()
            || token.is_empty()
            || token.len() > LAMBDA_IPC_MAX_TOKEN_BYTES
            || !token.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "Lambda IPC requires a loopback address and a bounded printable ASCII \
                         token",
            });
        }
        Ok(Self {
            address,
            token,
            timeout: LAMBDA_IPC_DEFAULT_TIMEOUT,
        })
    }

    pub fn try_with_timeout(mut self, timeout: Duration) -> Result<Self, LifecycleError> {
        if timeout.is_zero() || Instant::now().checked_add(timeout).is_none() {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "Lambda IPC timeout must be positive and fit a monotonic deadline",
            });
        }
        self.timeout = timeout;
        Ok(self)
    }
}
