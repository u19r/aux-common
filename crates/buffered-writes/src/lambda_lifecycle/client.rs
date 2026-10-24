use std::{marker::PhantomData, time::Instant};

use serde::Serialize;
use tokio::net::TcpStream;

use super::{
    configuration::LambdaIpcConfig,
    framing,
    invocation::LambdaInvocation,
    protocol::{IpcCommand, IpcRequest, IpcResponse},
};
use crate::{Deadline, LifecycleError, OperationId, WriteError, constants::LAMBDA_IPC_VERSION};

/// Function-side IPC handle. It holds connection settings, never the writer or
/// server.
pub struct LambdaExtensionClient<T> {
    pub(super) config: LambdaIpcConfig,
    marker: PhantomData<fn() -> T>,
}

impl<T> std::fmt::Debug for LambdaExtensionClient<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LambdaExtensionClient")
    }
}

pub(super) struct ExchangeFailure {
    pub(super) error: LifecycleError,
    dispatched: bool,
}

impl<T> LambdaExtensionClient<T> {
    #[must_use]
    pub const fn new(config: LambdaIpcConfig) -> Self {
        Self {
            config,
            marker: PhantomData,
        }
    }
}
impl<T: Serialize> LambdaExtensionClient<T> {
    /// Bind exactly once from the trusted runtime loop after Runtime Next.
    /// Request IDs correlate events; attempt IDs must identify this runtime
    /// attempt. The extension grants a local first-binder capability, not an
    /// AWS-attested relationship between opaque provider IDs. Give application
    /// work only the returned scoped handle, never this binding authority.
    pub async fn begin_invocation(
        &mut self,
        request_id: &str,
        attempt_id: &str,
    ) -> Result<LambdaInvocation<T>, LifecycleError> {
        let bytes = framing::encode(&self.request(IpcCommand::Bind {
            request_id: request_id.to_owned(),
            attempt_id: attempt_id.to_owned(),
        }))
        .map_err(|_| LifecycleError::IpcProtocolViolation {
            reason: "Lambda binding exceeds its encoding budget",
        })?;
        match self
            .exchange(&bytes, Deadline::after(self.config.timeout))
            .await
            .map_err(|failure| failure.error)?
        {
            IpcResponse::Bound {
                request_id: received_request,
                attempt_id: received_attempt,
                session,
                namespace,
            } if received_request == request_id
                && received_attempt == attempt_id
                && session.get_version_num() == 7 =>
            {
                Ok(LambdaInvocation::new(
                    self.config.clone(),
                    session,
                    namespace,
                ))
            }
            _ => Err(LifecycleError::IpcProtocolViolation {
                reason: "Lambda extension rejected invocation binding",
            }),
        }
    }

    pub(super) fn request(&self, command: IpcCommand<T>) -> IpcRequest<T> {
        IpcRequest {
            version: LAMBDA_IPC_VERSION,
            auth_token: self.config.token.clone(),
            command,
        }
    }

    pub(super) async fn exchange(
        &self,
        bytes: &[u8],
        deadline: Deadline,
    ) -> Result<IpcResponse, ExchangeFailure> {
        let mut dispatched = false;
        if deadline.is_expired_at(Instant::now()) {
            return Err(ExchangeFailure {
                error: LifecycleError::DeadlineExceeded,
                dispatched,
            });
        }
        let result = tokio::time::timeout(deadline.remaining_at(Instant::now()), async {
            let mut stream = TcpStream::connect(self.config.address).await.map_err(|_| {
                LifecycleError::IpcUnavailable {
                    reason: "Lambda extension is not reachable",
                }
            })?;
            dispatched = true;
            framing::write_frame(&mut stream, bytes).await?;
            let reply = framing::read_frame(&mut stream).await?;
            serde_json::from_slice(&reply).map_err(|_| LifecycleError::IpcProtocolViolation {
                reason: "Lambda IPC response is invalid",
            })
        })
        .await
        .unwrap_or(Err(LifecycleError::DeadlineExceeded));
        result.map_err(|error| ExchangeFailure { error, dispatched })
    }
}

impl ExchangeFailure {
    pub(super) fn into_write_error(self, operation_id: OperationId) -> WriteError {
        if self.dispatched {
            return WriteError::Ambiguous { operation_id };
        }
        match self.error {
            LifecycleError::DeadlineExceeded => WriteError::DeadlineExceeded {
                operation_id: Some(operation_id),
                accepted: false,
            },
            _ => WriteError::Unavailable {
                operation_id: Some(operation_id),
                accepted: false,
            },
        }
    }
}
