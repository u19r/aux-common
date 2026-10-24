use std::time::Instant;

use serde::Serialize;

use super::{
    admission_deadline::AdmissionDeadline,
    client::LambdaExtensionClient,
    configuration::LambdaIpcConfig,
    framing,
    protocol::{IpcCommand, IpcResponse},
};
use crate::{
    Admission, Deadline, EncodeError, FlushReportSummary, LifecycleError, OperationId, WriteError,
    WriteOptions,
};

/// Cloneable authority scoped to one provider phase. Old handles cannot add
/// writes or complete a later invocation, even if its request ID is reused.
pub struct LambdaInvocation<T> {
    client: LambdaExtensionClient<T>,
    session: uuid::Uuid,
    namespace: crate::Namespace,
}
impl<T> Clone for LambdaInvocation<T> {
    fn clone(&self) -> Self {
        Self {
            client: LambdaExtensionClient::new(self.client.config.clone()),
            session: self.session,
            namespace: self.namespace.clone(),
        }
    }
}
impl<T> std::fmt::Debug for LambdaInvocation<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LambdaInvocation")
    }
}
impl<T: Serialize> LambdaInvocation<T> {
    pub(super) fn new(
        config: LambdaIpcConfig,
        session: uuid::Uuid,
        namespace: crate::Namespace,
    ) -> Self {
        Self {
            client: LambdaExtensionClient::new(config),
            session,
            namespace,
        }
    }
    /// The extension writer's validated namespace, received during binding.
    pub fn namespace(&self) -> &crate::Namespace {
        &self.namespace
    }
    pub async fn add_write_item(&self, item: T) -> Result<Admission, WriteError> {
        self.add_write_item_with_options(item, WriteOptions::new())
            .await
    }

    /// A lost post-dispatch response returns Ambiguous with a stable operation
    /// ID. Retry with that same ID; the original item is moved and is not
    /// cloned here.
    pub async fn add_write_item_with_options(
        &self,
        item: T,
        options: WriteOptions,
    ) -> Result<Admission, WriteError> {
        let operation_id = options
            .operation_id()
            .cloned()
            .unwrap_or_else(OperationId::generate_v7);
        let deadline = Deadline::after(self.client.config.timeout).shorten_to(
            options
                .deadline()
                .unwrap_or_else(|| Deadline::after(self.client.config.timeout)),
            Instant::now(),
        );
        let request = self.client.request(IpcCommand::Submit {
            session: self.session,
            deadline: AdmissionDeadline::capture(deadline).map_err(|_| {
                WriteError::Unavailable {
                    operation_id: Some(operation_id.clone()),
                    accepted: false,
                }
            })?,
            operation_id: operation_id.clone(),
            scope: options.scope().cloned(),
            item,
        });
        let bytes = framing::encode(&request).map_err(encode_error)?;
        let response = self
            .client
            .exchange(&bytes, deadline)
            .await
            .map_err(|failure| failure.into_write_error(operation_id.clone()))?;
        match response {
            IpcResponse::Admitted(admission) if admission.operation_id() == &operation_id => {
                Ok(admission)
            }
            IpcResponse::Admitted(_) => Err(WriteError::Ambiguous { operation_id }),
            IpcResponse::WriteFailed(failure) => Err(failure.into_error(operation_id)),
            IpcResponse::Rejected => Err(WriteError::Rejected {
                reason: "Lambda extension rejected IPC authority",
            }),
            IpcResponse::Completed(_) | IpcResponse::Bound { .. } => {
                Err(WriteError::Ambiguous { operation_id })
            }
        }
    }

    /// Call only after the Runtime API response POST is acknowledged.
    /// This acknowledges the eligible flush, not destination durability of a
    /// young batch.
    pub async fn after_response(&self) -> Result<FlushReportSummary, LifecycleError> {
        let request = self.client.request(IpcCommand::InvocationComplete {
            session: self.session,
        });
        let bytes =
            framing::encode(&request).map_err(|_| LifecycleError::IpcProtocolViolation {
                reason: "Lambda completion marker exceeds its encoding budget",
            })?;
        match self
            .client
            .exchange(&bytes, Deadline::after(self.client.config.timeout))
            .await
            .map_err(|failure| failure.error)?
        {
            IpcResponse::Completed(summary) => Ok(summary),
            _ => Err(LifecycleError::IpcProtocolViolation {
                reason: "Lambda extension rejected the completion marker",
            }),
        }
    }
}
fn encode_error(error: EncodeError) -> WriteError {
    match error {
        EncodeError::PayloadTooLarge { size, limit } => WriteError::OversizedItem { size, limit },
        other => WriteError::Encode(other),
    }
}
