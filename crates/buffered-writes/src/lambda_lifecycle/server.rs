use std::{net::SocketAddr, sync::Arc, time::Instant};

use serde::{Serialize, de::DeserializeOwned};
use tokio::net::{TcpListener, TcpStream};

use super::{
    configuration::LambdaIpcConfig,
    coordination::{InvocationCoordination, InvocationPermission, ServiceGuard},
    framing,
    protocol::{IpcCommand, IpcRequest, IpcResponse},
};
use crate::{
    BufferedWrites, Deadline, FlushReportSummary, LifecycleError, WriteEvent, WriteObserver,
    WriteOptions,
    constants::{
        LAMBDA_EXTERNAL_EXTENSION_MAX_SHUTDOWN, LAMBDA_IPC_VERSION, LAMBDA_SHUTDOWN_SAFETY_MARGIN,
    },
};

/// Extension-owned writer and bounded IPC listener. Construction spawns no
/// task.
pub struct LambdaExtensionServer<T> {
    inner: Arc<ServerInner<T>>,
    pub(super) observer: Arc<dyn WriteObserver>,
}

struct ServerInner<T> {
    writer: BufferedWrites<T>,
    config: LambdaIpcConfig,
    listener: TcpListener,
    coordination: InvocationCoordination,
}

impl<T> Clone for LambdaExtensionServer<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            observer: self.observer.clone(),
        }
    }
}

impl<T> std::fmt::Debug for LambdaExtensionServer<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LambdaExtensionServer")
    }
}

impl<T: Serialize + DeserializeOwned + Send + Sync + 'static> LambdaExtensionServer<T> {
    pub async fn bind(
        writer: BufferedWrites<T>,
        config: LambdaIpcConfig,
    ) -> Result<Self, LifecycleError> {
        let listener = TcpListener::bind(config.address).await.map_err(|_| {
            LifecycleError::IpcUnavailable {
                reason: "Lambda IPC listener could not be bound",
            }
        })?;
        writer.claim_lifecycle_slot(false)?;
        let observer = writer.clone_observer();
        Ok(Self {
            inner: Arc::new(ServerInner {
                writer,
                config,
                listener,
                coordination: InvocationCoordination::default(),
            }),
            observer,
        })
    }

    /// The actual loopback endpoint, including the assigned port when bound to
    /// zero.
    pub fn local_addr(&self) -> Result<SocketAddr, LifecycleError> {
        self.inner
            .listener
            .local_addr()
            .map_err(|_| LifecycleError::IpcUnavailable {
                reason: "Lambda IPC listener address is unavailable",
            })
    }

    #[must_use]
    pub fn with_observer(mut self, observer: impl WriteObserver) -> Self {
        self.observer = Arc::new(observer);
        self
    }

    /// Called only for the actual provider INVOKE event, never from function
    /// IPC.
    pub fn begin_invocation(
        &self,
        event_id: &str,
        request_id: &str,
        deadline: impl Into<Deadline>,
    ) -> Result<(), LifecycleError> {
        self.inner
            .coordination
            .begin(event_id, request_id, deadline.into())
    }

    /// Wait under the deadline already established by begin_invocation.
    pub async fn await_invoke_completion(
        &self,
        id: &str,
    ) -> Result<FlushReportSummary, LifecycleError> {
        self.inner.coordination.completed(id).await
    }

    /// Poll alongside the Extensions API loop. Dropping this future cancels
    /// active IPC. One connection is processed at a time; each has a finite
    /// total deadline.
    pub async fn serve(&self) -> Result<(), LifecycleError> {
        let _service = self.claim_service()?;
        self.serve_owned().await
    }

    pub(super) fn claim_service(&self) -> Result<ServiceGuard<'_>, LifecycleError> {
        self.inner.coordination.claim_service()
    }

    pub(super) async fn serve_owned(&self) -> Result<(), LifecycleError> {
        tokio::select! {
            result = self.serve_connections() => result,
            result = self.inner.coordination.stopped() => result,
        }
    }

    pub async fn shutdown(
        &self,
        deadline: impl Into<Deadline>,
    ) -> Result<crate::DrainReport, LifecycleError> {
        let now = Instant::now();
        let budget = deadline
            .into()
            .remaining_at(now)
            .min(LAMBDA_EXTERNAL_EXTENSION_MAX_SHUTDOWN)
            .saturating_sub(LAMBDA_SHUTDOWN_SAFETY_MARGIN);
        self.inner.coordination.stop()?;
        Ok(self
            .inner
            .writer
            .shutdown(Deadline::from_anchor(now, budget))
            .await)
    }

    async fn serve_connections(&self) -> Result<(), LifecycleError> {
        loop {
            let (mut stream, _) =
                self.inner
                    .listener
                    .accept()
                    .await
                    .map_err(|_| LifecycleError::IpcUnavailable {
                        reason: "Lambda IPC accept failed",
                    })?;
            let deadline = Deadline::after(self.inner.config.timeout);
            let result = tokio::time::timeout(
                deadline.remaining_at(Instant::now()),
                self.exchange(&mut stream, deadline),
            )
            .await
            .unwrap_or(Err(LifecycleError::DeadlineExceeded));
            if let Err(error) = result {
                self.observer
                    .observe(WriteEvent::LifecycleSourceFailed { error });
            }
        }
    }

    async fn exchange(
        &self,
        stream: &mut TcpStream,
        deadline: Deadline,
    ) -> Result<(), LifecycleError> {
        let bytes = framing::read_frame(stream).await?;
        let request: IpcRequest<T> =
            serde_json::from_slice(&bytes).map_err(|_| LifecycleError::IpcProtocolViolation {
                reason: "Lambda IPC request is invalid",
            })?;
        let response = if request.version != LAMBDA_IPC_VERSION
            || request.auth_token != self.inner.config.token
        {
            IpcResponse::Rejected
        } else {
            self.process(request, deadline).await?
        };
        let bytes =
            framing::encode(&response).map_err(|_| LifecycleError::IpcProtocolViolation {
                reason: "Lambda IPC response exceeds its encoding budget",
            })?;
        framing::write_frame(stream, &bytes).await
    }

    async fn process(
        &self,
        request: IpcRequest<T>,
        deadline: Deadline,
    ) -> Result<IpcResponse, LifecycleError> {
        match request.command {
            IpcCommand::Bind {
                request_id,
                attempt_id,
            } => match self.inner.coordination.bind(&request_id, &attempt_id).await {
                Ok(session) => Ok(IpcResponse::Bound {
                    request_id,
                    attempt_id,
                    session,
                    namespace: self.inner.writer.namespace().clone(),
                }),
                Err(LifecycleError::IpcProtocolViolation { .. }) => Ok(IpcResponse::Rejected),
                Err(error) => Err(error),
            },
            command => self.apply_command(command, deadline).await,
        }
    }

    async fn apply_command(
        &self,
        command: IpcCommand<T>,
        deadline: Deadline,
    ) -> Result<IpcResponse, LifecycleError> {
        let session = match &command {
            IpcCommand::Submit { session, .. } | IpcCommand::InvocationComplete { session } => {
                session
            }
            IpcCommand::Bind { .. } => return Ok(IpcResponse::Rejected),
        };
        let permission = match self.inner.coordination.permission(session) {
            Ok(permission) => permission,
            Err(LifecycleError::IpcProtocolViolation { .. }) => return Ok(IpcResponse::Rejected),
            Err(error) => return Err(error),
        };
        match permission {
            InvocationPermission::Completed(report) => Ok(match command {
                IpcCommand::InvocationComplete { .. } => IpcResponse::Completed(report),
                IpcCommand::Submit { .. } | IpcCommand::Bind { .. } => IpcResponse::Rejected,
            }),
            InvocationPermission::Active(invocation_deadline) => {
                let deadline = deadline.shorten_to(invocation_deadline, Instant::now());
                match command {
                    IpcCommand::Submit {
                        operation_id,
                        scope,
                        item,
                        deadline: admission_deadline,
                        ..
                    } => Ok(self
                        .admit_current(
                            item,
                            operation_id,
                            scope,
                            admission_deadline.shorten(deadline)?,
                        )
                        .await),
                    IpcCommand::InvocationComplete { session } => {
                        self.complete_current(&session, deadline).await
                    }
                    IpcCommand::Bind { .. } => Ok(IpcResponse::Rejected),
                }
            }
        }
    }

    async fn admit_current(
        &self,
        item: T,
        operation_id: crate::OperationId,
        scope: Option<crate::TenantScope>,
        deadline: Deadline,
    ) -> IpcResponse {
        let mut options = WriteOptions::new()
            .with_operation_id(operation_id)
            .with_deadline(deadline);
        if let Some(scope) = scope {
            options = options.with_scope(scope);
        }
        match self
            .inner
            .writer
            .add_write_item_with_options(item, options)
            .await
        {
            Ok(admission) => IpcResponse::Admitted(admission),
            Err(error) => IpcResponse::WriteFailed(error.into()),
        }
    }

    async fn complete_current(
        &self,
        session: &uuid::Uuid,
        deadline: Deadline,
    ) -> Result<IpcResponse, LifecycleError> {
        if deadline.is_expired_at(Instant::now()) {
            return Err(LifecycleError::DeadlineExceeded);
        }
        let report = tokio::time::timeout(
            deadline.remaining_at(Instant::now()),
            self.inner.writer.after_response(),
        )
        .await
        .map_err(|_| LifecycleError::DeadlineExceeded)?;
        let summary = FlushReportSummary::from(report);
        self.inner.coordination.complete(session, summary)?;
        Ok(IpcResponse::Completed(summary))
    }
}
