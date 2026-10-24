use buffered_writes::{
    Admission, BufferedWrites, Deadline, DrainReport, FlushReport, FlushReportSummary,
    LifecycleError, LifecycleEvents, OperationId, RuntimeGuard, WriteError, WriteOptions,
    WriteSink,
};

use super::{
    MeteringBuilder, RequestMeasurement, begin_request_cost_collection,
    metering_runtime::MeteringRuntime,
};

/// Metering entry point with shared buffering policy and caller-owned sink
/// semantics.
///
/// Builders install bounded operational metrics by default. Install the process
/// metrics backend before building the writer; each observer captures that
/// backend for its full lifetime. `MeteringBuilder::with_observer` replaces
/// this projection when the caller owns observation or composes multiple
/// observers.
#[derive(Clone)]
pub struct BufferedMetering {
    pub(super) runtime: MeteringRuntime,
}

impl BufferedMetering {
    pub fn builder(
        namespace: impl Into<String>,
        sink: impl WriteSink<RequestMeasurement>,
    ) -> MeteringBuilder {
        MeteringBuilder {
            writer: BufferedWrites::builder(namespace, sink),
            uses_default_observer: true,
        }
    }

    pub async fn record_request(&self, item: RequestMeasurement) -> Result<Admission, WriteError> {
        let operation_id = OperationId::derive(
            self.runtime.namespace().as_str(),
            item.scope().as_str(),
            item.request_id().as_str(),
        );
        let mut options = WriteOptions::new()
            .with_operation_id(operation_id)
            .with_scope(item.scope().clone());
        if let Some(deadline) = item.deadline() {
            options = options.with_deadline(deadline);
        }
        begin_request_cost_collection(None, || self.runtime.submit(item, options)).await
    }

    /// Complete the host response boundary. For Lambda, call only after the
    /// Runtime API response POST acknowledgement. Young buffered writes can
    /// remain retained; successful completion is not a durability receipt.
    pub async fn after_response(&self) -> Result<FlushReportSummary, LifecycleError> {
        begin_request_cost_collection(None, || self.runtime.after_response()).await
    }

    /// Force a local flush. Lambda function handles return
    /// `InvalidConfiguration` because the extension owns this operation.
    pub async fn flush_writes(&self) -> Result<FlushReport, LifecycleError> {
        let writer = self.runtime.local_writer()?;
        Ok(begin_request_cost_collection(None, || writer.flush_writes()).await)
    }

    /// Drain a local writer. Lambda function handles reject this operation;
    /// provider shutdown belongs to the extension event loop.
    pub async fn shutdown(
        &self,
        deadline: impl Into<Deadline>,
    ) -> Result<DrainReport, LifecycleError> {
        let writer = self.runtime.local_writer()?;
        Ok(begin_request_cost_collection(None, || writer.shutdown(deadline)).await)
    }

    pub async fn start(
        &self,
        lifecycle: impl LifecycleEvents,
    ) -> Result<RuntimeGuard, LifecycleError> {
        self.runtime.local_writer()?.start(lifecycle).await
    }
}

/// Convert only invocation-scoped authority from the trusted runtime loop.
/// Namespace identity comes from the extension handshake, never a second
/// setting.
///
/// ```no_run
/// # #[cfg(feature = "buffered-lambda")]
/// # async fn submit(
/// #     invocation: metrics_facade::LambdaInvocation<metrics_facade::RequestMeasurement>,
/// #     input: metrics_facade::RequestMeasurement,
/// # ) -> Result<(), Box<dyn std::error::Error>> {
/// use metrics_facade::BufferedMetering;
/// let metering = BufferedMetering::from(invocation);
/// let admission = metering.record_request(input).await?;
/// // The trusted runtime acknowledges its response POST before this call.
/// let completion = metering.after_response().await?;
/// # let _ = (admission, completion);
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "buffered-lambda")]
impl From<buffered_writes::LambdaInvocation<RequestMeasurement>> for BufferedMetering {
    fn from(invocation: buffered_writes::LambdaInvocation<RequestMeasurement>) -> Self {
        Self {
            runtime: MeteringRuntime::Lambda(std::sync::Arc::new(invocation)),
        }
    }
}
