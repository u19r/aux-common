#[cfg(feature = "buffered-lambda")]
use std::sync::Arc;

use buffered_writes::{
    Admission, BufferedWrites, FlushReportSummary, LifecycleError, Namespace, WriteError,
    WriteOptions,
};

use super::RequestMeasurement;

#[derive(Clone)]
pub(super) enum MeteringRuntime {
    Local(BufferedWrites<RequestMeasurement>),
    #[cfg(feature = "buffered-lambda")]
    Lambda(Arc<buffered_writes::LambdaInvocation<RequestMeasurement>>),
}

impl MeteringRuntime {
    pub(super) fn namespace(&self) -> &Namespace {
        match self {
            Self::Local(writer) => writer.namespace(),
            #[cfg(feature = "buffered-lambda")]
            Self::Lambda(invocation) => invocation.namespace(),
        }
    }

    pub(super) async fn submit(
        &self,
        item: RequestMeasurement,
        options: WriteOptions,
    ) -> Result<Admission, WriteError> {
        match self {
            Self::Local(writer) => writer.add_write_item_with_options(item, options).await,
            #[cfg(feature = "buffered-lambda")]
            Self::Lambda(invocation) => invocation.add_write_item_with_options(item, options).await,
        }
    }

    pub(super) async fn after_response(&self) -> Result<FlushReportSummary, LifecycleError> {
        match self {
            Self::Local(writer) => Ok(writer.after_response().await.into()),
            #[cfg(feature = "buffered-lambda")]
            Self::Lambda(invocation) => invocation.after_response().await,
        }
    }

    pub(super) fn local_writer(
        &self,
    ) -> Result<&BufferedWrites<RequestMeasurement>, LifecycleError> {
        match self {
            Self::Local(writer) => Ok(writer),
            #[cfg(feature = "buffered-lambda")]
            Self::Lambda(_) => Err(LifecycleError::InvalidConfiguration {
                reason: "the Lambda extension owns writer flush, driver and shutdown control",
            }),
        }
    }
}
