use std::{future::Future, sync::Arc};

use crate::constants::{MAX_METRIC_LABEL_VALUE_BYTES, UNMATCHED_REQUEST_OPERATION};
#[cfg(feature = "request-cost")]
use crate::{
    HistogramMetric,
    constants::{LABEL_API_OPERATION, LABEL_STORAGE_OPERATION},
};

#[cfg(feature = "request-cost")]
tokio::task_local! {
    static REQUEST_OPERATION: Arc<str>;
}

/// A router-owned method and matched path template, scoped to one request
/// future. This context deliberately does not join request-cost or worker
/// propagation.
pub struct RequestOperation(Arc<str>);

impl From<&str> for RequestOperation {
    fn from(operation: &str) -> Self {
        let operation = if operation.is_empty() || operation.len() > MAX_METRIC_LABEL_VALUE_BYTES {
            UNMATCHED_REQUEST_OPERATION
        } else {
            operation
        };
        Self(Arc::from(operation))
    }
}

impl RequestOperation {
    pub async fn scope<F: Future>(self, future: F) -> F::Output {
        #[cfg(feature = "request-cost")]
        {
            REQUEST_OPERATION.scope(self.0, future).await
        }
        #[cfg(not(feature = "request-cost"))]
        {
            let _ = self.0;
            future.await
        }
    }
}

/// Capture the metric for a request-owned provider call before native handoff.
/// The returned handle can record its completion without propagating request
/// context.
pub fn request_storage_operation_histogram(operation: &'static str) -> metrics::Histogram {
    #[cfg(feature = "request-cost")]
    {
        REQUEST_OPERATION
            .try_with(|api_operation| {
                // Router templates and static storage operations bound these
                // labels. Share the operation string without the facade's
                // global key cap.
                metrics::histogram!(
                    HistogramMetric::HttpStorageOperationDurationSeconds.name(),
                    LABEL_API_OPERATION => Arc::clone(api_operation),
                    LABEL_STORAGE_OPERATION => operation
                )
            })
            .unwrap_or_else(|_| metrics::Histogram::noop())
    }
    #[cfg(not(feature = "request-cost"))]
    {
        let _ = operation;
        metrics::Histogram::noop()
    }
}
