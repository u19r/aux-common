use std::future::Future;
#[cfg(feature = "request-cost")]
use std::sync::Arc;

#[cfg(feature = "request-cost")]
use super::request_cost::{REQUEST_COST_COLLECTOR, RequestCostCollectorHandle};

/// Captures an existing collector for work executed by a shared worker.
/// Capture in the originating task; scope each physical attempt exactly once.
#[derive(Clone)]
pub struct RequestCostContext {
    #[cfg(feature = "request-cost")]
    collector: Option<RequestCostCollectorHandle>,
}

impl RequestCostContext {
    pub fn capture() -> Self {
        Self {
            #[cfg(feature = "request-cost")]
            collector: REQUEST_COST_COLLECTOR.try_with(Arc::clone).ok(),
        }
    }

    pub fn scope<F: Future>(&self, future: F) -> impl Future<Output = F::Output> + use<F> {
        #[cfg(feature = "request-cost")]
        let collector = self.collector.clone();
        #[cfg(feature = "request-cost")]
        let work = self.collector.as_ref().and_then(RequestCostWork::reserve);
        async move {
            #[cfg(feature = "request-cost")]
            {
                if let (Some(_work), Some(collector)) = (work, collector) {
                    return REQUEST_COST_COLLECTOR.scope(collector, future).await;
                }
            }
            future.await
        }
    }
}

/// Carries the current collector into a provider task. Construct before spawn.
pub fn inherit_request_cost<F: Future>(future: F) -> impl Future<Output = F::Output> {
    // Reserve before returning: an unpolled spawned future is outstanding work.
    RequestCostContext::capture().scope(future)
}

#[cfg(feature = "request-cost")]
struct RequestCostWork(RequestCostCollectorHandle);

#[cfg(feature = "request-cost")]
impl RequestCostWork {
    fn reserve(collector: &RequestCostCollectorHandle) -> Option<Self> {
        if !collector.lock().ok()?.begin_work() {
            return None;
        }
        Some(Self(Arc::clone(collector)))
    }
}

#[cfg(feature = "request-cost")]
impl Drop for RequestCostWork {
    fn drop(&mut self) {
        if let Ok(mut collector) = self.0.lock() {
            collector.finish_work();
        }
    }
}
