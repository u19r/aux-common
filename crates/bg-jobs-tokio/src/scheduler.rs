use std::time::Duration;

use bg_jobs::runtime::{WakeFuture, WakeScheduler, WakeSchedulerError};

/// Supplies bounded wake futures from Tokio's timer runtime.
///
/// The caller must run this scheduler inside a Tokio runtime with its time
/// driver enabled. Calls made outside a runtime return `Unavailable`.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TokioWakeScheduler;

impl WakeScheduler for TokioWakeScheduler {
    fn sleep(&self, delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(WakeSchedulerError::Unavailable);
        }
        Ok(Box::pin(tokio::time::sleep(delay)))
    }
}
