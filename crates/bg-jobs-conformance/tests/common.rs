use std::{sync::Arc, time::Duration};

use bg_jobs::runtime::{WakeFuture, WakeScheduler, WakeSchedulerError};

struct ImmediateWakeScheduler;

impl WakeScheduler for ImmediateWakeScheduler {
    fn sleep(&self, _delay: Duration) -> Result<WakeFuture, WakeSchedulerError> {
        Ok(Box::pin(std::future::ready(())))
    }
}

pub(crate) fn wake_scheduler() -> Arc<dyn WakeScheduler> {
    Arc::new(ImmediateWakeScheduler)
}
