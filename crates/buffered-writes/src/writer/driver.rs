use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use super::handle::BufferedWrites;
#[cfg(feature = "tokio")]
use super::lifecycle_driver::LifecycleDriver;
use crate::{
    configuration::Deadline,
    error::LifecycleError,
    lifecycle::{LifecycleEvents, RuntimeGuard, RuntimeGuardInner},
};
pub(super) struct DriverHandleState {
    shutdown_completed: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    #[cfg(feature = "tokio")]
    join_handle: Option<tokio::task::JoinHandle<()>>,
}

impl<T: Send + Sync + 'static> BufferedWrites<T> {
    pub(super) async fn complete_attached_driver(&self, deadline: Deadline) {
        let state = self.driver_state.lock().ok().and_then(|mut g| g.take());
        let Some(state) = state else {
            return;
        };
        state.shutdown_completed.store(true, Ordering::Release);
        state.cancelled.store(true, Ordering::Release);
        #[cfg(feature = "tokio")]
        if let Some(join_handle) = state.join_handle {
            join_handle.abort();
            let remaining = deadline.remaining_at(self.engine.cfg.clock.now_instant());
            let _ = tokio::time::timeout(remaining, join_handle).await;
        }
        #[cfg(not(feature = "tokio"))]
        let _ = deadline;
    }

    pub async fn start(
        &self,
        lifecycle: impl LifecycleEvents,
    ) -> Result<RuntimeGuard, LifecycleError> {
        if !cfg!(feature = "tokio") {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "lifecycle driver requires the tokio feature",
            });
        }
        #[cfg(feature = "tokio")]
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "lifecycle driver requires an active Tokio runtime",
            });
        }
        self.claim_lifecycle_slot(lifecycle.can_flush_between_responses())?;
        Ok(self.attach_driver(lifecycle))
    }

    pub(crate) fn claim_lifecycle_slot(
        &self,
        can_flush_between_responses: bool,
    ) -> Result<(), LifecycleError> {
        if self.engine.cfg.periodic_interval.is_some() && !can_flush_between_responses {
            return Err(LifecycleError::InvalidConfiguration {
                reason: "periodic flushing requires a persistent execution window",
            });
        }
        if !self.engine.claim_driver_slot() {
            return Err(LifecycleError::DriverAlreadyStarted);
        }
        Ok(())
    }

    fn attach_driver(&self, lifecycle: impl LifecycleEvents) -> RuntimeGuard {
        let shutdown_completed = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let engine = Arc::clone(&self.engine);

        #[cfg(feature = "tokio")]
        let (abort_handle, join_handle) = {
            let engine_task = Arc::clone(&engine);
            let cancelled_task = Arc::clone(&cancelled);
            let done_task = Arc::clone(&shutdown_completed);
            let handle = tokio::spawn(async move {
                LifecycleDriver::new(engine_task, lifecycle, cancelled_task, done_task)
                    .drive()
                    .await;
            });
            (Some(handle.abort_handle()), Some(handle))
        };

        #[cfg(not(feature = "tokio"))]
        let _ = (lifecycle, engine);

        if let Ok(mut guard) = self.driver_state.lock() {
            *guard = Some(DriverHandleState {
                shutdown_completed: Arc::clone(&shutdown_completed),
                cancelled: Arc::clone(&cancelled),
                #[cfg(feature = "tokio")]
                join_handle,
            });
        }

        RuntimeGuard::new(RuntimeGuardInner {
            shutdown_completed,
            cancelled,
            observer: Arc::clone(&self.engine.cfg.observer),
            #[cfg(feature = "tokio")]
            abort_handle,
        })
    }
}
