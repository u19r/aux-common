use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Caller-controlled cancellation; clones refer to the same job signal.
#[derive(Clone, Default)]
pub struct JsCancellation {
    cancelled: Arc<AtomicBool>,
}
impl JsCancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}
