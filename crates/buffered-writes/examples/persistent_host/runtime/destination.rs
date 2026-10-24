use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use buffered_writes::{
    ConfigurationError, PartialSink, SinkError, SinkLimits, WriteAttempt, WriteOutcome,
};

/// A volatile maximum register: repeated or reordered assignments are
/// intrinsically idempotent. This demonstration destination has no persistence
/// guarantee.
pub(super) struct DemoDestination {
    pub(super) sink: PartialSink<u64>,
    pub(super) maximum: Arc<AtomicU64>,
}

impl DemoDestination {
    pub(super) fn try_new(delay: Duration) -> Result<Self, ConfigurationError> {
        let maximum = Arc::new(AtomicU64::new(0));
        let observed = maximum.clone();
        let sink =
            PartialSink::try_new(SinkLimits::default(), move |attempt: WriteAttempt<u64>| {
                let observed = observed.clone();
                async move {
                    tokio::time::sleep(delay).await;
                    for item in attempt.pending_items() {
                        observed.fetch_max(*item.item(), Ordering::SeqCst);
                    }
                    Ok::<_, SinkError>(WriteOutcome::Complete)
                }
            })?;
        Ok(Self { sink, maximum })
    }
}
